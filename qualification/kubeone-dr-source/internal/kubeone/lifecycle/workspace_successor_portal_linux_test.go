//go:build linux

package lifecycle

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/kubeone/workspaceproof"
)

func TestNativeWorkspaceScopeCannotAliasProtectedOwner(t *testing.T) {
	w := Workspace{Tenant: "lab-dc", ClusterID: "kubeone-dc", Directory: workspaceSuccessorRoot, Manifest: workspaceSuccessorRoot + "/kubeone.yaml", Kubeconfig: workspaceSuccessorRoot + "/kubeconfig", ExpectedCPNodes: 3, ExpectedNodes: 4, Provisionable: true, SelfServiceLifecycle: true}
	if !nativeWorkspaceSelected(w) || !nativeWorkspaceExact(w) {
		t.Fatal("exact fixed workspace rejected")
	}
	for _, mutate := range []func(*Workspace){
		func(w *Workspace) { w.Tenant = "foreign" },
		func(w *Workspace) { w.ClusterID = "foreign" },
		func(w *Workspace) { w.Directory = t.TempDir() },
		func(w *Workspace) { w.Tenant = "foreign"; w.Directory += "/" },
		func(w *Workspace) {
			w.Tenant = "foreign"
			w.Directory = "/var/lib/layersentry/kubeone/lab-dc/../lab-dc/kubeone-dc"
		},
		func(w *Workspace) { w.Manifest += ".other" },
		func(w *Workspace) { w.Kubeconfig += ".other" },
		func(w *Workspace) { w.TFJSON = "foreign.json" },
		func(w *Workspace) { w.Credentials = "foreign" },
		func(w *Workspace) { w.ExpectedCPNodes = 1 },
		func(w *Workspace) { w.ExpectedNodes = 3 },
		func(w *Workspace) { w.Provisionable = false },
		func(w *Workspace) { w.SelfServiceLifecycle = false },
	} {
		bad := w
		mutate(&bad)
		if !nativeWorkspaceSelected(bad) || nativeWorkspaceExact(bad) {
			t.Fatal("protected identity/path alias bypassed exact owner")
		}
		if lease, e := lockNativeWorkspace(bad); e == nil || lease != nil {
			t.Fatal("aliased owner obtained operation lock")
		}
	}
	p := &Portal{}
	if p.verifyNativeWorkspaceProvision(context.Background(), w, nil) == nil {
		t.Fatal("omitted native authority admitted provisioning")
	}
	p.nativeWorkspaceSuccessor = true
	if p.verifyNativeWorkspaceProvision(context.Background(), w, nil) == nil {
		t.Fatal("missing held operation lease admitted provisioning")
	}
	unrelated := Workspace{Tenant: "other", ClusterID: "other", Directory: t.TempDir()}
	if lease, e := lockNativeWorkspace(unrelated); e != nil || lease != nil {
		t.Fatal("unrelated workspace changed")
	}
	if p.verifyNativeWorkspaceProvision(context.Background(), unrelated, nil) != nil {
		t.Fatal("unrelated provisioning changed")
	}
}

func TestRegistryResolvesPathAndSymlinkAliasesBeforeOwnerSelection(t *testing.T) {
	root, w := tempWorkspace(t)
	canonical := filepath.Join(root, w.Directory)
	if e := os.Symlink(canonical, filepath.Join(root, "alias")); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{"alias", "tenant-a/../tenant-a/cluster-a/"} {
		x := w
		x.Directory = dir
		r, e := NewRegistry(root, RegistryFile{Clusters: []Workspace{x}})
		if e != nil {
			t.Fatal(e)
		}
		resolved, e := r.Resolve(w.Tenant, w.ClusterID)
		if e != nil || resolved.Directory != canonical {
			t.Fatal("registry alias remained unresolved", e)
		}
	}
}

// A failed terminal write must not turn an actual native attempt into retry
// authority. The prior durable RUNNING bytes remain exact; the ordinary restart
// reader can subsequently classify them UNKNOWN, without replaying Apply.
func TestProvisionTerminalWriteFailurePreservesNonretryableIntent(t *testing.T) {
	if os.Geteuid() == 0 {
		root, e := os.MkdirTemp("", "workspace-terminal-failure-")
		if e != nil {
			t.Fatal(e)
		}
		defer os.RemoveAll(root)
		if e = os.Chown(root, workspaceproof.CallerID, workspaceproof.CallerID); e != nil {
			t.Fatal(e)
		}
		binary := filepath.Join(root, "test-owner")
		raw, e := os.ReadFile(os.Args[0])
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(binary, raw, 0755); e != nil {
			t.Fatal(e)
		}
		// The child runs as the scoped unprivileged owner; umask must not
		// remove its execute permission from this test-only binary.
		if e = os.Chmod(binary, 0755); e != nil {
			t.Fatal(e)
		}
		c := exec.Command(binary, "-test.run=^TestProvisionTerminalWriteFailurePreservesNonretryableIntent$", "-test.v")
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: workspaceproof.CallerID, Gid: workspaceproof.CallerID, Groups: []uint32{}}}
		if out, e := c.CombinedOutput(); e != nil {
			t.Fatalf("isolated unprivileged child: %v\n%s", e, out)
		}
		return
	}
	p, _, w, runner := provisionAdmissionFixture(t)
	job := ProvisionJob{ID: strings.Repeat("b", 32), ClusterID: w.ClusterID, Status: "RUNNING", ExpectedNodes: w.ExpectedNodes, RequestedAt: time.Now().UTC()}
	if e := writeBoundedJob(w, provisionJobPath(w), ".test-intent-", job); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(provisionJobPath(w))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(w.Directory, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(w.Directory, 0700)
	p.runProvision(registryKey(w.Tenant, w.ClusterID), w, job, nil)
	after, e := os.ReadFile(provisionJobPath(w))
	if e != nil || string(after) != string(before) {
		t.Fatal("failed terminal publication changed original intent", e)
	}
	var retained ProvisionJob
	if readBoundedJob(provisionJobPath(w), &retained) != nil || retained.Status != "RUNNING" || retryableProvisionJob(retained, w) || runner.applyCalls != 1 {
		t.Fatal("write failure became success or replay authority")
	}
}

type heldProvisionRunner struct {
	Runner
	entered chan struct{}
	release chan struct{}
}

func (r *heldProvisionRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if strings.HasPrefix(strings.Join(args, " "), "apply --manifest ") {
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			return CommandResult{}, ctx.Err()
		}
	}
	return r.Runner.Run(ctx, dir, binary, args, env)
}

// Exercise the actual asynchronous provision owner with a synthetic native
// runner. An independent OS process must remain excluded through terminal job
// publication, then reuse the same persistent lock inode after release.
func TestProvisionRetainsWorkspaceLeaseAcrossProcessAndTerminalWrite(t *testing.T) {
	for _, kind := range []string{"provision", "worker", "control-plane"} {
		t.Run(kind, func(t *testing.T) { testLifecycleOwnerRetainsWorkspaceLease(t, kind) })
	}
}
func testLifecycleOwnerRetainsWorkspaceLease(t *testing.T, kind string) {
	p, _, w, runner := provisionAdmissionFixture(t)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	d, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	l, e := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid()))
	if e != nil {
		d.Close()
		t.Fatal(e)
	}
	lease := &nativeWorkspaceLease{dir: d, lock: l}
	before, e := os.Stat(filepath.Join(dir, workspaceOperationLockName))
	if e != nil {
		lease.Close()
		t.Fatal(e)
	}
	blocking := &heldProvisionRunner{Runner: runner, entered: make(chan struct{}), release: make(chan struct{})}
	p.Client.runner = blocking
	key := registryKey(w.Tenant, w.ClusterID)
	p.running[key] = true
	done := make(chan struct{})
	jobPath := provisionJobPath(w)
	if kind == "worker" {
		jobPath = workerJobPath(w)
	}
	if kind == "control-plane" {
		jobPath = controlPlaneJobPath(w)
	}
	go func() {
		switch kind {
		case "provision":
			p.runProvision(key, w, ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: w.ClusterID, Status: "RUNNING", ExpectedNodes: w.ExpectedNodes, RequestedAt: time.Now().UTC()}, lease)
		case "worker":
			p.runWorkerReconcile(key, w, WorkerReconcileJob{ID: strings.Repeat("a", 32), ClusterID: w.ClusterID, Status: "RUNNING", ExpectedNodes: w.ExpectedNodes, RequestedAt: time.Now().UTC()}, lease)
		case "control-plane":
			p.runControlPlaneReconcile(key, w, ControlPlaneReconcileJob{ID: strings.Repeat("a", 32), ClusterID: w.ClusterID, Status: "RUNNING", ExpectedControlPlanes: w.ExpectedCPNodes, RequestedAt: time.Now().UTC()}, lease)
		}
		close(done)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply not entered")
	}
	child := func() int {
		c := exec.Command(os.Args[0], "-test.run=^TestWorkspaceOperationCrossProcessAndRestart$")
		c.Env = append(os.Environ(), "LS_TEST_WORKSPACE_LOCK_CHILD="+dir)
		if e := c.Run(); e != nil {
			if x, ok := e.(*exec.ExitError); ok {
				return x.ExitCode()
			}
			t.Fatal(e)
		}
		return 0
	}
	blocked := child()
	close(blocking.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("provision did not finish")
	}
	if blocked != 2 {
		t.Fatal("independent process bypassed native apply lease")
	}
	var jobID, jobStatus string
	var readErr error
	switch kind {
	case "provision":
		var job ProvisionJob
		readErr = readBoundedJob(jobPath, &job)
		jobID, jobStatus = job.ID, job.Status
	case "worker":
		var job WorkerReconcileJob
		readErr = readBoundedJob(jobPath, &job)
		jobID, jobStatus = job.ID, job.Status
	case "control-plane":
		var job ControlPlaneReconcileJob
		readErr = readBoundedJob(jobPath, &job)
		jobID, jobStatus = job.ID, job.Status
	}
	if readErr != nil || jobStatus == "RUNNING" || jobID != strings.Repeat("a", 32) {
		t.Fatal("lease released without terminal durable job", readErr)
	}
	if child() != 0 {
		t.Fatal("operation not available after terminal job")
	}
	after, e := os.Stat(filepath.Join(dir, workspaceOperationLockName))
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("operation lock inode replaced")
	}
}
