package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls []struct {
		dir    string
		binary string
		args   []string
	}
	status map[string]CommandResult
	err    error
}

func (f *fakeRunner) Run(_ context.Context, dir, binary string, args, _ []string) (CommandResult, error) {
	f.calls = append(f.calls, struct {
		dir    string
		binary string
		args   []string
	}{dir: dir, binary: binary, args: append([]string(nil), args...)})
	if f.err != nil {
		return CommandResult{}, f.err
	}
	key := strings.Join(args, " ")
	if value, ok := f.status[key]; ok {
		return value, nil
	}
	return CommandResult{}, nil
}

func tempWorkspace(t *testing.T) (string, Workspace) {
	t.Helper()
	root := t.TempDir()
	clusterDir := filepath.Join(root, "tenant-a", "cluster-a")
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kubeone.yaml", "kubeconfig", "tf.json", "credentials.yaml"} {
		if err := os.WriteFile(filepath.Join(clusterDir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, Workspace{
		Tenant: "tenant-a", ClusterID: "cluster-a",
		Directory: filepath.Join("tenant-a", "cluster-a"),
		Manifest:  "kubeone.yaml", Kubeconfig: "kubeconfig",
		TFJSON: "tf.json", Credentials: "credentials.yaml",
		ExpectedCPNodes: 3,
	}
}

func executable(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegistryRejectsWorkspaceEscape(t *testing.T) {
	root, ws := tempWorkspace(t)
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "tenant-a", "cluster-a", "escape.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	ws.Manifest = "escape.yaml"
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
		t.Fatal("registry must reject symlink escape")
	}
}

func TestApplyUsesFixedTypedArguments(t *testing.T) {
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve("tenant-a", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{status: map[string]CommandResult{}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"),
		KubectlBinary: executable(t, root, "kubectl"),
		Timeout:       time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Apply(context.Background(), resolved, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls=%d", len(runner.calls))
	}
	got := runner.calls[0].args
	want := []string{
		"apply", "--manifest", resolved.Manifest, "--auto-approve",
		"-t", resolved.TFJSON, "--credentials", resolved.Credentials,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%q want=%q", got, want)
	}
	for _, arg := range got {
		if strings.ContainsAny(arg, ";&|`$") {
			t.Fatalf("unexpected shell metacharacter in fixed argv: %q", arg)
		}
	}
}

func TestStatusUsesReadOnlyKubectlAndParsesHealth(t *testing.T) {
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := registry.Resolve("tenant-a", "cluster-a")
	base := "--kubeconfig " + resolved.Kubeconfig + " "
	nodes := `{"items":[{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp2","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp3","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"worker1","labels":{}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
	pods := `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"fixture-container","ready":true}]}},{"status":{"phase":"Succeeded","containerStatuses":[]}}]}`
	runner := &fakeRunner{status: map[string]CommandResult{
		base + "get --raw=/readyz":               {Stdout: "ok\n"},
		base + "get nodes -o json":               {Stdout: nodes},
		base + "get pods -n kube-system -o json": {Stdout: pods},
	}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"),
		KubectlBinary: executable(t, root, "kubectl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !status.APIReady || status.ReadyNodes != 4 || status.ControlPlanes != 3 || status.ReadyControlPlanes != 3 || status.KubeSystemNonReady != 0 {
		t.Fatalf("unexpected status %#v", status)
	}
	for _, call := range runner.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, " delete ") || strings.Contains(joined, " apply ") || strings.Contains(joined, " patch ") {
			t.Fatalf("status used mutating kubectl command: %s", joined)
		}
	}
}

func TestRegistryRequiresDurableBaselineForAutonomousWorkerRepair(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.AutonomousWorkerRepairQualified = true
	ws.ExpectedNodes = 0
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
		t.Fatal("autonomous worker repair without expected_nodes baseline was accepted")
	}
	ws.ExpectedNodes = ws.ExpectedCPNodes
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
		t.Fatal("autonomous worker repair without at least one declared worker was accepted")
	}
	ws.ExpectedNodes = ws.ExpectedCPNodes + 1
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err != nil {
		t.Fatalf("qualified autonomous worker baseline rejected: %v", err)
	}
}

func TestProvisionableWorkspaceAllowsMissingKubeconfig(t *testing.T) {
	root, ws := tempWorkspace(t)
	clusterDir := filepath.Join(root, "tenant-a", "cluster-a")
	if err := os.Remove(filepath.Join(clusterDir, "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	ws.Provisionable = true
	ws.SelfServiceLifecycle = true
	ws.ExpectedNodes = ws.ExpectedCPNodes
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatalf("provisionable workspace rejected: %v", err)
	}
	resolved, err := registry.Resolve("tenant-a", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Kubeconfig != filepath.Join(clusterDir, "kubeconfig") {
		t.Fatalf("unexpected kubeconfig output path %q", resolved.Kubeconfig)
	}
	if !resolved.SelfServiceLifecycle {
		t.Fatal("self-service lifecycle policy was not preserved")
	}

	ws.Provisionable = false
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
		t.Fatal("existing non-provisionable cluster without kubeconfig was accepted")
	}
}

func TestLifecycleWorkspaceRequiresExplicitTopologyBaseline(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.Provisionable = true
	ws.ExpectedNodes = 0
	if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil ||
		!strings.Contains(err.Error(), "explicit total-node baseline") {
		t.Fatalf("lifecycle workspace without an explicit topology baseline was accepted: %v", err)
	}
}

func TestPersistKubeconfigUsesTypedKubeOneCommand(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.Provisionable = true
	ws.ExpectedNodes = ws.ExpectedCPNodes
	if err := os.Remove(filepath.Join(root, "tenant-a", "cluster-a", "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := registry.Resolve("tenant-a", "cluster-a")
	key := strings.Join([]string{
		"kubeconfig", "--manifest", resolved.Manifest,
		"-t", resolved.TFJSON, "--credentials", resolved.Credentials,
	}, " ")
	runner := &fakeRunner{status: map[string]CommandResult{
		key: {Stdout: "apiVersion: v1\nkind: Config\n"},
	}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"),
		KubectlBinary: executable(t, root, "kubectl"),
		Timeout:       time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.PersistKubeconfig(context.Background(), resolved); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(resolved.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "apiVersion: v1\nkind: Config" {
		t.Fatalf("unexpected kubeconfig contents %q", string(raw))
	}
	info, err := os.Stat(resolved.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("kubeconfig mode=%#o", info.Mode().Perm())
	}
	if !client.KubeconfigExists(resolved) {
		t.Fatal("persisted kubeconfig not detected")
	}
}
