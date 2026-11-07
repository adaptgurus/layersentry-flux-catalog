package lifecycle

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Source-only HTTP entry: different lifecycle job types use the same KubeOne
// workspace and Apply owner. Healthy old counts cannot clear another job.
func TestReconciliationCannotCrossPriorAmbiguity(t *testing.T) {
	for _, pair := range [][2]string{{"control-plane", "worker"}, {"worker", "control-plane"}, {"provision", "control-plane"}, {"worker", "provision"}, {"control-plane", "provision"}} {
		for _, state := range []string{"UNKNOWN", "RUNNING"} {
			t.Run(fmt.Sprintf("%s-to-%s/%s", pair[0], pair[1], state), func(t *testing.T) {
				_, h, ws, runner := attributionFixture(t)
				now := time.Now().UTC().Add(-time.Minute)
				id := strings.Repeat("d", 32)
				var path string
				var job any
				switch pair[0] {
				case "worker":
					path = workerJobPath(ws)
					job = WorkerReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
				case "control-plane":
					path = controlPlaneJobPath(ws)
					job = ControlPlaneReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedControlPlanes: ws.ExpectedCPNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
				case "provision":
					path = provisionJobPath(ws)
					job = ProvisionJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
				}
				if err := writeBoundedJob(ws, path, ".test-overlap-*", job); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				url := "/v1/kubernetes/clusters/cluster-a/" + pair[1] + "-reconciliation"
				targetPath := workerJobPath(ws)
				if pair[1] == "control-plane" {
					targetPath = controlPlaneJobPath(ws)
				} else if pair[1] == "provision" {
					url = "/v1/kubernetes/clusters/cluster-a/provision"
					targetPath = provisionJobPath(ws)
					if err := os.Remove(ws.Kubeconfig); err != nil {
						t.Fatal(err)
					}
				}
				runner.fail = true // Bound any incorrect async dispatch to UNKNOWN.
				response := portalAdminRequest(t, h, http.MethodPost, url, "{}", ws.Tenant)
				if response.Code == http.StatusAccepted {
					waitPortalJob(t, h, url, ws.Tenant, "UNKNOWN")
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				_, targetErr := os.Lstat(targetPath)
				t.Logf("SOURCE_ONLY prior=%s state=%s next=%s response=%d applies=%d original_unchanged=%t new_job_absent=%t native_execution=false", pair[0], state, pair[1], response.Code, runner.applies, string(before) == string(after), os.IsNotExist(targetErr))
				if response.Code != http.StatusConflict || runner.applies != 0 || string(before) != string(after) || !os.IsNotExist(targetErr) {
					t.Fatal("another job type crossed an unresolved original KubeOne outcome")
				}
			})
		}
	}
}

func overlapJob(t *testing.T, ws Workspace, kind, state string) (string, []byte) {
	t.Helper()
	now := time.Now().UTC()
	id := strings.Repeat("e", 32)
	var job any
	var path string
	switch kind {
	case "worker":
		path = workerJobPath(ws)
		job = WorkerReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	case "control-plane":
		path = controlPlaneJobPath(ws)
		job = ControlPlaneReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedControlPlanes: ws.ExpectedCPNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	case "provision":
		path = provisionJobPath(ws)
		job = ProvisionJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	default:
		t.Fatal("invalid fixture kind")
	}
	if err := writeBoundedJob(ws, path, ".test-overlap-*", job); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func overlapEndpoint(t *testing.T, ws Workspace, kind string) string {
	t.Helper()
	if kind == "provision" {
		if err := os.Remove(ws.Kubeconfig); err != nil {
			t.Fatal(err)
		}
		return "/v1/kubernetes/clusters/cluster-a/provision"
	}
	return "/v1/kubernetes/clusters/cluster-a/" + kind + "-reconciliation"
}

func TestReconciliationSettledAbsentAndActiveControls(t *testing.T) {
	for _, kind := range []string{"worker", "control-plane", "provision"} {
		for _, state := range []string{"absent", "SUCCEEDED", "active"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				p, h, ws, runner := attributionFixture(t)
				url := overlapEndpoint(t, ws, kind)
				var priorPath string
				var prior []byte
				if state == "active" {
					priorPath, prior = overlapJob(t, ws, kind, "RUNNING")
					p.running[registryKey(ws.Tenant, ws.ClusterID)] = true
				} else if state == "SUCCEEDED" {
					other := "worker"
					if kind == "worker" {
						other = "control-plane"
					}
					priorPath, prior = overlapJob(t, ws, other, "SUCCEEDED")
				}
				response := portalAdminRequest(t, h, http.MethodPost, url, "{}", ws.Tenant)
				want, applies := http.StatusOK, 0
				if state == "active" || kind == "provision" {
					want = http.StatusAccepted
				}
				if kind == "provision" && state != "active" {
					waitPortalJob(t, h, url, ws.Tenant, "SUCCEEDED")
					applies = 1
				}
				if response.Code != want || runner.applies != applies {
					t.Fatalf("control changed: response=%d applies=%d", response.Code, runner.applies)
				}
				if priorPath != "" {
					after, err := os.ReadFile(priorPath)
					if err != nil || string(after) != string(prior) {
						t.Fatal("control rewrote another settled or active original record", err)
					}
				}
				p.mu.Lock()
				busy := p.running[registryKey(ws.Tenant, ws.ClusterID)]
				p.mu.Unlock()
				if busy != (state == "active") {
					t.Fatal("control changed reservation ownership")
				}
			})
		}
	}
}

type overlapStatusHook struct {
	Runner
	once sync.Once
	hook func()
}

func (r *overlapStatusHook) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if strings.Contains(strings.Join(args, " "), "get --raw=/readyz") {
		r.once.Do(r.hook)
	}
	return r.Runner.Run(ctx, dir, binary, args, env)
}

func TestReconciliationRechecksAfterHealthCallback(t *testing.T) {
	for _, kind := range []string{"worker", "control-plane"} {
		for _, state := range []string{"UNKNOWN", "unreadable"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				p, h, ws, runner := attributionFixture(t)
				other, target := "worker", controlPlaneJobPath(ws)
				if kind == "worker" {
					other, target = "control-plane", workerJobPath(ws)
				}
				var path string
				var original []byte
				runner.inner = &overlapStatusHook{Runner: runner.inner, hook: func() {
					path, original = overlapJob(t, ws, other, "UNKNOWN")
					if state == "unreadable" {
						original = []byte("{truncated")
						if err := os.WriteFile(path, original, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}}
				url := overlapEndpoint(t, ws, kind)
				response := portalAdminRequest(t, h, http.MethodPost, url, "{}", ws.Tenant)
				want := http.StatusConflict
				if state == "unreadable" {
					want = http.StatusInternalServerError
				}
				after, err := os.ReadFile(path)
				_, targetErr := os.Lstat(target)
				if response.Code != want || runner.applies != 0 || err != nil || string(after) != string(original) || !os.IsNotExist(targetErr) {
					t.Fatalf("late state crossed final admission: response=%d applies=%d err=%v target=%v", response.Code, runner.applies, err, targetErr)
				}
				p.mu.Lock()
				busy := p.running[registryKey(ws.Tenant, ws.ClusterID)]
				p.mu.Unlock()
				if busy {
					t.Fatal("synchronous rejection leaked its reservation")
				}
			})
		}
	}
}

func TestReconciliationPendingDoesNotHideLaterReadError(t *testing.T) {
	_, _, ws, _ := attributionFixture(t)
	overlapJob(t, ws, "worker", "UNKNOWN")
	path, _ := overlapJob(t, ws, "control-plane", "SUCCEEDED")
	if err := os.WriteFile(path, []byte("{truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciliationState(ws); err == nil {
		t.Fatal("earlier pending state hid a later unreadable original record")
	}
}

func TestReconciliationPublicationFailureReleasesReservation(t *testing.T) {
	for _, kind := range []string{"worker", "control-plane"} {
		t.Run(kind, func(t *testing.T) {
			p, h, ws, runner := attributionFixture(t)
			runner.inner = &overlapStatusHook{Runner: runner.inner, hook: func() {
				if err := os.Rename(ws.Directory, ws.Directory+".moved"); err != nil {
					t.Fatal(err)
				}
			}}
			response := portalAdminRequest(t, h, http.MethodPost, overlapEndpoint(t, ws, kind), "{}", ws.Tenant)
			p.mu.Lock()
			busy := p.running[registryKey(ws.Tenant, ws.ClusterID)]
			p.mu.Unlock()
			t.Logf("SOURCE_ONLY publication_unavailable=true kind=%s response=%d applies=%d busy=%t native_execution=false", kind, response.Code, runner.applies, busy)
			if response.Code != http.StatusInternalServerError || runner.applies != 0 || busy || strings.Contains(response.Body.String(), `"status":"SUCCEEDED"`) {
				t.Fatal("failed publication reported success or leaked reservation")
			}
		})
	}
}

func TestReconciliationWaitsForFinalCompletionLock(t *testing.T) {
	p, h, ws, runner := attributionFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	runner.inner = &overlapStatusHook{Runner: runner.inner, hook: func() { close(entered); <-release }}
	var responseCode int
	go func() {
		responseCode = portalAdminRequest(t, h, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/control-plane-reconciliation", "{}", ws.Tenant).Code
		close(done)
	}()
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture request did not finish")
		}
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not reach health callback")
	}
	var path string
	var original []byte
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		unblock() // The request must wait for this completion's final lock.
		path, original = overlapJob(t, ws, "worker", "UNKNOWN")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete")
	}
	after, err := os.ReadFile(path)
	if responseCode != http.StatusConflict || runner.applies != 0 || err != nil || string(after) != string(original) {
		t.Fatal("waiting request did not preserve the completed UNKNOWN outcome", responseCode, err)
	}
}
