package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Source-only original portal job execution with a fake runner. Its unchanged
// healthy topology provides no evidence that the requested Apply completed.
type attributionRunner struct {
	inner   Runner
	fail    bool
	applies int
}

// Hold the second health attempt after an explicit failed first readback. This
// exercises the real worker without waiting for its fixed production deadline.
type attributionHealthGate struct {
	inner   Runner
	checks  int
	blocked chan struct{}
	release chan struct{}
}

func (r *attributionHealthGate) Run(c context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if strings.Contains(strings.Join(args, " "), "get --raw=/readyz") {
		r.checks++
		if r.checks == 1 {
			return CommandResult{}, errors.New("fixture post-Apply health unavailable")
		}
		if r.checks == 2 {
			close(r.blocked)
			select {
			case <-r.release:
			case <-c.Done():
				return CommandResult{}, c.Err()
			}
		}
	}
	return r.inner.Run(c, dir, binary, args, env)
}

func TestApplyAttributionSuccessStillRequiresHealth(t *testing.T) {
	p, _, ws, r := attributionFixture(t)
	gate := &attributionHealthGate{inner: r.inner, blocked: make(chan struct{}), release: make(chan struct{})}
	r.inner = gate
	key := registryKey(ws.Tenant, ws.ClusterID)
	p.running[key] = true
	now := time.Now().UTC()
	job := WorkerReconcileJob{ID: strings.Repeat("c", 32), ClusterID: ws.ClusterID, Status: "RUNNING", ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	if err := writeWorkerJob(ws, job); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate.release) })
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture worker did not finish")
		}
	})
	go func() {
		p.runWorkerReconcile(key, ws, job, nil)
		close(done)
	}()
	select {
	case <-gate.blocked:
	case <-done:
		t.Fatal("job completed before qualified health")
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not reach blocked health readback")
	}
	var observed WorkerReconcileJob
	if err := readBoundedJob(workerJobPath(ws), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status != "RUNNING" || observed.EvidenceLabel != "UNKNOWN" || observed.ID != job.ID || r.applies != 1 {
		t.Fatal("successful Apply alone incorrectly completed the operation")
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish after healthy readback")
	}
	if err := readBoundedJob(workerJobPath(ws), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status != "SUCCEEDED" || observed.EvidenceLabel != "LIVE_PROVEN" || observed.ID != job.ID || r.applies != 1 {
		t.Fatal("confirmed command plus healthy readback failed")
	}
	t.Log("SOURCE_ONLY original Apply zero-exit; failed health keeps RUNNING; later valid health permits existing success; native_execution=false")
}

func (r *attributionRunner) Run(c context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if len(args) > 0 && args[0] == "apply" {
		r.applies++
		if r.fail {
			return CommandResult{}, errors.New("fixture original Apply returned without confirmation")
		}
	}
	return r.inner.Run(c, dir, binary, args, env)
}

func attributionFixture(t *testing.T) (*Portal, http.Handler, Workspace, *attributionRunner) {
	t.Helper()
	p, h, ws, _ := provisionAdmissionFixture(t)
	r := &attributionRunner{inner: p.Client.runner}
	p.Client.runner = r
	if err := p.Client.PersistKubeconfig(t.Context(), ws); err != nil {
		t.Fatal(err)
	}
	return p, h, ws, r
}

func TestApplyAttributionRequiresOriginalCommandSuccess(t *testing.T) {
	for _, kind := range []string{"provision", "worker", "control-plane"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/error-%t", kind, fail), func(t *testing.T) {
				p, _, ws, r := attributionFixture(t)
				r.fail = fail
				now := time.Now().UTC()
				id, key := strings.Repeat("a", 32), registryKey(ws.Tenant, ws.ClusterID)
				p.running[key] = true
				var path string
				switch kind {
				case "provision":
					job := ProvisionJob{ID: id, ClusterID: ws.ClusterID, Status: "RUNNING", ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					path = provisionJobPath(ws)
					if err := writeBoundedJob(ws, path, ".test-attribution-*", job); err != nil {
						t.Fatal(err)
					}
					p.runProvision(key, ws, job, nil)
				case "worker":
					job := WorkerReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: "RUNNING", ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					path = workerJobPath(ws)
					if err := writeWorkerJob(ws, job); err != nil {
						t.Fatal(err)
					}
					p.runWorkerReconcile(key, ws, job, nil)
				case "control-plane":
					job := ControlPlaneReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: "RUNNING", ExpectedControlPlanes: ws.ExpectedCPNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					path = controlPlaneJobPath(ws)
					if err := writeBoundedJob(ws, path, ".test-attribution-*", job); err != nil {
						t.Fatal(err)
					}
					p.runControlPlaneReconcile(key, ws, job, nil)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var job map[string]any
				if err := json.Unmarshal(raw, &job); err != nil {
					t.Fatal(err)
				}
				t.Logf("SOURCE_ONLY kind=%s original_apply_error=%t unchanged_healthy_topology=true job=%v applies=%d native_execution=false", kind, fail, job, r.applies)
				want, label := "SUCCEEDED", "LIVE_PROVEN"
				if fail {
					want, label = "UNKNOWN", "UNKNOWN"
				}
				if job["status"] != want || job["evidence_label"] != label || job["id"] != id || r.applies != 1 {
					t.Fatal("aggregate health replaced original command outcome")
				}
			})
		}
	}
}

func TestApplyAttributionPriorAmbiguityPreserved(t *testing.T) {
	for _, kind := range []string{"provision", "provision-via-worker", "worker", "control-plane"} {
		for _, state := range []string{"UNKNOWN", "RUNNING"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				_, h, ws, r := attributionFixture(t)
				now := time.Now().UTC().Add(-time.Minute)
				id := strings.Repeat("b", 32)
				var path, url string
				switch kind {
				case "provision", "provision-via-worker":
					path = provisionJobPath(ws)
					url = "/v1/kubernetes/clusters/cluster-a/provision"
					if kind == "provision-via-worker" {
						url = "/v1/kubernetes/clusters/cluster-a/worker-reconciliation"
					}
					job := ProvisionJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					if err := writeBoundedJob(ws, path, ".test-attribution-*", job); err != nil {
						t.Fatal(err)
					}
				case "worker":
					path = workerJobPath(ws)
					url = "/v1/kubernetes/clusters/cluster-a/worker-reconciliation"
					job := WorkerReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					if err := writeWorkerJob(ws, job); err != nil {
						t.Fatal(err)
					}
				case "control-plane":
					path = controlPlaneJobPath(ws)
					url = "/v1/kubernetes/clusters/cluster-a/control-plane-reconciliation"
					job := ControlPlaneReconcileJob{ID: id, ClusterID: ws.ClusterID, Status: state, ExpectedControlPlanes: ws.ExpectedCPNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
					if err := writeBoundedJob(ws, path, ".test-attribution-*", job); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				response := portalAdminRequest(t, h, http.MethodPost, url, "{}", ws.Tenant)
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("SOURCE_ONLY kind=%s original=%s response=%d applies=%d record_unchanged=%t native_execution=false", kind, state, response.Code, r.applies, string(before) == string(after))
				if response.Code != http.StatusConflict || r.applies != 0 || string(before) != string(after) {
					t.Fatal("healthy aggregate observations promoted or replaced prior ambiguous operation")
				}
			})
		}
	}
}
