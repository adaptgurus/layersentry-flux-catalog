package lifecycle

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func provisionAdmissionFixture(t *testing.T) (*Portal, http.Handler, Workspace, *provisionRunner) {
	t.Helper()
	root, ws := tempWorkspace(t)
	if err := os.Remove(filepath.Join(root, ws.Directory, ws.Kubeconfig)); err != nil {
		t.Fatal(err)
	}
	ws.Provisionable, ws.SelfServiceLifecycle, ws.ExpectedNodes = true, true, 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &provisionRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"), KubectlBinary: executable(t, root, "kubectl"),
		Timeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(ws.Tenant, ws.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	return portal, auth.Middleware(portal.Handler()), resolved, runner
}

func TestProvisionPreservesUnreadableOrNonretryableIntent(t *testing.T) {
	for _, state := range []string{"corrupt", "truncated", "symlink", "directory", "foreign", "UNKNOWN", "RUNNING", "SUCCEEDED", "FAILED", "unrecognized", "unproved NOT_STARTED"} {
		t.Run(state, func(t *testing.T) {
			_, handler, ws, runner := provisionAdmissionFixture(t)
			path := provisionJobPath(ws)
			job := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID,
				Status: state, ExpectedNodes: ws.ExpectedNodes, RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
			if state == "foreign" {
				job.Status, job.ClusterID, job.EvidenceLabel = "NOT_STARTED", "foreign-cluster", "LIVE_PROVEN"
			}
			if state == "unproved NOT_STARTED" {
				job.Status = "NOT_STARTED"
			}
			raw, _ := json.Marshal(job)
			switch state {
			case "corrupt":
				raw = []byte("not json")
			case "truncated":
				raw = []byte(`{"status":"UNKNOWN"`)
			case "symlink":
				target := filepath.Join(ws.Directory, "original-intent")
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if state != "symlink" && state != "directory" {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			response := portalRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/provision", "{}", "tenant-a")
			if (response.Code != http.StatusConflict && response.Code != http.StatusInternalServerError) || runner.applyCalls != 0 {
				t.Fatalf("prior intent replayed: status=%d applies=%d", response.Code, runner.applyCalls)
			}
			if state != "directory" {
				actual, err := os.ReadFile(path)
				if err != nil || string(actual) != string(raw) {
					t.Fatalf("prior intent changed: %v", err)
				}
			}
			if state == "symlink" {
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("foreign symlink was replaced")
				}
			}
		})
	}
}

type admissionBody struct {
	io.Reader
	done  chan struct{}
	onEOF func()
}

func (b *admissionBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		if b.onEOF != nil {
			b.onEOF()
		}
		close(b.done)
	}
	return n, err
}

func TestProvisionAcceptsProvenUnstartedRetryOnce(t *testing.T) {
	_, handler, ws, runner := provisionAdmissionFixture(t)
	previous := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID, Status: "NOT_STARTED",
		ExpectedNodes: ws.ExpectedNodes, RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), EvidenceLabel: "LIVE_PROVEN"}
	if err := writeBoundedJob(ws, provisionJobPath(ws), ".test-repaired-*", previous); err != nil {
		t.Fatal(err)
	}
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	response := portalRequest(t, handler, http.MethodPost, path, "{}", "tenant-a")
	if response.Code != http.StatusAccepted {
		t.Fatalf("proven retry rejected: %s", response.Body.String())
	}
	var accepted struct {
		Job ProvisionJob `json:"job"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Job.ID == previous.ID || accepted.Job.Status != "RUNNING" {
		t.Fatal("retry did not publish a new running intent")
	}
	waitPortalJob(t, handler, path, "tenant-a", "SUCCEEDED")
	if runner.applyCalls != 1 {
		t.Fatalf("apply count=%d", runner.applyCalls)
	}
	var durable ProvisionJob
	if err := readBoundedJob(provisionJobPath(ws), &durable); err != nil {
		t.Fatal(err)
	}
	if durable.ID != accepted.Job.ID || durable.ReadyNodes != 4 {
		t.Fatalf("retry result differs: %+v", durable)
	}
	if result := portalRequest(t, handler, http.MethodPost, path, "{}", "tenant-a"); result.Code != http.StatusConflict {
		t.Fatalf("completed retry dispatched again: %d", result.Code)
	}
	if runner.applyCalls != 1 {
		t.Fatal("completed retry dispatched another apply")
	}
}

func TestProvisionPublicationFailureNeverDispatches(t *testing.T) {
	_, handler, ws, runner := provisionAdmissionFixture(t)
	// Resolve has completed before request-body validation. Remove the writable
	// workspace at that boundary so intent publication fails before dispatch.
	var moveErr error
	body := &admissionBody{Reader: strings.NewReader("{}"), done: make(chan struct{}), onEOF: func() {
		moveErr = os.Rename(ws.Directory, ws.Directory+".moved")
	}}
	req := httptest.NewRequest(http.MethodPost, "/v1/kubernetes/clusters/cluster-a/provision", body)
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "alice")
	req.Header.Set(platformapi.GatewayUIDHeader, "42")
	req.Header.Set(platformapi.GatewayTenantHeader, "tenant-a")
	setLifecycleTestStepUp(req)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if moveErr != nil {
		t.Fatal(moveErr)
	}
	if response.Code != http.StatusInternalServerError || runner.applyCalls != 0 {
		t.Fatalf("publication failure dispatched: status=%d applies=%d", response.Code, runner.applyCalls)
	}
}
func (b *admissionBody) Close() error { return nil }

func TestProvisionRechecksStepUpAfterRequestBody(t *testing.T) {
	_, handler, ws, _ := provisionAdmissionFixture(t)
	boundaryReached := false
	body := &admissionBody{Reader: strings.NewReader("{}"), done: make(chan struct{}), onEOF: func() {
		boundaryReached = true
		time.Sleep(1100 * time.Millisecond)
	}}
	req := httptest.NewRequest(http.MethodPost, "/v1/kubernetes/clusters/cluster-a/provision", body)
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "alice")
	req.Header.Set(platformapi.GatewayUIDHeader, "42")
	req.Header.Set(platformapi.GatewayTenantHeader, "tenant-a")
	setLifecycleTestStepUp(req)
	req.Header.Set(platformapi.GatewayStepUpAtHeader, time.Now().UTC().Add(-4*time.Minute-59*time.Second).Format(time.RFC3339Nano))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code == http.StatusAccepted {
		waitPortalJob(t, handler, req.URL.Path, "tenant-a", "SUCCEEDED")
	}
	if !boundaryReached {
		t.Fatal("test did not reach authorized body boundary")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired step-up reached dispatch: status=%d", response.Code)
	}
	if _, err := os.Lstat(provisionJobPath(ws)); !os.IsNotExist(err) {
		t.Fatal("expired step-up produced durable intent")
	}
}

func TestProvisionAdmissionReadsOutcomeAfterWaitingForCompletionLock(t *testing.T) {
	portal, handler, ws, runner := provisionAdmissionFixture(t)
	job := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID, Status: "NOT_STARTED",
		ExpectedNodes: ws.ExpectedNodes, RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), EvidenceLabel: "LIVE_PROVEN"}
	if err := writeBoundedJob(ws, provisionJobPath(ws), ".test-intent-*", job); err != nil {
		t.Fatal(err)
	}
	portal.mu.Lock()
	body := &admissionBody{Reader: strings.NewReader("{}"), done: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPost, "/v1/kubernetes/clusters/cluster-a/provision", body)
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "alice")
	req.Header.Set(platformapi.GatewayUIDHeader, "42")
	req.Header.Set(platformapi.GatewayTenantHeader, "tenant-a")
	setLifecycleTestStepUp(req)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { handler.ServeHTTP(response, req); close(done) }()
	<-body.done
	// Let admission reach the held lock. The previous implementation read the
	// NOT_STARTED file before waiting, so this completion transition was missed.
	time.Sleep(20 * time.Millisecond)
	job.Status, job.EvidenceLabel = "UNKNOWN", "UNKNOWN"
	err := writeBoundedJob(ws, provisionJobPath(ws), ".test-completion-*", job)
	portal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("admission did not complete")
	}
	if response.Code != http.StatusConflict || runner.applyCalls != 0 {
		t.Fatalf("stale admission dispatched: status=%d applies=%d", response.Code, runner.applyCalls)
	}
}
