package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

type portalRunner struct{ namespaceRunner }

func (r *portalRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "get --raw=/readyz"):
		return CommandResult{Stdout: "ok\n"}, nil
	case strings.Contains(joined, "get nodes -o json"):
		return CommandResult{Stdout: `{"items":[{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp2","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp3","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"worker1","labels":{}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`}, nil
	case strings.Contains(joined, "get pods -n kube-system -o json"):
		return CommandResult{Stdout: `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"fixture-container","ready":true}]}}]}`}, nil
	default:
		return r.namespaceRunner.Run(ctx, dir, binary, args, env)
	}
}

type failedReadbackRunner struct{ portalRunner }

func (r *failedReadbackRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if strings.Contains(strings.Join(args, " "), "get --raw=/readyz") {
		return CommandResult{}, errors.New("API transport unavailable")
	}
	return r.portalRunner.Run(ctx, dir, binary, args, env)
}

func portalAdminRequest(t *testing.T, handler http.Handler, method, path, body, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "oneadmin")
	req.Header.Set(platformapi.GatewayUIDHeader, "0")
	req.Header.Set(platformapi.GatewayTenantHeader, tenant)
	req.Header.Set(platformapi.GatewayAdminHeader, "true")
	setLifecycleTestStepUp(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func portalRequest(t *testing.T, handler http.Handler, method, path, body, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "alice")
	req.Header.Set(platformapi.GatewayUIDHeader, "42")
	req.Header.Set(platformapi.GatewayTenantHeader, tenant)
	setLifecycleTestStepUp(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// Unit-test gateway projection only. Real enrollment proof is exercised by the
// private TLS gateway/portal integration, never by these synthetic headers.
func setLifecycleTestStepUp(req *http.Request) {
	req.Header.Set(platformapi.GatewayRolesHeader, "admin")
	req.Header.Set(platformapi.GatewayAssuranceHeader, "2")
	req.Header.Set(platformapi.GatewayStepUpAtHeader, time.Now().UTC().Format(time.RFC3339Nano))
}

func TestPortalTenantScopeNamespaceAndKubeconfig(t *testing.T) {
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &portalRunner{namespaceRunner: namespaceRunner{t: t}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(client, []AcceleratorProfile{{ID: "nvidia-vgpu-a16", Label: "NVIDIA A16 vGPU", Kind: "VGPU", MaxCount: 2}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(portal.Handler())

	list := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters", "", "tenant-a")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"id":"cluster-a"`) || !strings.Contains(list.Body.String(), `"kind":"VGPU"`) {
		t.Fatalf("unexpected cluster inventory: status=%d body=%s", list.Code, list.Body.String())
	}
	foreign := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters", "", "tenant-b")
	if foreign.Code != http.StatusOK || strings.Contains(foreign.Body.String(), "cluster-a") {
		t.Fatalf("cross-tenant inventory leak: status=%d body=%s", foreign.Code, foreign.Body.String())
	}
	capabilities := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/capabilities", "", "tenant-a")
	if capabilities.Code != http.StatusOK || !strings.Contains(capabilities.Body.String(), `"multi_cluster":true`) ||
		!strings.Contains(capabilities.Body.String(), `"destructive_lifecycle":false`) ||
		!strings.Contains(capabilities.Body.String(), `"code_tests_can_certify_live":false`) {
		t.Fatalf("unexpected portal capabilities: status=%d body=%s", capabilities.Code, capabilities.Body.String())
	}
	diagnostics := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/diagnostics", "", "tenant-a")
	if diagnostics.Code != http.StatusOK || !strings.Contains(diagnostics.Body.String(), `"phase":"HEALTHY"`) ||
		!strings.Contains(diagnostics.Body.String(), `"healthy":true`) ||
		!strings.Contains(diagnostics.Body.String(), `"evidence_label":"LIVE_PROVEN"`) ||
		!strings.Contains(diagnostics.Body.String(), `"production_certified":false`) {
		t.Fatalf("unexpected cluster diagnostics: status=%d body=%s", diagnostics.Code, diagnostics.Body.String())
	}
	created := portalRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/namespaces", `{"name":"customer-a"}`, "tenant-a")
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"created":true`) {
		t.Fatalf("namespace create failed: status=%d body=%s", created.Code, created.Body.String())
	}
	kubeconfig := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/kubeconfig", "", "tenant-a")
	if kubeconfig.Code != http.StatusOK || kubeconfig.Body.String() != "x" || kubeconfig.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected kubeconfig response: status=%d body=%q", kubeconfig.Code, kubeconfig.Body.String())
	}
}

func TestPortalRejectsUnqualifiedAcceleratorProfiles(t *testing.T) {
	client := &Client{}
	for _, profile := range []AcceleratorProfile{
		{ID: "../../gpu", Label: "GPU", Kind: "GPU", MaxCount: 1},
		{ID: "gpu", Label: "GPU", Kind: "FPGA", MaxCount: 1},
		{ID: "gpu", Label: "GPU", Kind: "GPU", MaxCount: 9},
	} {
		if _, err := NewPortal(client, []AcceleratorProfile{profile}); err == nil {
			t.Fatalf("invalid accelerator profile accepted: %#v", profile)
		}
	}
}

func TestPortalDiagnosticsFailClosedWhenReadbackIsUnavailable(t *testing.T) {
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &failedReadbackRunner{portalRunner{namespaceRunner{t: t}}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
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
	result := portalRequest(t, auth.Middleware(portal.Handler()), http.MethodGet,
		"/v1/kubernetes/clusters/cluster-a/diagnostics", "", "tenant-a")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"healthy":false`) ||
		!strings.Contains(result.Body.String(), `"code":"READBACK_UNAVAILABLE"`) ||
		strings.Contains(result.Body.String(), "API transport unavailable") {
		t.Fatalf("diagnostics did not fail closed safely: status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestPortalWorkerReconcileRequiresProviderAdminAndIsIdempotent(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &portalRunner{namespaceRunner: namespaceRunner{t: t}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
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
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/worker-reconciliation"
	denied := portalRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin worker reconcile status=%d body=%s", denied.Code, denied.Body.String())
	}
	result := portalAdminRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"status":"SUCCEEDED"`) || !strings.Contains(result.Body.String(), `already converged`) {
		t.Fatalf("idempotent worker reconcile status=%d body=%s", result.Code, result.Body.String())
	}
	readback := portalRequest(t, handler, http.MethodGet, path, "", "tenant-a")
	if readback.Code != http.StatusOK || !strings.Contains(readback.Body.String(), `"expected_nodes":4`) {
		t.Fatalf("worker job readback status=%d body=%s", readback.Code, readback.Body.String())
	}
}

type controlPlaneRunner struct {
	namespaceRunner
	applied  bool
	applyErr error
}

func (r *controlPlaneRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(joined, "apply --manifest "):
		r.applied = true
		if r.applyErr != nil {
			return CommandResult{}, r.applyErr
		}
		return CommandResult{Stdout: "apply completed"}, nil
	case strings.Contains(joined, "get --raw=/readyz"):
		return CommandResult{Stdout: "ok\n"}, nil
	case strings.Contains(joined, "get nodes -o json"):
		if r.applied {
			return CommandResult{Stdout: `{"items":[
				{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
				{"metadata":{"name":"cp2","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
				{"metadata":{"name":"cp3","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}
			]}`}, nil
		}
		return CommandResult{Stdout: `{"items":[
			{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
			{"metadata":{"name":"cp2","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}
		]}`}, nil
	case strings.Contains(joined, "get pods -n kube-system -o json"):
		return CommandResult{Stdout: `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"fixture-container","ready":true}]}}]}`}, nil
	default:
		return r.namespaceRunner.Run(ctx, dir, binary, args, env)
	}
}

type provisionRunner struct {
	portalRunner
	applyErr   error
	applyCalls int
}

func (r *provisionRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	joined := strings.Join(args, " ")
	if strings.HasPrefix(joined, "kubeconfig --manifest ") {
		return CommandResult{Stdout: "apiVersion: v1\nkind: Config\n"}, nil
	}
	if strings.HasPrefix(joined, "apply --manifest ") {
		r.applyCalls++
		if r.applyErr != nil {
			return CommandResult{}, r.applyErr
		}
		return CommandResult{Stdout: "apply completed"}, nil
	}
	return r.portalRunner.Run(ctx, dir, binary, args, env)
}

func waitPortalJob(t *testing.T, handler http.Handler, path, tenant, expected string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec := portalRequest(t, handler, http.MethodGet, path, "", tenant)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `"status":"`+expected+`"`) {
			return rec.Body.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach %s", path, expected)
	return ""
}

func TestPortalSelfServiceControlPlaneReconciliationUsesKubeOne(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.ExpectedCPNodes = 3
	ws.ExpectedNodes = 3
	ws.SelfServiceLifecycle = true
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &controlPlaneRunner{namespaceRunner: namespaceRunner{t: t}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"),
		Timeout:       time.Minute, PollInterval: time.Millisecond,
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
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/control-plane-reconciliation"
	result := portalRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatalf("control-plane reconcile status=%d body=%s", result.Code, result.Body.String())
	}
	body := waitPortalJob(t, handler, path, "tenant-a", "SUCCEEDED")
	if !runner.applied || !strings.Contains(body, `"ready_control_planes":3`) {
		t.Fatalf("control-plane reconcile did not use KubeOne/readback: applied=%v body=%s", runner.applied, body)
	}
}

func TestPortalControlPlaneKeepsApplyTransportFailureUnknownDespiteHealthyState(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.ExpectedCPNodes = 3
	ws.ExpectedNodes = 3
	ws.SelfServiceLifecycle = true
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &controlPlaneRunner{
		namespaceRunner: namespaceRunner{t: t},
		applyErr:        errors.New("transport closed after remote completion"),
	}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"),
		Timeout:       time.Minute, PollInterval: time.Millisecond,
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
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/control-plane-reconciliation"
	result := portalRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatalf("control-plane reconcile status=%d body=%s", result.Code, result.Body.String())
	}
	body := waitPortalJob(t, handler, path, "tenant-a", "UNKNOWN")
	if !runner.applied || !strings.Contains(body, `"evidence_label":"UNKNOWN"`) ||
		!strings.Contains(body, `current control-plane health cannot establish the original outcome`) {
		t.Fatalf("transport failure lost its original uncertainty: %s", body)
	}
	status, err := client.Status(t.Context(), ws)
	if err != nil || status.ReadyControlPlanes != 3 {
		t.Fatalf("fixture must remain healthy without proving Apply completion: %+v %v", status, err)
	}
}

func TestPortalDiagnosticsExplainsProvisioningPlan(t *testing.T) {
	root, ws := tempWorkspace(t)
	if err := os.Remove(filepath.Join(root, "tenant-a", "cluster-a", "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	ws.Provisionable = true
	ws.ExpectedNodes = ws.ExpectedCPNodes
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &portalRunner{namespaceRunner: namespaceRunner{t: t}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
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
	result := portalRequest(t, auth.Middleware(portal.Handler()), http.MethodGet,
		"/v1/kubernetes/clusters/cluster-a/diagnostics", "", "tenant-a")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"ready_to_provision":true`) ||
		!strings.Contains(result.Body.String(), `"code":"NOT_PROVISIONED"`) {
		t.Fatalf("provision diagnostics status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestPortalDiagnosticsFencesUnreconciledProvision(t *testing.T) {
	for _, scenario := range []struct {
		name, status             string
		corrupt, busy, retryable bool
	}{
		{name: "unknown", status: "UNKNOWN"},
		{name: "orphaned running", status: "RUNNING"},
		{name: "completed without kubeconfig", status: "SUCCEEDED"},
		{name: "failed", status: "FAILED"},
		{name: "active running", status: "RUNNING", busy: true},
		{name: "corrupt", corrupt: true},
		{name: "active lifecycle without job", busy: true},
		{name: "native proven not started", status: "NOT_STARTED", retryable: true},
		{name: "unproven not started", status: "NOT_STARTED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			portal, handler, ws, runner := provisionAdmissionFixture(t)
			jobPath := provisionJobPath(ws)
			if scenario.corrupt {
				if err := os.WriteFile(jobPath, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if scenario.status != "" {
				job := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID, Status: scenario.status, ExpectedNodes: ws.ExpectedNodes, RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), EvidenceLabel: "UNKNOWN"}
				if scenario.retryable {
					job.EvidenceLabel = "LIVE_PROVEN"
				}
				if err := writeBoundedJob(ws, jobPath, ".provision-test-*", job); err != nil {
					t.Fatal(err)
				}
			}
			before, beforeErr := os.ReadFile(jobPath)
			portal.running[registryKey(ws.Tenant, ws.ClusterID)] = scenario.busy
			result := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/diagnostics", "", "tenant-a")
			wantReady := `"ready_to_provision":false`
			if scenario.retryable {
				wantReady = `"ready_to_provision":true`
			}
			if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), wantReady) {
				t.Fatalf("incorrect replay readiness: %d %s", result.Code, result.Body.String())
			}
			if !scenario.retryable && !strings.Contains(result.Body.String(), `"code":"PROVISION_RECONCILIATION_REQUIRED"`) {
				t.Fatalf("missing durable fence explanation: %s", result.Body.String())
			}
			if runner.applyCalls != 0 {
				t.Fatal("diagnostics dispatched KubeOne apply")
			}
			after, afterErr := os.ReadFile(jobPath)
			if string(before) != string(after) || errors.Is(beforeErr, os.ErrNotExist) != errors.Is(afterErr, os.ErrNotExist) {
				t.Fatal("diagnostic read altered durable provisioning evidence")
			}
		})
	}
}

func TestPortalProvisionRegisteredKubeOnePlan(t *testing.T) {
	root, ws := tempWorkspace(t)
	clusterDir := filepath.Join(root, "tenant-a", "cluster-a")
	if err := os.Remove(filepath.Join(clusterDir, "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	ws.Provisionable = true
	ws.SelfServiceLifecycle = true
	ws.ExpectedCPNodes = 3
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &provisionRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"),
		Timeout:       time.Minute, PollInterval: time.Millisecond,
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
	handler := auth.Middleware(portal.Handler())
	list := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters", "", "tenant-a")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"provisioned":false`) || !strings.Contains(list.Body.String(), `"provisionable":true`) {
		t.Fatalf("unexpected provisionable inventory status=%d body=%s", list.Code, list.Body.String())
	}
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	result := portalRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatalf("provision status=%d body=%s", result.Code, result.Body.String())
	}
	body := waitPortalJob(t, handler, path, "tenant-a", "SUCCEEDED")
	if !strings.Contains(body, `"ready_nodes":4`) {
		t.Fatalf("provision did not verify expected topology: %s", body)
	}
	if _, err := os.Stat(filepath.Join(clusterDir, "kubeconfig")); err != nil {
		t.Fatalf("provision did not persist kubeconfig: %v", err)
	}
}

func TestPortalProvisionKeepsApplyTransportFailureUnknownDespiteHealthyState(t *testing.T) {
	root, ws := tempWorkspace(t)
	clusterDir := filepath.Join(root, "tenant-a", "cluster-a")
	if err := os.Remove(filepath.Join(clusterDir, "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	ws.Provisionable = true
	ws.SelfServiceLifecycle = true
	ws.ExpectedCPNodes = 3
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &provisionRunner{
		portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}},
		applyErr:     errors.New("transport closed after remote completion"),
	}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"),
		Timeout:       time.Minute, PollInterval: time.Millisecond,
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
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	result := portalRequest(t, handler, http.MethodPost, path, `{}`, "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatalf("provision status=%d body=%s", result.Code, result.Body.String())
	}
	body := waitPortalJob(t, handler, path, "tenant-a", "UNKNOWN")
	if runner.applyCalls != 1 || !strings.Contains(body, `"evidence_label":"UNKNOWN"`) ||
		!strings.Contains(body, `current cluster health cannot establish the original outcome`) {
		t.Fatalf("transport failure lost its original uncertainty: %s", body)
	}
	status, err := client.Status(t.Context(), ws)
	if err != nil || status.ReadyNodes != 4 {
		t.Fatalf("fixture must remain healthy without proving Apply completion: %+v %v", status, err)
	}
}

func TestPortalProvisionBlocksBlindReplayAfterUnknownOutcome(t *testing.T) {
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
		t.Fatal(err)
	}
	resolved, err := registry.Resolve("tenant-a", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := writeBoundedJob(resolved, provisionJobPath(resolved), ".layersentry-provision-*.tmp", ProvisionJob{
		ID: "unknown-provision", ClusterID: "cluster-a", Status: "UNKNOWN",
		ExpectedNodes: ws.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN",
	}); err != nil {
		t.Fatal(err)
	}
	runner := &provisionRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
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
	result := portalRequest(t, auth.Middleware(portal.Handler()), http.MethodPost,
		"/v1/kubernetes/clusters/cluster-a/provision", "{}", "tenant-a")
	if result.Code != http.StatusConflict || !strings.Contains(result.Body.String(), "automatic KubeOne replay is blocked") || runner.applyCalls != 0 {
		t.Fatalf("unknown provisioning outcome was replayed: status=%d calls=%d body=%s", result.Code, runner.applyCalls, result.Body.String())
	}
}

func TestPortalApplicationUnknownBlocksBlindHelmReplay(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &portalRunner{namespaceRunner: namespaceRunner{t: t}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "helm-mutation-called")
	helm := filepath.Join(root, "helm")
	script := "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then echo '[]'; exit 0; fi\necho mutation > " + marker + "\nexit 0\n"
	if err := os.WriteFile(helm, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := portal.ConfigureApplications([]ApplicationProfile{{
		ID: "strimzi-kafka", Label: "Strimzi Kafka Operator", Category: "messaging",
		RepositoryURL: "https://strimzi.io/charts/", Chart: "strimzi-kafka-operator",
		Version: "1.2.0", ReleaseName: "strimzi-kafka-operator", Namespace: "strimzi-system",
	}}, helm); err != nil {
		t.Fatal(err)
	}
	resolved, _ := registry.Resolve("tenant-a", "cluster-a")
	now := time.Now().UTC()
	if err := writeApplicationJob(resolved, ApplicationInstallJob{
		ID: "prior", ClusterID: resolved.ClusterID, Application: "strimzi-kafka",
		Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(portal.Handler())
	result := portalAdminRequest(t, handler, http.MethodPost,
		"/v1/kubernetes/clusters/cluster-a/applications/strimzi-kafka", "{}", "tenant-a")
	if result.Code != http.StatusConflict || !strings.Contains(result.Body.String(), "automatic Helm replay is blocked") {
		t.Fatalf("unknown Helm outcome was not blocked: status=%d body=%s", result.Code, result.Body.String())
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Helm mutation executed despite UNKNOWN prior outcome: %v", err)
	}
}

func TestPortalApplicationTransportFailureRemainsUnknownDespiteInventory(t *testing.T) {
	root, ws := tempWorkspace(t)
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &portalRunner{namespaceRunner: namespaceRunner{t: t}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-portal"),
		KubectlBinary: executable(t, root, "kubectl-portal"), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "helm-release-present")
	helm := filepath.Join(root, "helm-reconcile")
	script := "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then\n  if [ -e \"" + marker + "\" ]; then echo '[{\"name\":\"strimzi-kafka-operator\",\"namespace\":\"strimzi-system\",\"status\":\"deployed\",\"revision\":\"1\",\"chart\":\"strimzi-kafka-operator-1.2.0\"}]'; else echo '[]'; fi\n  exit 0\nfi\ntouch \"" + marker + "\"\nexit 1\n"
	if err := os.WriteFile(helm, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := portal.ConfigureApplications([]ApplicationProfile{{
		ID: "strimzi-kafka", Label: "Strimzi Kafka Operator", Category: "messaging",
		RepositoryURL: "https://strimzi.io/charts/", Chart: "strimzi-kafka-operator",
		Version: "1.2.0", ReleaseName: "strimzi-kafka-operator", Namespace: "strimzi-system",
	}}, helm); err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/applications/strimzi-kafka"
	result := portalAdminRequest(t, handler, http.MethodPost, path, "{}", "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatalf("application install status=%d body=%s", result.Code, result.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		inventory := portalAdminRequest(t, handler, http.MethodGet,
			"/v1/kubernetes/clusters/cluster-a/applications", "", "tenant-a")
		if inventory.Code == http.StatusOK && strings.Contains(inventory.Body.String(), `"status":"UNKNOWN"`) &&
			strings.Contains(inventory.Body.String(), `inventory cannot prove the original invocation`) {
			result := portalAdminRequest(t, handler, http.MethodPost, path, "{}", "tenant-a")
			if result.Code != http.StatusConflict {
				t.Fatal("uncertain install allowed replay", result.Code)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Helm transport failure did not preserve UNKNOWN despite matching inventory")
}
