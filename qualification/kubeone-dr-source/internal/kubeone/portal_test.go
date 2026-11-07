package kubeone

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func portalAdminRequest(t *testing.T, handler http.Handler, method, path, body, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayUserHeader, "oneadmin")
	req.Header.Set(platformapi.GatewayUIDHeader, "0")
	req.Header.Set(platformapi.GatewayTenantHeader, tenant)
	req.Header.Set(platformapi.GatewayAdminHeader, "true")
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
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
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
