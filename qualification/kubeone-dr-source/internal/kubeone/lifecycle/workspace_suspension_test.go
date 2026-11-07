package lifecycle

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestSuspendedIncompleteWorkspacePortalFence(t *testing.T) {
	root, ws := tempWorkspace(t)
	if err := os.Remove(filepath.Join(root, ws.Directory, ws.Kubeconfig)); err != nil {
		t.Fatal(err)
	}
	// Reproduce the actual pre-provisioning state without copying live credentials.
	raw, err := json.Marshal(RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"cluster_id":"cluster-a"`, `"cluster_id":"cluster-a","suspended":true`, 1))
	registryPath := filepath.Join(root, "registry.json")
	if err := os.WriteFile(registryPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(root, registryPath)
	if err != nil {
		t.Fatalf("cannot retain an incomplete, non-provisionable suspended workspace: %v", err)
	}
	runner := &fakeRunner{}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"), KubectlBinary: executable(t, root, "kubectl"), Timeout: time.Second,
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
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"suspended":true`) || strings.Contains(list.Body.String(), `"provisionable":true`) {
		t.Fatalf("suspension missing from inventory: %d %s", list.Code, list.Body.String())
	}
	foreign := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters", "", "tenant-b")
	if foreign.Code != http.StatusOK || strings.Contains(foreign.Body.String(), "cluster-a") {
		t.Fatal("cross-tenant inventory leak")
	}
	for _, route := range []struct{ method, suffix string }{
		{"GET", "diagnostics"}, {"GET", "provision"}, {"POST", "provision"},
		{"POST", "workspace-successor/prepare"}, {"GET", "control-plane-reconciliation"}, {"POST", "control-plane-reconciliation"},
		{"GET", "namespaces"}, {"POST", "namespaces"}, {"GET", "kubeconfig"},
		{"GET", "worker-reconciliation"}, {"POST", "worker-reconciliation"},
		{"GET", "applications"}, {"POST", "applications/test"},
	} {
		t.Run(route.method+"/"+route.suffix, func(t *testing.T) {
			result := portalAdminRequest(t, handler, route.method, "/v1/kubernetes/clusters/cluster-a/"+route.suffix, `{}`, "tenant-a")
			if result.Code < 400 || result.Code >= 500 {
				t.Fatalf("suspended admin route was not denied: %d %s", result.Code, result.Body.String())
			}
		})
	}
	if len(runner.calls) != 0 {
		t.Fatalf("suspended workspace dispatched %d native commands", len(runner.calls))
	}
	for _, name := range []string{ws.Kubeconfig, provisionFile, workerReconcileFile, controlPlaneReconcileFile, ".layersentry-workspace-operation.lock"} {
		if _, err := os.Lstat(filepath.Join(root, ws.Directory, name)); !os.IsNotExist(err) {
			t.Fatalf("suspended operation created %s: %v", name, err)
		}
	}
}

func TestSuspensionDoesNotGrantLifecycleOrBypassPathValidation(t *testing.T) {
	for _, flag := range []string{"provision", "self-service", "repair", "manifest-escape", "kubeconfig-escape", "unsuspend-without-kubeconfig"} {
		t.Run(flag, func(t *testing.T) {
			root, ws := tempWorkspace(t)
			ws.Suspended = true
			switch flag {
			case "provision":
				ws.Provisionable = true
			case "self-service":
				ws.SelfServiceLifecycle = true
			case "repair":
				ws.AutonomousWorkerRepairQualified = true
			case "manifest-escape":
				ws.Manifest = "../../../../absent"
			case "kubeconfig-escape":
				ws.Kubeconfig = "../../escaped"
			case "unsuspend-without-kubeconfig":
				ws.Suspended = false
				if err := os.Remove(filepath.Join(root, ws.Directory, ws.Kubeconfig)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
