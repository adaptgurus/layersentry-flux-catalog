package lifecycle

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

// Source qualification uses the real authenticated portal, with a runner that
// cannot touch a cluster. Readback returns healthy topology so corruption cannot
// be hidden by an unrelated readiness failure.
type reconciliationAdmissionRunner struct {
	portalRunner
	calls int
}

func (r *reconciliationAdmissionRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	r.calls++
	return r.portalRunner.Run(ctx, dir, binary, args, env)
}

func TestReconciliationRejectsUnreadablePriorIntent(t *testing.T) {
	for _, endpoint := range []string{"worker-reconciliation", "control-plane-reconciliation"} {
		for _, stateFile := range []string{workerReconcileFile, controlPlaneReconcileFile, provisionFile} {
			for _, corruption := range []string{"truncated", "trailing", "null", "foreign cluster"} {
				t.Run(endpoint+"/"+stateFile+"/"+corruption, func(t *testing.T) {
					root, ws := tempWorkspace(t)
					ws.ExpectedNodes, ws.SelfServiceLifecycle = 4, true
					registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
					if err != nil {
						t.Fatal(err)
					}
					ws, err = registry.Resolve(ws.Tenant, ws.ClusterID)
					if err != nil {
						t.Fatal(err)
					}
					runner := &reconciliationAdmissionRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}}
					client, err := NewClient(registry, runner, ClientConfig{KubeOneBinary: executable(t, root, "kubeone"), KubectlBinary: executable(t, root, "kubectl"), Timeout: time.Second})
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
					raw := []byte(`{"id":"prior-operation","cluster_id":"cluster-a","status":"SUCCEEDED"}`)
					switch corruption {
					case "truncated":
						raw = []byte("{")
					case "trailing":
						raw = append(raw, []byte(" {}")...)
					case "null":
						raw = []byte("null")
					case "foreign cluster":
						raw = bytes.ReplaceAll(raw, []byte("cluster-a"), []byte("cluster-foreign"))
					}
					path := filepath.Join(ws.Directory, stateFile)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					response := portalRequest(t, auth.Middleware(portal.Handler()), http.MethodPost, fmt.Sprintf("/v1/kubernetes/clusters/%s/%s", ws.ClusterID, endpoint), "{}", ws.Tenant)
					if response.Code != http.StatusInternalServerError {
						t.Errorf("unreadable intent not fenced: status=%d body=%s", response.Code, response.Body.String())
					}
					if runner.calls != 0 {
						t.Errorf("unreadable intent reached command runner: %d calls", runner.calls)
					}
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(raw, after) {
						t.Errorf("prior intent was overwritten: err=%v", err)
					}
					for _, other := range []string{workerReconcileFile, controlPlaneReconcileFile, provisionFile} {
						if other == stateFile {
							continue
						}
						if _, err := os.Lstat(filepath.Join(ws.Directory, other)); !os.IsNotExist(err) {
							t.Errorf("created %s while prior state unreadable: %v", other, err)
						}
					}
					if len(portal.running) != 0 {
						t.Error("failed admission leaked running ownership")
					}
				})
			}
		}
	}
}
