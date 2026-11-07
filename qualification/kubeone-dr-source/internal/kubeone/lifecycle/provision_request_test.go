package lifecycle

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestProvisionRejectsUnsupportedInputBeforeIntentAndDispatch(t *testing.T) {
	for name, body := range map[string]string{
		"foreign manifest":    `{"manifest":"/foreign/kubeone.yaml"}`,
		"credential override": `{"sshPrivateKeyFile":"/foreign/key"}`,
		"force":               `{"force":true}`,
		"null":                `null`,
		"array":               `[]`,
		"trailing object":     `{} {}`,
		"malformed":           `{`,
		"oversized":           strings.Repeat(" ", int(maxPortalBodyBytes)+1),
	} {
		t.Run(name, func(t *testing.T) {
			root, ws := tempWorkspace(t)
			clusterDir := filepath.Join(root, ws.Directory)
			if err := os.Remove(filepath.Join(clusterDir, ws.Kubeconfig)); err != nil {
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
			response := portalRequest(t, auth.Middleware(portal.Handler()), http.MethodPost,
				"/v1/kubernetes/clusters/cluster-a/provision", body, "tenant-a")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("unsupported provisioning input status=%d body=%s", response.Code, response.Body.String())
			}
			if runner.applyCalls != 0 {
				t.Fatal("unsupported input dispatched KubeOne")
			}
			for _, name := range []string{provisionFile, ws.Kubeconfig} {
				if _, err := os.Stat(filepath.Join(clusterDir, name)); !os.IsNotExist(err) {
					t.Fatalf("unsupported input created %s: %v", name, err)
				}
			}
		})
	}
}
