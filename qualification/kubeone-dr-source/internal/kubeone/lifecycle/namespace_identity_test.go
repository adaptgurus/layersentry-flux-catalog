package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

const identityNamespaceJSON = `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"Opaque-UID-Aa"}}`

type namespaceIdentityRunner struct {
	t         *testing.T
	ws        Workspace
	binary    string
	calls     int
	raw       string
	err       error
	truncated bool
	after     func()
}

func (r *namespaceIdentityRunner) Run(_ context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	r.t.Helper()
	r.calls++
	want := []string{"--kubeconfig", r.ws.Kubeconfig, "get", "namespace", "kube-system", "-o", "json"}
	if dir != r.ws.Directory || binary != r.binary || !reflect.DeepEqual(args, want) || !reflect.DeepEqual(env, []string{"FIXTURE=identity"}) {
		r.t.Fatalf("unexpected runner invocation: dir=%s binary=%s args=%v env=%v", dir, binary, args, env)
	}
	if r.after != nil {
		r.after()
	}
	return CommandResult{Stdout: r.raw, Stderr: "SECRET stderr", StdoutTruncated: r.truncated}, r.err
}

func namespaceIdentityClient(t *testing.T, suspended bool) (*Client, *namespaceIdentityRunner) {
	t.Helper()
	root, ws := tempWorkspace(t)
	ws.Suspended = suspended
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	// List includes suspended entries so the fixture can retain the registered paths.
	resolved := registry.List()[0]
	binary := executable(t, root, "kubectl-identity")
	runner := &namespaceIdentityRunner{t: t, ws: resolved, binary: binary, raw: identityNamespaceJSON}
	client, err := NewClient(registry, runner, ClientConfig{KubeOneBinary: executable(t, root, "kubeone-identity"), KubectlBinary: binary, Environment: []string{"FIXTURE=identity"}})
	if err != nil {
		t.Fatal(err)
	}
	return client, runner
}

func TestNamespaceIdentityRegistryScopedObservation(t *testing.T) {
	client, runner := namespaceIdentityClient(t, false)
	before := time.Now().UTC()
	got, err := client.NamespaceIdentity(context.Background(), "tenant-a", "cluster-a")
	if err != nil || runner.calls != 1 || got.Tenant != "tenant-a" || got.ClusterID != "cluster-a" || got.NamespaceName != "kube-system" || got.NamespaceUID != "Opaque-UID-Aa" || got.ObservationScope != "KUBE_SYSTEM_NAMESPACE_OBJECT_ONLY" || got.ObservedAt.Before(before) || got.ObservedAt.Location() != time.UTC {
		t.Fatalf("observation=%+v err=%v calls=%d", got, err, runner.calls)
	}
}

func TestNamespaceIdentityRejectsWithoutObservation(t *testing.T) {
	for _, mode := range []string{"foreign", "missing", "suspended", "absent-config", "empty-config", "directory-config", "symlink-config", "runner-error", "malformed", "truncated", "cancel-before", "cancel-after", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			client, runner := namespaceIdentityClient(t, mode == "suspended")
			cancelCtx, cancel := context.WithCancel(context.Background())
			var ctx context.Context = cancelCtx
			defer cancel()
			tenant, id := "tenant-a", "cluster-a"
			wantCalls := 0
			switch mode {
			case "foreign":
				tenant = "tenant-b"
			case "missing":
				id = "missing"
			case "absent-config", "empty-config", "directory-config", "symlink-config":
				if err := os.Remove(runner.ws.Kubeconfig); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "empty-config":
					if err := os.WriteFile(runner.ws.Kubeconfig, nil, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory-config":
					if err := os.Mkdir(runner.ws.Kubeconfig, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink-config":
					if err := os.Symlink(runner.ws.Manifest, runner.ws.Kubeconfig); err != nil {
						t.Fatal(err)
					}
				}
			case "runner-error":
				runner.err = errors.New("SECRET path/password")
				runner.raw = "SECRET stdout"
				wantCalls = 1
			case "malformed":
				runner.raw = `{"metadata":{"uid":"SECRET"}}`
				wantCalls = 1
			case "truncated":
				runner.truncated = true
				wantCalls = 1
			case "cancel-before":
				cancel()
			case "cancel-after":
				runner.after = cancel
				wantCalls = 1
			case "nil-context":
				ctx = nil
			}
			got, err := client.NamespaceIdentity(ctx, tenant, id)
			if err == nil || got != (NamespaceIdentityObservation{}) || runner.calls != wantCalls || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), runner.ws.Directory) {
				t.Fatalf("got=%+v err=%v calls=%d", got, err, runner.calls)
			}
		})
	}
}

// This subprocess is the Go test binary, never kubectl, a shell or a provider.
func TestNamespaceIdentitySyntheticChild(t *testing.T) {
	if os.Getenv("LAYERSENTRY_NAMESPACE_IDENTITY_TEST_CHILD") != "1" {
		return
	}
	fmt.Print(identityNamespaceJSON + os.Getenv("LAYERSENTRY_NAMESPACE_IDENTITY_TEST_SUFFIX"))
	os.Exit(0)
}

func TestNamespaceIdentityExecRunnerPropagatesTruncation(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "{}"} {
		runner := ExecRunner{Timeout: 10 * time.Second, MaxOut: len(identityNamespaceJSON)}
		result, err := runner.Run(context.Background(), t.TempDir(), binary,
			[]string{"-test.run=^TestNamespaceIdentitySyntheticChild$"},
			append(os.Environ(), "LAYERSENTRY_NAMESPACE_IDENTITY_TEST_CHILD=1", "LAYERSENTRY_NAMESPACE_IDENTITY_TEST_SUFFIX="+suffix))
		if err != nil || result.Stdout != identityNamespaceJSON || result.StdoutTruncated != (suffix != "") {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	}
}

func TestNamespaceIdentityRunnerBufferDetectsOmittedTrailingBytes(t *testing.T) {
	for _, chunks := range [][]string{{identityNamespaceJSON}, {identityNamespaceJSON, "{}"}, {identityNamespaceJSON + "{}"}} {
		buf := limitedBuffer{max: len(identityNamespaceJSON)}
		for _, chunk := range chunks {
			if n, err := buf.Write([]byte(chunk)); n != len(chunk) || err != nil {
				t.Fatalf("write n=%d err=%v", n, err)
			}
		}
		wantTruncated := strings.Join(chunks, "") != identityNamespaceJSON
		if buf.String() != identityNamespaceJSON || buf.truncated != wantTruncated {
			t.Fatalf("truncated=%v want=%v", buf.truncated, wantTruncated)
		}
	}
}

func TestPortalNamespaceIdentityAuthenticatedReadOnly(t *testing.T) {
	client, runner := namespaceIdentityClient(t, false)
	portal, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(portal.Handler())
	path := "/v1/kubernetes/clusters/cluster-a/identity"
	unauth := httptest.NewRecorder()
	handler.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, path, nil))
	if unauth.Code == http.StatusOK || runner.calls != 0 {
		t.Fatal("unauthenticated identity read reached runner")
	}
	foreign := portalRequest(t, handler, http.MethodGet, path, "", "tenant-b")
	if foreign.Code != http.StatusNotFound || runner.calls != 0 {
		t.Fatalf("foreign=%d calls=%d", foreign.Code, runner.calls)
	}
	// Paths supplied by request data cannot replace registry custody.
	got := portalRequest(t, handler, http.MethodGet, path+"?workspace=/forged&kubeconfig=/forged", `{"directory":"/forged","kubeconfig":"/forged"}`, "tenant-a")
	var obs NamespaceIdentityObservation
	if json.Unmarshal(got.Body.Bytes(), &obs) != nil || got.Code != http.StatusOK || obs.NamespaceUID != "Opaque-UID-Aa" || runner.calls != 1 || got.Header().Get("Cache-Control") != "no-store" || strings.Contains(got.Body.String(), runner.ws.Kubeconfig) {
		t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
	}
	runner.err = errors.New("SECRET transport")
	runner.raw = "SECRET stdout"
	failed := portalRequest(t, handler, http.MethodGet, path, "", "tenant-a")
	if failed.Code != http.StatusServiceUnavailable || strings.Contains(failed.Body.String(), "SECRET") || strings.Contains(failed.Body.String(), runner.ws.Directory) {
		t.Fatalf("status=%d body=%s", failed.Code, failed.Body.String())
	}
	method := portalRequest(t, handler, http.MethodPost, path, "", "tenant-a")
	if method.Code != http.StatusMethodNotAllowed || runner.calls != 2 {
		t.Fatalf("mutating method=%d calls=%d", method.Code, runner.calls)
	}
}
