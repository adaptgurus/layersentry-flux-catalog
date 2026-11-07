package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

// This is a real compiled portal process with an isolated fixture, NOT a live
// customer gateway session, Kubernetes cluster or native VM qualification.
func TestCompiledPortalSuspendedWorkspace(t *testing.T) {
	binary := os.Getenv("LAYERSENTRY_KUBEONE_PORTAL_TEST_BINARY")
	if binary == "" {
		t.Skip("explicit compiled portal binary required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("test binary must be absolute")
	}
	root := t.TempDir()
	workspace := filepath.Join(root, "fixture")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"kubeone.yaml":                "# Isolated suspended fixture; deliberately contains no hosts.\n",
		".layersentry-provision.json": `{"status":"UNKNOWN","evidence_label":"UNKNOWN"}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(workspace, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	registry := filepath.Join(root, "registry.json")
	if err := os.WriteFile(registry, []byte(`{"clusters":[{"tenant":"isolated-fixture","cluster_id":"suspended-fixture","directory":"fixture","manifest":"kubeone.yaml","kubeconfig":"kubeconfig","suspended":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(random[:])
	for attempt := 0; attempt < 2; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		cmd := exec.Command(binary)
		// No inherited active service credentials, proxies, or native environment.
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LAYERSENTRY_KUBEONE_WORKSPACE_ROOT=" + root,
			"LAYERSENTRY_KUBEONE_REGISTRY_FILE=" + registry, "LAYERSENTRY_GATEWAY_TOKEN=" + token,
			"LAYERSENTRY_KUBEONE_PORTAL_LISTEN=" + address, "LAYERSENTRY_KUBEONE_BIN=/usr/bin/false", "LAYERSENTRY_KUBECTL_BIN=/usr/bin/false"}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		func() {
			defer func() {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("portal process exit: %v", err)
					}
				case <-time.After(5 * time.Second):
					_ = cmd.Process.Kill()
					<-done
					t.Error("portal shutdown timed out")
				}
			}()
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(5 * time.Second)
			for {
				resp, err := client.Get("http://" + address + "/readyz")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("isolated portal did not become ready")
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, probe := range []struct {
				method, path, tenant string
				auth                 bool
				code                 int
			}{
				{"GET", "/v1/kubernetes/clusters", "", false, 401},
				{"GET", "/v1/kubernetes/clusters", "isolated-fixture", true, 200},
				{"GET", "/v1/kubernetes/clusters", "foreign-fixture", true, 200},
				{"POST", "/v1/kubernetes/clusters/suspended-fixture/provision", "isolated-fixture", true, 404},
				{"GET", "/v1/kubernetes/clusters/suspended-fixture/kubeconfig", "isolated-fixture", true, 404},
			} {
				req, err := http.NewRequest(probe.method, "http://"+address+probe.path, strings.NewReader(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				if probe.auth {
					req.Header.Set(platformapi.GatewayTokenHeader, token)
					req.Header.Set(platformapi.GatewayUserHeader, "isolated-fixture")
					req.Header.Set(platformapi.GatewayUIDHeader, "fixture-admin")
					req.Header.Set(platformapi.GatewayTenantHeader, probe.tenant)
					req.Header.Set(platformapi.GatewayAdminHeader, "true")
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				if err != nil || resp.StatusCode != probe.code {
					t.Fatalf("%s %s status=%d expected=%d readError=%v", probe.method, probe.path, resp.StatusCode, probe.code, err)
				}
				if probe.auth && probe.path == "/v1/kubernetes/clusters" {
					var result struct {
						Clusters []struct{ Suspended, Provisionable, Provisioned bool }
					}
					if err := json.Unmarshal(body, &result); err != nil {
						t.Fatal(err)
					}
					if probe.tenant == "foreign-fixture" {
						if len(result.Clusters) != 0 {
							t.Fatal("cross-tenant leak")
						}
					} else if len(result.Clusters) != 1 || !result.Clusters[0].Suspended || result.Clusters[0].Provisionable || result.Clusters[0].Provisioned {
						t.Fatal("incorrect suspended inventory")
					}
				}
			}
		}()
	}
	for name, original := range files {
		value, err := os.ReadFile(filepath.Join(workspace, name))
		if err != nil || string(value) != original {
			t.Fatalf("workspace %s changed: %v", name, err)
		}
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != len(files) {
		t.Fatalf("workspace files changed: %v", err)
	}
}
