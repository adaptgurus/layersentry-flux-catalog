package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/layersentry/layersentry-platform/internal/qualification/testgateway"
)

// Real compiled portal and first-party gateway with independently verified
// cryptographic/knowledge factors. Workspace files are private fixtures, with
// no hosts/provider credentials. No native or Kubernetes E2E claim is made.
func TestCompiledPortalEnrolledTwoFactorGateway(t *testing.T) {
	binary := os.Getenv("LAYERSENTRY_KUBEONE_PORTAL_TEST_BINARY")
	if binary == "" {
		t.Skip("explicit compiled portal binary required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("test binary must be absolute")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	listen := func() net.Listener {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	front, back := listen(), listen()
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random[:])
	factor := filepath.Join(base, "independent-factor")
	write(factor, []byte(password))
	rootPath := filepath.Join(base, "enrollment")
	c := testgateway.Config{TestOnly: true, Listen: front.Addr().String(), Upstream: "https://" + back.Addr().String(), User: "kubeone-owner", UID: "kubeone-owner-id", Tenant: "kubeone-disposable", TenantAdmin: true}
	if err := testgateway.BootstrapWithPasswordFile(rootPath, c, factor); err != nil {
		t.Fatal(err)
	}
	root, err := testgateway.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	c, tlsConfig, _, err := testgateway.OwnerBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = tlsConfig // OwnerBackend independently checks complete private enrollment.
	workspaces := filepath.Join(base, "workspaces")
	workspace := filepath.Join(workspaces, "cluster")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(workspace, "kubeone.yaml"), []byte("# private fixture: deliberately no hosts\n"))
	registry := filepath.Join(base, "registry.json")
	write(registry, []byte(`{"clusters":[{"tenant":"kubeone-disposable","cluster_id":"new-fixture","directory":"cluster","manifest":"kubeone.yaml","kubeconfig":"kubeconfig","provisionable":true,"self_service_lifecycle":true,"expected_control_planes":3,"expected_nodes":4}]}`))
	backAddress := back.Addr().String()
	back.Close()
	cmd := exec.Command(binary)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LAYERSENTRY_KUBEONE_WORKSPACE_ROOT=" + workspaces, "LAYERSENTRY_KUBEONE_REGISTRY_FILE=" + registry, "LAYERSENTRY_GATEWAY_TOKEN_FILE=" + filepath.Join(rootPath, "gateway.token"), "LAYERSENTRY_KUBEONE_PORTAL_LISTEN=" + backAddress, "LAYERSENTRY_KUBEONE_BIN=/usr/bin/false", "LAYERSENTRY_KUBECTL_BIN=/usr/bin/false", "LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE=" + filepath.Join(rootPath, "backend.pem"), "LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE=" + filepath.Join(rootPath, "backend.key"), "LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE=" + filepath.Join(rootPath, "ca.pem"), "LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256=" + c.GatewaySHA256}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("portal stop timeout")
		}
	}()
	gateway, err := testgateway.NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	frontDone := make(chan error, 1)
	go func() { frontDone <- gateway.ServeTLS(front, "", "") }()
	defer func() { gateway.Close(); <-frontDone }()
	ca, err := os.ReadFile(filepath.Join(rootPath, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("CA fixture invalid")
	}
	leaf, err := tls.LoadX509KeyPair(filepath.Join(rootPath, "client.pem"), filepath.Join(rootPath, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{leaf}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	endpoint := "https://" + front.Addr().String()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(endpoint + "/v1/kubernetes/clusters")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("enrolled gateway could not reach compiled portal over pinned mTLS")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, probe := range []struct {
		name, password string
		spoof          bool
		want           int
	}{
		{"possession-only", "", false, 403}, {"spoofed-assurance", "", true, 403}, {"wrong-knowledge", "incorrect-factor", false, 401}, {"verified-two-factors", password, false, 400},
	} {
		t.Run(probe.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", endpoint+"/v1/kubernetes/clusters/new-fixture/provision", strings.NewReader(`{"unexpected":true}`))
			if probe.password != "" {
				req.SetBasicAuth(c.User, probe.password)
			}
			if probe.spoof {
				req.Header.Set(platformapi.GatewayAdminHeader, "true")
				req.Header.Set(platformapi.GatewayAssuranceHeader, "2")
				req.Header.Set(platformapi.GatewayStepUpAtHeader, time.Now().UTC().Format(time.RFC3339Nano))
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			if err != nil || resp.StatusCode != probe.want {
				t.Fatalf("status=%d want=%d", resp.StatusCode, probe.want)
			}
			if probe.want == 400 && !strings.Contains(string(body), "empty JSON object") {
				t.Fatal("positive factors did not reach bounded lifecycle request validation")
			}
		})
	}
	// Even possession of the fixture gateway token cannot make the subscriber
	// leaf a trusted gateway leaf on the direct backend connection.
	token, err := os.ReadFile(filepath.Join(rootPath, "gateway.token"))
	if err != nil {
		t.Fatal(err)
	}
	direct, _ := http.NewRequest("GET", c.Upstream+"/v1/kubernetes/clusters", nil)
	direct.Header.Set(platformapi.GatewayTokenHeader, string(token))
	direct.Header.Set(platformapi.GatewayUserHeader, c.User)
	direct.Header.Set(platformapi.GatewayUIDHeader, c.UID)
	direct.Header.Set(platformapi.GatewayTenantHeader, c.Tenant)
	resp, err := client.Do(direct)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("direct subscriber leaf admitted: %d", resp.StatusCode)
	}
	if err := testgateway.Revoke(root); err != nil {
		t.Fatal(err)
	}
	resp, err = client.Get(endpoint + "/v1/kubernetes/clusters")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("revoked enrollment admitted")
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 1 {
		t.Fatal("denied/invalid requests produced lifecycle state")
	}
	var persisted testgateway.Config
	raw, err := os.ReadFile(filepath.Join(rootPath, "config.json"))
	if err != nil || json.Unmarshal(raw, &persisted) != nil || !persisted.TenantAdmin || persisted.Admin {
		t.Fatal("tenant enrollment changed")
	}
	t.Log("ACTUAL_PRIVATE_GATEWAY_PORTAL_TLS: registered subscriber factors, role, pin, no-privilege spoof, revoke; zero native dispatch")
}
