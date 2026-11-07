package testgateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func start(t *testing.T, s *http.Server, l net.Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Serve(tls.NewListener(l, s.TLSConfig)) }()
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(c)
		select {
		case err := <-done:
			if err != nil && err != http.ErrServerClosed {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("server did not terminate")
		}
	})
}

func listener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func fixture(t *testing.T, admin bool) (*os.Root, Config, net.Listener, net.Listener) {
	t.Helper()
	b, f := listener(t), listener(t)
	path := filepath.Join(t.TempDir(), "new-session")
	if err := Bootstrap(path, Config{TestOnly: true, Listen: f.Addr().String(), Upstream: "https://" + b.Addr().String(), User: "test-owner", UID: "new-user", Tenant: "new-tenant", Admin: admin}); err != nil {
		t.Fatal(err)
	}
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	c, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, c, b, f
}

func client(t *testing.T, root *os.Root, name string) *http.Client {
	t.Helper()
	b, err := readPrivate(root, "ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if name != "" {
		cert, err := certificate(root, name)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{TLSClientConfig: cfg, Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

func request(t *testing.T, c *http.Client, endpoint, path string, spoof bool) int {
	t.Helper()
	r, err := http.NewRequest("GET", endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spoof {
		for k, v := range map[string]string{platformapi.GatewayAdminHeader: "true", platformapi.GatewayUserHeader: "forged", platformapi.GatewayUIDHeader: "0", platformapi.GatewayTenantHeader: "foreign", platformapi.GatewayRolesHeader: "super-admin", platformapi.GatewayAssuranceHeader: "3", platformapi.GatewayStepUpAtHeader: time.Now().Format(time.RFC3339), platformapi.GatewayTokenHeader: "forged", "Authorization": "Bearer forged", "Cookie": "session=forged", "X-Forwarded-For": "foreign"} {
			r.Header.Set(k, v)
		}
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func backend(t *testing.T, root *os.Root, c Config, l net.Listener, h http.Handler) {
	t.Helper()
	cert, err := certificate(root, "backend")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := readPrivate(root, "ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	token, err := readPrivate(root, "gateway.token")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuthWithConfig(platformapi.GatewayAuthConfig{Token: string(token), RequireVerifiedWorkloadMTLS: true, AllowedGatewayCertificateSHA256: []string{c.GatewaySHA256}})
	if err != nil {
		t.Fatal(err)
	}
	start(t, &http.Server{Handler: auth.Middleware(h), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}, l)
}

func TestActualTLSGatewayIdentitySpoofRevocationAndRestart(t *testing.T) {
	root, c, b, f := fixture(t, false)
	var reached atomic.Int32
	backend(t, root, c, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		a, ok := platformapi.ActorFromContext(r.Context())
		if !ok || a.User != c.User || a.UID != c.UID || a.Tenant != c.Tenant || a.Oneadmin || len(a.Roles) != 0 || a.AssuranceLevel != 1 || !a.StepUpAt.IsZero() || a.WorkloadIdentity != "mtls-sha256:"+c.GatewaySHA256 {
			t.Error("gateway actor boundary changed")
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("untrusted credentials forwarded")
		}
		if r.URL.Path == "/v1/admin" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	s, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	start(t, s, f)
	human := client(t, root, "client")
	endpoint := "https://" + f.Addr().String()
	if got := request(t, human, endpoint, "/v1/owned", true); got != 200 {
		t.Fatalf("enrolled identity: %d", got)
	}
	if got := request(t, human, endpoint, "/v1/admin", true); got != 403 {
		t.Fatalf("spoofed admin: %d", got)
	}
	if got := request(t, client(t, root, "gateway"), endpoint, "/v1/owned", true); got != 401 {
		t.Fatalf("non-client workload promoted: %d", got)
	}
	if got := request(t, human, endpoint, "/outside", false); got != 403 {
		t.Fatalf("unadmitted route: %d", got)
	}
	if got := request(t, human, c.Upstream, "/v1/owned", true); got != 401 {
		t.Fatalf("client bypassed BFF: %d", got)
	}
	if resp, err := client(t, root, "").Get(endpoint + "/v1/owned"); err == nil {
		resp.Body.Close()
		t.Fatal("anonymous TLS admitted")
	}
	if err := Revoke(root); err != nil {
		t.Fatal(err)
	}
	if err := Revoke(root); err != nil {
		t.Fatal("revoke not idempotent", err)
	}
	if got := request(t, human, endpoint, "/v1/owned", false); got != 401 {
		t.Fatalf("same-connection revocation: %d", got)
	}
	if reached.Load() != 2 {
		t.Fatalf("unauthorized request reached backend: %d", reached.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	newListener := listener(t)
	start(t, restarted, newListener)
	if got := request(t, human, "https://"+newListener.Addr().String(), "/v1/owned", false); got != 401 {
		t.Fatalf("restart revived revoked identity: %d", got)
	}
}

func TestActualTLSGatewayAdminDoesNotForgeStepUp(t *testing.T) {
	root, c, b, f := fixture(t, true)
	backend(t, root, c, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, _ := platformapi.ActorFromContext(r.Context())
		if !a.Oneadmin || a.Tenant != c.Tenant {
			t.Error("explicit admin enrollment missing")
			w.WriteHeader(500)
			return
		}
		if a.HasFreshStepUp(time.Now(), time.Minute) {
			t.Error("test certificate was promoted to MFA")
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	s, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	start(t, s, f)
	if got := request(t, client(t, root, "client"), "https://"+f.Addr().String(), "/v1/admin", true); got != 200 {
		t.Fatalf("admin enrollment: %d", got)
	}
}

func TestActualTLSGatewayBackendPinMismatch(t *testing.T) {
	root, c, b, f := fixture(t, true)
	var reached atomic.Int32
	backend(t, root, c, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	c.UpstreamSHA256 = strings.Repeat("a", 64)
	raw, _ := json.Marshal(c)
	if err := root.WriteFile("config.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	start(t, s, f)
	if got := request(t, client(t, root, "client"), "https://"+f.Addr().String(), "/v1/admin", false); got != 502 {
		t.Fatalf("unapproved backend: %d", got)
	}
	if reached.Load() != 0 {
		t.Fatal("wrong backend received credentials")
	}
}

func TestTestGatewayBootstrapAndCustodyFailClosed(t *testing.T) {
	root, c, _, _ := fixture(t, false)
	if _, err := root.Stat("ca.key"); !os.IsNotExist(err) {
		t.Fatal("issuer private key persisted")
	}
	if err := Bootstrap(root.Name(), c); err == nil {
		t.Fatal("overwrote bootstrap")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.TestOnly = false }, func(c *Config) { c.Upstream = "http://127.0.0.1:19999" },
		func(c *Config) { c.Upstream = "https://10.254.60.72:9444" }, func(c *Config) { c.Listen = "0.0.0.0:19999" },
		func(c *Config) { c.Upstream = "https://localhost:19999" }, func(c *Config) { c.Expires = time.Now().Add(-time.Second) },
		func(c *Config) { c.Expires = time.Now().Add(5 * time.Hour) }, func(c *Config) { c.Tenant = "" },
		func(c *Config) { c.UID = "bad\r\nidentity" }, func(c *Config) { c.ClientSHA256 = c.GatewaySHA256 },
	} {
		bad := c
		mutate(&bad)
		if err := bad.validate(time.Now()); err == nil {
			t.Fatal("invalid enrollment accepted")
		}
	}
	if err := root.Chmod("config.json", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(root); err == nil {
		t.Fatal("public registry accepted")
	}
	if err := root.Chmod("config.json", 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("config.json", "retained-config.json"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("retained-config.json", "config.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(root); err == nil {
		t.Fatal("symlink registry accepted")
	}
}
