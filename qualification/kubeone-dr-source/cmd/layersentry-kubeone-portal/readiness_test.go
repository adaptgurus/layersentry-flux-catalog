package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func clearReadinessEnvironment(t *testing.T) {
	t.Helper()
	names := append([]string{}, portalTLSSettings...)
	names = append(names, "LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY", "LAYERSENTRY_KUBEONE_PORTAL_LISTEN")
	for _, suffix := range []string{"SERVER_CA_FILE", "SERVER_NAME", "CLIENT_CERT_FILE", "CLIENT_KEY_FILE", "CLIENT_KEY"} {
		names = append(names, readinessPrefix+suffix)
	}
	for _, name := range names {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadinessDiagnosticDispatchDoesNotStartPortal(t *testing.T) {
	clearReadinessEnvironment(t)
	t.Setenv("LAYERSENTRY_KUBEONE_WORKSPACE_ROOT", "/nonexistent-readiness-workspace")
	t.Setenv("LAYERSENTRY_KUBEONE_REGISTRY_FILE", "/nonexistent-readiness-registry")
	t.Setenv("LAYERSENTRY_GATEWAY_TOKEN", "")
	t.Setenv("LAYERSENTRY_KUBEONE_AUTODR_ENABLE", "true")
	t.Setenv("LAYERSENTRY_KUBEONE_AUTODR_CONTROLLER_SITE", "")
	if err := runPortalCommand([]string{"--check-readiness-config"}); err != nil {
		t.Fatalf("configuration-only command entered normal startup or failed: %v", err)
	}
	for _, args := range [][]string{{"--unknown"}, {"--check-ready", "extra"}, {"--check-readiness-config", "extra"}} {
		if err := runPortalCommand(args); err == nil {
			t.Fatal("unsupported command was accepted")
		}
	}
}

func TestReadinessEndpointSelectionAndPlaintextAdmission(t *testing.T) {
	clearReadinessEnvironment(t)
	p, err := newPortalReadinessProbe()
	if err != nil || p.endpoint != "http://127.0.0.1:9445/readyz" {
		t.Fatalf("wrong default endpoint: %v", err)
	}
	p.client.CloseIdleConnections()
	for _, addr := range []string{":9445", "0.0.0.0:9445", "portal.test:9445", "127.0.0.1:0", "127.0.0.1:not-a-port", "127.0.0.1:65536"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", addr)
			if _, err := newPortalReadinessProbe(); err == nil {
				t.Fatal("invalid plaintext profile accepted")
			}
		})
	}
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", "[::1]:19445")
	p, err = newPortalReadinessProbe()
	if err != nil || p.endpoint != "http://[::1]:19445/readyz" {
		t.Fatalf("wrong IPv6 endpoint: %v", err)
	}
	for _, name := range portalTLSSettings {
		t.Run("empty_"+name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := newPortalReadinessProbe(); err == nil {
				t.Fatal("partial TLS configuration fell back to plaintext")
			}
		})
	}
}

func TestReadinessConfiguredHTTPListenerAndRetry(t *testing.T) {
	clearReadinessEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/readyz" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected readiness request")
		}
		if requests.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	}))
	defer server.Close()
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	p, err := newPortalReadinessProbe()
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	if p.endpoint != server.URL+"/readyz" || p.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("probe ignored its configured endpoint or enabled a proxy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.wait(ctx, time.Millisecond); err != nil || requests.Load() != 3 {
		t.Fatalf("configured endpoint/retry failed: %v, requests=%d", err, requests.Load())
	}
}

type readinessFixture struct {
	caPath, serverCert, serverKey, clientCert, clientKey string
	serverPair                                           tls.Certificate
	roots                                                *x509.CertPool
}

func newReadinessFixture(t *testing.T) readinessFixture {
	t.Helper()
	return newReadinessFixtureWithSharedKey(t, false)
}

func newReadinessFixtureWithSharedKey(t *testing.T, sharedKey bool) readinessFixture {
	t.Helper()
	dir := t.TempDir()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "readiness test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	write := func(name string, body []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	result := readinessFixture{caPath: write("ca.pem", caPEM, 0644), roots: x509.NewCertPool()}
	result.roots.AppendCertsFromPEM(caPEM)
	var serverPublic ed25519.PublicKey
	var serverPrivate ed25519.PrivateKey
	for i, role := range []string{"server", "client"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if role == "server" {
			serverPublic, serverPrivate = pub, key
		} else if sharedKey {
			pub, key = serverPublic, serverPrivate
		}
		usage := x509.ExtKeyUsageClientAuth
		if role == "server" {
			usage = x509.ExtKeyUsageServerAuth
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: role},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			DNSNames: []string{"portal.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certPath := write(role+".pem", certPEM, 0644)
		keyPath := write(role+".key", keyPEM, 0640)
		if role == "server" {
			result.serverCert, result.serverKey = certPath, keyPath
			result.serverPair, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			result.clientCert, result.clientKey = certPath, keyPath
		}
	}
	return result
}

func (f readinessFixture) configure(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE":  f.serverCert,
		"LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE":   f.serverKey,
		"LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE": f.caPath,
		"LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256":    strings.Repeat("a", 64),
		readinessPrefix + "SERVER_CA_FILE":          f.caPath,
		readinessPrefix + "SERVER_NAME":             "portal.test",
		readinessPrefix + "CLIENT_CERT_FILE":        f.clientCert,
		readinessPrefix + "CLIENT_KEY_FILE":         f.clientKey,
	} {
		t.Setenv(name, value)
	}
}

func TestReadinessMutualTLS(t *testing.T) {
	clearReadinessEnvironment(t)
	f := newReadinessFixture(t)
	f.configure(t)
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.Version != tls.VersionTLS13 {
			t.Error("readiness reached HTTP without verified TLS 1.3 client identity")
		}
		requests.Add(1)
		_, _ = io.WriteString(w, "ready\n")
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverPair}, ClientCAs: f.roots, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	defer s.Close()
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", strings.TrimPrefix(s.URL, "https://"))
	p, err := newPortalReadinessProbe()
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.wait(ctx, time.Millisecond); err != nil || requests.Load() != 1 {
		t.Fatalf("verified mTLS readiness failed: %v", err)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", "0.0.0.0:"+port)
	p, err = newPortalReadinessProbe()
	if err != nil || p.endpoint != s.URL+"/readyz" {
		t.Fatalf("wildcard TLS listener did not map to loopback with verified server name: %v", err)
	}
}

func TestReadinessTLSPreflightRejectsInvalidIdentity(t *testing.T) {
	clearReadinessEnvironment(t)
	f := newReadinessFixture(t)
	foreign := newReadinessFixture(t)
	f.configure(t)
	for _, tc := range []struct{ name, setting, value string }{
		{"missing_probe_key", readinessPrefix + "CLIENT_KEY_FILE", ""},
		{"inline_key", readinessPrefix + "CLIENT_KEY", ""},
		{"wrong_server_ca", readinessPrefix + "SERVER_CA_FILE", foreign.caPath},
		{"wrong_server_name", readinessPrefix + "SERVER_NAME", "foreign.test"},
		{"untrusted_client", readinessPrefix + "CLIENT_CERT_FILE", foreign.clientCert},
		{"wrong_client_key", readinessPrefix + "CLIENT_KEY_FILE", foreign.clientKey},
		{"server_identity_as_client", readinessPrefix + "CLIENT_CERT_FILE", f.serverCert},
		{"partial_server_profile", "LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE", ""},
		{"relative_client_cert", readinessPrefix + "CLIENT_CERT_FILE", "client.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.setting, tc.value)
			if _, err := newPortalReadinessProbe(); err == nil {
				t.Fatal("invalid transport identity accepted")
			}
		})
	}
	if err := os.Chmod(f.clientKey, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := newPortalReadinessProbe(); err == nil {
		t.Fatal("world-readable client key accepted")
	}
}

func TestReadinessServerRejectsUntrustedClientAtHandshake(t *testing.T) {
	clearReadinessEnvironment(t)
	f := newReadinessFixture(t)
	foreign := newReadinessFixture(t)
	f.configure(t)
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "ready\n")
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverPair}, ClientCAs: foreign.roots, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	defer s.Close()
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", strings.TrimPrefix(s.URL, "https://"))
	p, err := newPortalReadinessProbe()
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := p.wait(ctx, 5*time.Millisecond); err == nil || requests.Load() != 0 {
		t.Fatal("untrusted client reached ready handler")
	}
}

func TestReadinessRejectsRedirectAndUnexpectedBodies(t *testing.T) {
	clearReadinessEnvironment(t)
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = io.WriteString(w, "ready\n")
	}))
	defer target.Close()
	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{"redirect", "", http.StatusFound},
		{"wrong_success_body", "different-service\n", http.StatusOK},
		{"oversized_body", strings.Repeat("x", 10000), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code == http.StatusFound {
					http.Redirect(w, r, target.URL, tc.code)
					return
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", strings.TrimPrefix(s.URL, "http://"))
			p, err := newPortalReadinessProbe()
			if err != nil {
				t.Fatal(err)
			}
			defer p.client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.wait(ctx, time.Millisecond); err == nil {
				t.Fatal("unexpected readiness response accepted")
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatal("readiness followed a redirect")
	}
}

func TestReadinessUnavailableEndpointIsCancellable(t *testing.T) {
	clearReadinessEnvironment(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", strings.TrimPrefix(s.URL, "http://"))
	p, err := newPortalReadinessProbe()
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := p.wait(ctx, time.Second); err == nil || time.Since(started) > time.Second {
		t.Fatal("readiness ignored cancellation")
	}
}

func TestReadinessScopedIPv6AndMalformedListenerPreflight(t *testing.T) {
	clearReadinessEnvironment(t)
	f := newReadinessFixture(t)
	f.configure(t)
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", "[fe80::1%eth0]:19445")
	p, err := newPortalReadinessProbe()
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, p.endpoint, nil)
	if err != nil || request.URL.Hostname() != "fe80::1%eth0" ||
		p.endpoint != "https://[fe80::1%25eth0]:19445/readyz" {
		t.Fatalf("scoped IPv6 listener lost its endpoint identity: %q: %v", p.endpoint, err)
	}
	for _, address := range []string{"user@host:9445", "host/path:9445", "host?query:9445", "host#fragment:9445", "host name:9445"} {
		t.Run(address, func(t *testing.T) {
			t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", address)
			if _, err := newPortalReadinessProbe(); err == nil {
				t.Fatal("listener with URL semantics passed preflight")
			}
		})
	}
}

func TestReadinessRejectsClientCertificateSharingServerKey(t *testing.T) {
	clearReadinessEnvironment(t)
	f := newReadinessFixtureWithSharedKey(t, true)
	f.configure(t)
	if _, err := newPortalReadinessProbe(); err == nil || !strings.Contains(err.Error(), "separate client identity") {
		t.Fatalf("valid ClientAuth certificate sharing the server key was not refused by identity guard: %v", err)
	}
}
