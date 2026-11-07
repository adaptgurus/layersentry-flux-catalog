package platformapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mtlsRuntime struct{}

func (mtlsRuntime) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (mtlsRuntime) Ready(context.Context) error             { return nil }
func (mtlsRuntime) OperationalHealth(context.Context) error { return nil }

func writePEMFile(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func issueTestCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64, cn string, server bool) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func TestPlatformServerMTLSHandshakeBindsWorkloadIdentity(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LayerSentry Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _ := issueTestCert(t, ca, caKey, 2, "layersentry-test-server", true)
	clientCert, clientDER := issueTestCert(t, ca, caKey, 3, "layersentry-test-gateway", false)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	serverCertFile := filepath.Join(dir, "server.pem")
	serverKeyFile := filepath.Join(dir, "server.key")
	writePEMFile(t, caFile, "CERTIFICATE", caDER)
	writePEMFile(t, serverCertFile, "CERTIFICATE", serverCert.Certificate[0])
	serverKey, ok := serverCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("server key is not RSA")
	}
	writePEMFile(t, serverKeyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token, RequireVerifiedWorkloadMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	identityCh := make(chan string, 1)
	module := Module{
		Name: "dr", Prefix: "/v1/dr/", Runtime: mtlsRuntime{},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, ok := ActorFromContext(r.Context())
			if !ok {
				http.Error(w, "actor missing", http.StatusInternalServerError)
				return
			}
			identityCh <- actor.WorkloadIdentity
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	app, err := NewAuthenticatedApplication(auth, module)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	server, err := NewServer(app, ServerConfig{
		ListenAddress: addr,
		TLSCertFile:   serverCertFile, TLSKeyFile: serverKeyFile,
		TLSClientCAFile: caFile, RequireClientCertificate: true,
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second,
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(ctx) }()

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	request := func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/dr/capabilities", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set(GatewayTokenHeader, token)
		req.Header.Set(GatewayUserHeader, "tester")
		req.Header.Set(GatewayUIDHeader, "100")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		return client.Do(req)
	}

	started := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
	}
	if !started {
		t.Fatal("mTLS server did not start")
	}

	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
	}}, Timeout: 2 * time.Second}
	if resp, err := request(noCertClient); err == nil {
		resp.Body.Close()
		t.Fatalf("mTLS server accepted client without certificate: status=%d", resp.StatusCode)
	}

	withCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12,
	}}, Timeout: 2 * time.Second}
	resp, err := request(withCertClient)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("mTLS authenticated request status=%d", resp.StatusCode)
	}
	sum := sha256.Sum256(clientDER)
	wantIdentity := "mtls-sha256:" + hex.EncodeToString(sum[:])
	select {
	case got := <-identityCh:
		if got != wantIdentity {
			t.Fatalf("workload identity=%q want=%q", got, wantIdentity)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated workload identity was not observed")
	}

	cancel()
	select {
	case err := <-serverErr:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("platform server did not stop")
	}
}
