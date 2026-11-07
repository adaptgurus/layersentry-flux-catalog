package platformapi

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPlatformServerRequiresTLSByDefault(t *testing.T) {
	app, err := NewApplication(testModule("dr", "/v1/dr/", &fakeModuleRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(app, ServerConfig{}); err == nil {
		t.Fatal("platform server must require TLS unless insecure HTTP is explicitly enabled")
	}
	if _, err := NewServer(app, ServerConfig{AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("explicit development HTTP should be allowed: %v", err)
	}
}

func TestPlatformServerPropagatesListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	app, err := NewApplication(testModule("dr", "/v1/dr/", &fakeModuleRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(app, ServerConfig{
		ListenAddress: listener.Addr().String(), AllowInsecureHTTP: true,
		ShutdownTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = server.Run(ctx)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "http") {
		t.Fatalf("expected listener failure to propagate, got %v", err)
	}
}

func TestPlatformServerMTLSConfigurationFailsClosed(t *testing.T) {
	app, err := NewApplication(testModule("dr", "/v1/dr/", &fakeModuleRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(app, ServerConfig{
		TLSCertFile: "server.crt", TLSKeyFile: "server.key", RequireClientCertificate: true,
	}); err == nil {
		t.Fatal("mTLS server accepted missing client CA")
	}
	if _, err := NewServer(app, ServerConfig{
		AllowInsecureHTTP: true, TLSClientCAFile: "ca.pem", RequireClientCertificate: true,
	}); err == nil {
		t.Fatal("mTLS server accepted insecure HTTP")
	}

	tlsSource := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSource.Close()
	cert := tlsSource.Certificate()
	caFile := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(app, ServerConfig{
		TLSCertFile: "server.crt", TLSKeyFile: "server.key",
		TLSClientCAFile: caFile, RequireClientCertificate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := server.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert || tlsCfg.ClientCAs == nil {
		t.Fatalf("mTLS server did not require verified client certificates: %#v", tlsCfg)
	}
	if tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("unexpected TLS minimum version %x", tlsCfg.MinVersion)
	}
}
