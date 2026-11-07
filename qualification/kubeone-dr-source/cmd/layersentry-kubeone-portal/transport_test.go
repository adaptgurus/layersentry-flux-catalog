package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/layersentry/layersentry-platform/internal/qualification/testgateway"
)

func TestPortalTransportFailsClosed(t *testing.T) {
	names := []string{"LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE", "LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE", "LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE", "LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256", "LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY"}
	for _, name := range names {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{":9445", "0.0.0.0:9445", "dc2:9445", "10.254.60.72:9445"} {
		if _, _, err := portalTransport(address, strings.Repeat("g", 32)); err == nil {
			t.Fatalf("plaintext nonloopback accepted: %s", address)
		}
	}
	if cfg, auth, err := portalTransport("127.0.0.1:9445", strings.Repeat("g", 32)); err != nil || cfg != nil || auth == nil {
		t.Fatal("legacy loopback failed")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, _, err := portalTransport("127.0.0.1:9445", strings.Repeat("g", 32)); err == nil {
				t.Fatal("explicit empty/partial TLS setting fell back")
			}
		})
	}
}

func TestPortalTransportPinnedTLSAndKeyCustody(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(base, "enrollment")
	config := testgateway.Config{TestOnly: true, Listen: "127.0.0.1:19443", Upstream: "https://127.0.0.1:19444", User: "fixture", UID: "fixture-id", Tenant: "fixture-tenant", TenantAdmin: true}
	factor := filepath.Join(base, "factor")
	if err := os.WriteFile(factor, []byte(strings.Repeat("fixture-factor-", 3)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := testgateway.BootstrapWithPasswordFile(rootPath, config, factor); err != nil {
		t.Fatal(err)
	}
	root, err := testgateway.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	config, _, _, err = testgateway.OwnerBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY", "")
	if err := os.Unsetenv("LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY"); err != nil {
		t.Fatal(err)
	}
	settings := map[string]string{
		"LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE":  filepath.Join(rootPath, "backend.pem"),
		"LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE":   filepath.Join(rootPath, "backend.key"),
		"LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE": filepath.Join(rootPath, "ca.pem"),
		"LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256":    config.GatewaySHA256,
	}
	for k, v := range settings {
		t.Setenv(k, v)
	}
	cfg, auth, err := portalTransport("0.0.0.0:19444", strings.Repeat("g", 32))
	if err != nil || auth == nil || cfg == nil || cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("complete pinned mTLS configuration rejected or weakened")
	}
	for _, probe := range []struct{ name, setting, value string }{
		{"bad-pin", "LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256", "invalid"},
		{"relative-cert", "LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE", "backend.pem"},
		{"missing-cert", "LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE", filepath.Join(base, "absent.pem")},
		{"non-ca", "LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE", factor},
		{"wrong-key", "LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE", filepath.Join(rootPath, "client.key")},
	} {
		t.Run(probe.name, func(t *testing.T) {
			t.Setenv(probe.setting, probe.value)
			if _, _, err := portalTransport("127.0.0.1:19444", strings.Repeat("g", 32)); err == nil {
				t.Fatal("invalid TLS configuration accepted")
			}
		})
	}
	key := settings["LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE"]
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := portalTransport("127.0.0.1:19444", strings.Repeat("g", 32)); err == nil {
		t.Fatal("publicly readable private key accepted")
	}
}
