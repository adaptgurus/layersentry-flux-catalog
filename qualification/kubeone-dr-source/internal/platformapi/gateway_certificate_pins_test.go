package platformapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayCertificatePinConfiguration(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name  string
		pins  []string
		mtls  bool
		valid bool
	}{
		{"optional", nil, false, true},
		{"approved", []string{pin}, true, true},
		{"overlap", []string{pin, strings.Repeat("b", 64)}, true, true},
		{"requires verified transport", []string{pin}, false, false},
		{"zero", []string{strings.Repeat("0", 64)}, true, false},
		{"uppercase", []string{strings.Repeat("A", 64)}, true, false},
		{"malformed", []string{strings.Repeat("z", 64)}, true, false},
		{"truncated", []string{pin[:62]}, true, false},
		{"duplicate", []string{pin, pin}, true, false},
		{"bounded", make([]string, MaxGatewayCertificatePins+1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: "ephemeral-source-only-pin-test-token-20261007", RequireVerifiedWorkloadMTLS: tc.mtls, AllowedGatewayCertificateSHA256: tc.pins})
			if (err == nil) != tc.valid {
				t.Fatalf("configuration accepted=%v want=%v", err == nil, tc.valid)
			}
		})
	}
}

// Uses ephemeral local PKI: this is source verification, not lab certificate approval.
func TestGatewayCertificatePinsVerifiedTLSLeaves(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "ephemeral pin test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _ := issueTestCert(t, ca, caKey, 102, "server", true)
	approved, approvedDER := issueTestCert(t, ca, caKey, 103, "gateway", false)
	rotation, rotationDER := issueTestCert(t, ca, caKey, 105, "rotation", false)
	renewed, _ := issueTestCert(t, ca, caKey, 104, "gateway", false)
	sum := sha256.Sum256(approvedDER)
	pin := hex.EncodeToString(sum[:])
	rotationSum := sha256.Sum256(rotationDER)
	rotationPin := hex.EncodeToString(rotationSum[:])
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: "ephemeral-source-only-pin-test-token-20261007", RequireVerifiedWorkloadMTLS: true, AllowedGatewayCertificateSHA256: []string{pin, rotationPin}, MaxFailuresPerSource: 3})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewUnstartedServer(auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok || (actor.WorkloadIdentity != "mtls-sha256:"+pin && actor.WorkloadIdentity != "mtls-sha256:"+rotationPin) {
			t.Error("incorrect authenticated leaf identity")
		}
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		want int
	}{{"approved", approved, 204}, {"approved rotation overlap", rotation, 204}, {"renewed same subject needs approval", renewed, 401}, {"wrong pin second failure", renewed, 401}, {"wrong pin third failure blocks", renewed, 429}, {"wrong pin throttled", renewed, 429}} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{tc.cert}, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(GatewayTokenHeader, "ephemeral-source-only-pin-test-token-20261007")
			req.Header.Set(GatewayUserHeader, "tester")
			req.Header.Set(GatewayUIDHeader, "100")
			req.Header.Set(GatewayTenantHeader, "tenant-a")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", response.StatusCode, tc.want)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("unauthorized request dispatched: calls=%d", calls.Load())
	}
}
