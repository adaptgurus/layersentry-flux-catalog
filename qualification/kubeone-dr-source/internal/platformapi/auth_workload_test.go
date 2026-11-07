package platformapi

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestVerifiedWorkloadIdentityCarriesSingleSPIFFEURI(t *testing.T) {
	u, err := url.Parse("spiffe://layersentry/node-agent/rocky-02")
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{Raw: []byte("leaf-cert"), URIs: []*url.URL{u}}
	r := &http.Request{TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	fingerprint, workloadURI := verifiedWorkloadIdentity(r)
	if fingerprint == "" || workloadURI != u.String() {
		t.Fatalf("unexpected verified identity fingerprint=%q uri=%q", fingerprint, workloadURI)
	}
}

func TestVerifiedWorkloadIdentityRejectsAmbiguousSPIFFEURI(t *testing.T) {
	one, _ := url.Parse("spiffe://layersentry/node-agent/rocky-02")
	two, _ := url.Parse("spiffe://layersentry/node-agent/rocky-03")
	leaf := &x509.Certificate{Raw: []byte("leaf-cert"), URIs: []*url.URL{one, two}}
	r := &http.Request{TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	fingerprint, workloadURI := verifiedWorkloadIdentity(r)
	if fingerprint == "" || workloadURI != "" {
		t.Fatalf("ambiguous SPIFFE identity must fail closed fingerprint=%q uri=%q", fingerprint, workloadURI)
	}
}

func TestVerifiedMachineAgentDoesNotRequireSharedGatewayToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token, RequireVerifiedWorkloadMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://layersentry/node-agent/dc3")
	leaf := &x509.Certificate{Raw: []byte("node-agent-cert"), URIs: []*url.URL{u}}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok {
			t.Fatal("actor missing")
		}
		if len(actor.Roles) != 1 || actor.Roles[0] != "node-agent" || actor.Oneadmin || actor.AssuranceLevel != 1 {
			t.Fatalf("unexpected machine actor: %#v", actor)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/autopilot/telemetry", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	req.Header.Set(GatewayUserHeader, "LayerSentry Node Agent")
	req.Header.Set(GatewayUIDHeader, "node-agent-dc3")
	req.Header.Set(GatewayTenantHeader, "platform")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNonMachineGatewayStillRequiresSharedToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token, RequireVerifiedWorkloadMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://layersentry/gateway/controller")
	leaf := &x509.Certificate{Raw: []byte("gateway-cert"), URIs: []*url.URL{u}}
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	req.Header.Set(GatewayUserHeader, "gateway")
	req.Header.Set(GatewayUIDHeader, "gateway-1")
	req.Header.Set(GatewayTenantHeader, "platform")
	rec := httptest.NewRecorder()
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-machine gateway without bearer token status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMachineAgentCannotSelfElevateHeaders(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token, RequireVerifiedWorkloadMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://layersentry/workload-agent/tenanthash/resourcehash")
	leaf := &x509.Certificate{Raw: []byte("workload-agent-cert"), URIs: []*url.URL{u}}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok {
			t.Fatal("actor missing")
		}
		if actor.Oneadmin || actor.AssuranceLevel != 1 || len(actor.Roles) != 1 || actor.Roles[0] != "workload-agent" {
			t.Fatalf("machine agent retained caller-controlled privilege: %#v", actor)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	req.Header.Set(GatewayTokenHeader, token)
	req.Header.Set(GatewayUserHeader, "malicious-agent")
	req.Header.Set(GatewayUIDHeader, "workload-agent-test")
	req.Header.Set(GatewayTenantHeader, "tenant-a")
	req.Header.Set(GatewayRolesHeader, "admin,approver,node-agent")
	req.Header.Set(GatewayAdminHeader, "true")
	req.Header.Set(GatewayAssuranceHeader, "2")
	req.Header.Set(GatewayStepUpAtHeader, time.Now().UTC().Format(time.RFC3339Nano))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
