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

func TestGatewayAmbiguousMachineIdentityCannotUseHeaderPrivileges(t *testing.T) {
	for _, identities := range [][]string{
		{"spiffe://layersentry/node-agent/host-a", "spiffe://layersentry/node-agent/host-b"},
		{"spiffe://layersentry/node-agent/host-a", "spiffe://layersentry/gateway/controller"},
		{"spiffe://layersentry/node-agent/host-a", "spiffe://layersentry/node-agent/host-a"},
	} {
		const token = "0123456789abcdef0123456789abcdef"
		auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token, RequireVerifiedWorkloadMTLS: true})
		if err != nil {
			t.Fatal(err)
		}
		var uris []*url.URL
		for _, value := range identities {
			u, err := url.Parse(value)
			if err != nil {
				t.Fatal(err)
			}
			uris = append(uris, u)
		}
		cert := &x509.Certificate{Raw: []byte("ambiguous-certificate-test-fixture"), URIs: uris}
		reached := false
		handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }))
		req := httptest.NewRequest(http.MethodGet, "/v1/resources", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		req.Header.Set(GatewayTokenHeader, token)
		req.Header.Set(GatewayUserHeader, "test-agent")
		req.Header.Set(GatewayUIDHeader, "node-agent-host-a")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		req.Header.Set(GatewayRolesHeader, "admin,approver")
		req.Header.Set(GatewayAdminHeader, "true")
		req.Header.Set(GatewayAssuranceHeader, "2")
		req.Header.Set(GatewayStepUpAtHeader, time.Now().UTC().Format(time.RFC3339Nano))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if reached || rec.Code != http.StatusUnauthorized {
			t.Errorf("ambiguous certificate reached privileged handler: called=%t HTTP=%d", reached, rec.Code)
		}
	}
}
