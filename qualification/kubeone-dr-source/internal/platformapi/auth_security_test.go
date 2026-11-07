package platformapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatewayAuthRejectsMalformedIdentityAndRoles(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuth(token)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := auth.Middleware(next)

	base := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.Header.Set(GatewayTokenHeader, token)
		req.Header.Set(GatewayUserHeader, "tester")
		req.Header.Set(GatewayUIDHeader, "100")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		return req
	}
	tests := []struct {
		name string
		edit func(*http.Request)
	}{
		{name: "wrong token", edit: func(r *http.Request) { r.Header.Set(GatewayTokenHeader, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") }},
		{name: "missing user", edit: func(r *http.Request) { r.Header.Del(GatewayUserHeader) }},
		{name: "missing uid", edit: func(r *http.Request) { r.Header.Del(GatewayUIDHeader) }},
		{name: "newline tenant", edit: func(r *http.Request) { r.Header.Set(GatewayTenantHeader, "tenant-a\nspoof") }},
		{name: "invalid role", edit: func(r *http.Request) { r.Header.Set(GatewayRolesHeader, "viewer,admin\nspoof") }},
		{name: "invalid assurance", edit: func(r *http.Request) { r.Header.Set(GatewayAssuranceHeader, "9") }},
		{name: "aal2 missing step-up timestamp", edit: func(r *http.Request) { r.Header.Set(GatewayAssuranceHeader, "2") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.edit(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestGatewayAuthDeduplicatesRoles(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuth(token)
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok {
			t.Fatal("actor missing")
		}
		if len(actor.Roles) != 2 || actor.Roles[0] != "viewer" || actor.Roles[1] != "approver" {
			t.Fatalf("unexpected roles %#v", actor.Roles)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set(GatewayTokenHeader, token)
	req.Header.Set(GatewayUserHeader, "tester")
	req.Header.Set(GatewayUIDHeader, "100")
	req.Header.Set(GatewayTenantHeader, "tenant-a")
	req.Header.Set(GatewayRolesHeader, "viewer,approver,viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGatewayAuthFreshStepUpSemantics(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuth(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok {
			t.Fatal("actor missing")
		}
		if !actor.HasFreshStepUp(now, 5*time.Minute) {
			t.Fatalf("fresh AAL2 step-up not accepted: %#v", actor)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set(GatewayTokenHeader, token)
	req.Header.Set(GatewayUserHeader, "tester")
	req.Header.Set(GatewayUIDHeader, "100")
	req.Header.Set(GatewayTenantHeader, "tenant-a")
	req.Header.Set(GatewayAssuranceHeader, "2")
	req.Header.Set(GatewayStepUpAtHeader, now.Format(time.RFC3339Nano))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	stale := Actor{AssuranceLevel: 2, StepUpAt: now.Add(-10 * time.Minute)}
	if stale.HasFreshStepUp(now, 5*time.Minute) {
		t.Fatal("stale step-up assertion was accepted")
	}
	future := Actor{AssuranceLevel: 2, StepUpAt: now.Add(2 * time.Minute)}
	if future.HasFreshStepUp(now, 5*time.Minute) {
		t.Fatal("future step-up assertion was accepted")
	}
}

func TestGatewayAuthStrictWorkloadIdentity(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{
		Token: token, RequireVerifiedWorkloadMTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := ActorFromContext(r.Context())
		if !ok || !strings.HasPrefix(actor.WorkloadIdentity, "mtls-sha256:") {
			t.Fatalf("verified workload identity missing: %#v ok=%v", actor, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.Header.Set(GatewayTokenHeader, token)
		req.Header.Set(GatewayUserHeader, "tester")
		req.Header.Set(GatewayUIDHeader, "100")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		return req
	}

	noMTLS := httptest.NewRecorder()
	handler.ServeHTTP(noMTLS, request())
	if noMTLS.Code != http.StatusUnauthorized {
		t.Fatalf("strict gateway accepted missing workload mTLS: %d %s", noMTLS.Code, noMTLS.Body.String())
	}

	unverified := request()
	unverified.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("unverified")}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, unverified)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("strict gateway accepted unverified peer certificate: %d", rec.Code)
	}

	verified := request()
	leaf := &x509.Certificate{Raw: []byte("verified-gateway-certificate")}
	verified.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, verified)
	if ok.Code != http.StatusNoContent {
		t.Fatalf("strict gateway rejected verified workload identity: %d %s", ok.Code, ok.Body.String())
	}
}


func TestGatewayAuthTemporarilyBlocksRepeatedBadSource(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{
		Token: token, MaxFailuresPerSource: 3,
		FailureWindow: time.Minute, BlockDuration: 5 * time.Minute, MaxTrackedSources: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	auth.now = func() time.Time { return now }
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(source, presented string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.RemoteAddr = source
		req.Header.Set(GatewayTokenHeader, presented)
		req.Header.Set(GatewayUserHeader, "tester")
		req.Header.Set(GatewayUIDHeader, "100")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		return req
	}
	for attempt := 1; attempt <= 3; attempt++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, request("192.0.2.10:4000", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
		want := http.StatusUnauthorized
		if attempt == 3 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("attempt %d status=%d want=%d body=%s", attempt, rec.Code, want, rec.Body.String())
		}
	}
	blockedValid := httptest.NewRecorder()
	handler.ServeHTTP(blockedValid, request("192.0.2.10:4001", token))
	if blockedValid.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked source bypassed ban with valid credential: %d", blockedValid.Code)
	}
	other := httptest.NewRecorder()
	handler.ServeHTTP(other, request("192.0.2.11:4000", token))
	if other.Code != http.StatusNoContent {
		t.Fatalf("unrelated source inherited block: %d", other.Code)
	}
	now = now.Add(6 * time.Minute)
	recovered := httptest.NewRecorder()
	handler.ServeHTTP(recovered, request("192.0.2.10:4999", token))
	if recovered.Code != http.StatusNoContent {
		t.Fatalf("temporary source block did not expire: %d %s", recovered.Code, recovered.Body.String())
	}
}

func TestGatewayAuthFailureTrackingIsMemoryBounded(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuthWithConfig(GatewayAuthConfig{
		Token: token, MaxFailuresPerSource: 3,
		FailureWindow: time.Minute, BlockDuration: time.Minute, MaxTrackedSources: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	auth.now = func() time.Time { return now }
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 1; i <= 300; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:443", (i%250)+1)
		req.Header.Set(GatewayTokenHeader, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		req.Header.Set(GatewayUserHeader, "tester")
		req.Header.Set(GatewayUIDHeader, "100")
		req.Header.Set(GatewayTenantHeader, "tenant-a")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := len(auth.failures.states); got > 128 {
		t.Fatalf("auth failure state grew beyond bound: %d", got)
	}
}
