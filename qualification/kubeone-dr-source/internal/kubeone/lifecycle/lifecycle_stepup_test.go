package lifecycle

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestLifecycleRequiresFreshStepUp(t *testing.T) {
	for _, tc := range []struct {
		name, role, assurance            string
		at                               time.Time
		providerAdmin, selfService, want bool
	}{
		{name: "certificate-only-provider-admin", providerAdmin: true},
		{name: "certificate-only-tenant-admin", role: "admin", selfService: true},
		{name: "stale-provider-admin", assurance: "2", at: time.Now().Add(-6 * time.Minute), providerAdmin: true},
		{name: "future-provider-admin", assurance: "2", at: time.Now().Add(time.Minute), providerAdmin: true},
		{name: "fresh-viewer", role: "viewer", assurance: "2", at: time.Now(), selfService: true},
		{name: "fresh-admin-without-self-service", role: "admin", assurance: "2", at: time.Now()},
		{name: "fresh-tenant-admin", role: "admin", assurance: "2", at: time.Now(), selfService: true, want: true},
		{name: "fresh-provider-admin", assurance: "2", at: time.Now(), providerAdmin: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
			if err != nil {
				t.Fatal(err)
			}
			called := false
			h := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if got := lifecycleAuthorized(r, Workspace{Tenant: "tenant-a", SelfServiceLifecycle: tc.selfService}); got != tc.want {
					t.Errorf("admitted=%v want=%v", got, tc.want)
				}
			}))
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
			r.Header.Set(platformapi.GatewayUserHeader, "test-user")
			r.Header.Set(platformapi.GatewayUIDHeader, "test-uid")
			r.Header.Set(platformapi.GatewayTenantHeader, "tenant-a")
			r.Header.Set(platformapi.GatewayRolesHeader, tc.role)
			if tc.providerAdmin {
				r.Header.Set(platformapi.GatewayAdminHeader, "true")
			}
			if tc.assurance != "" {
				r.Header.Set(platformapi.GatewayAssuranceHeader, tc.assurance)
				r.Header.Set(platformapi.GatewayStepUpAtHeader, tc.at.UTC().Format(time.RFC3339Nano))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if !called {
				t.Fatalf("fixture did not reach lifecycle boundary: %d", w.Code)
			}
		})
	}
}
