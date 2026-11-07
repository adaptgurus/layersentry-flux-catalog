package platformapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeModuleRuntime struct {
	readyErr error
	opErr    error
	runErr   error
	started  chan struct{}
}

func (f *fakeModuleRuntime) Ready(context.Context) error             { return f.readyErr }
func (f *fakeModuleRuntime) OperationalHealth(context.Context) error { return f.opErr }
func (f *fakeModuleRuntime) Run(ctx context.Context) error {
	if f.started != nil {
		select {
		case <-f.started:
		default:
			close(f.started)
		}
	}
	if f.runErr != nil {
		return f.runErr
	}
	<-ctx.Done()
	return ctx.Err()
}

func testModule(name, prefix string, runtime *fakeModuleRuntime) Module {
	return Module{
		Name: name, Prefix: prefix, Runtime: runtime,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(name + ":" + r.URL.Path))
		}),
	}
}

func TestApplicationMountsModulesOnOneHandler(t *testing.T) {
	app, err := NewApplication(testModule("dr", "/v1/dr/", &fakeModuleRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/dr/capabilities", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "dr:/v1/dr/capabilities" {
		t.Fatalf("module routing failed: code=%d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("shared security headers missing: %v", w.Header())
	}
}

func TestApplicationRejectsDuplicateModuleOrPrefix(t *testing.T) {
	runtime := &fakeModuleRuntime{}
	if _, err := NewApplication(testModule("dr", "/v1/dr/", runtime), testModule("dr", "/v1/other/", runtime)); err == nil {
		t.Fatal("duplicate module name must fail")
	}
	if _, err := NewApplication(testModule("dr", "/v1/dr/", runtime), testModule("other", "/v1/dr/", runtime)); err == nil {
		t.Fatal("duplicate module prefix must fail")
	}
}

func TestApplicationAggregatesReadinessAndOperationalHealth(t *testing.T) {
	app, err := NewApplication(
		testModule("dr", "/v1/dr/", &fakeModuleRuntime{}),
		testModule("migration", "/v1/migration/", &fakeModuleRuntime{opErr: errors.New("audit degraded")}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ready := httptest.NewRecorder()
	app.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready should remain healthy when only operational health is degraded: %d %s", ready.Code, ready.Body.String())
	}
	operational := httptest.NewRecorder()
	app.Handler().ServeHTTP(operational, httptest.NewRequest(http.MethodGet, "/health/operational", nil))
	if operational.Code != http.StatusServiceUnavailable || !strings.Contains(operational.Body.String(), "degraded") {
		t.Fatalf("expected degraded operational health: %d %s", operational.Code, operational.Body.String())
	}
}

func TestApplicationRunPropagatesModuleFailureAndCancelsPeers(t *testing.T) {
	drStarted := make(chan struct{})
	app, err := NewApplication(
		testModule("dr", "/v1/dr/", &fakeModuleRuntime{started: drStarted}),
		testModule("bad", "/v1/bad/", &fakeModuleRuntime{runErr: errors.New("boom")}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = app.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "bad") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("module failure not propagated: %v", err)
	}
}

func TestApplicationRunStopsOnParentCancellation(t *testing.T) {
	app, err := NewApplication(testModule("dr", "/v1/dr/", &fakeModuleRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := app.Run(ctx); err != nil {
		t.Fatalf("normal application cancellation should be clean, got %v", err)
	}
}

func TestAuthenticatedApplicationUsesOneSharedGatewayBoundary(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	auth, err := NewGatewayAuth(token)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeModuleRuntime{}
	module := Module{
		Name: "dr", Prefix: "/v1/dr/", Runtime: runtime,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, ok := ActorFromContext(r.Context())
			if !ok || actor.User != "tester" || !actor.Oneadmin {
				t.Fatalf("shared application actor missing: %+v ok=%v", actor, ok)
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	app, err := NewAuthenticatedApplication(auth, module)
	if err != nil {
		t.Fatal(err)
	}

	live := httptest.NewRecorder()
	app.Handler().ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("health endpoint should not require gateway auth: %d", live.Code)
	}

	unauthorized := httptest.NewRecorder()
	app.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/dr/capabilities", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("module route bypassed shared auth: %d", unauthorized.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/dr/capabilities", nil)
	req.Header.Set(GatewayTokenHeader, token)
	req.Header.Set(GatewayUserHeader, "tester")
	req.Header.Set(GatewayUIDHeader, "0")
	req.Header.Set(GatewayAdminHeader, "true")
	authorized := httptest.NewRecorder()
	app.Handler().ServeHTTP(authorized, req)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authenticated module route failed: %d body=%s", authorized.Code, authorized.Body.String())
	}

	inventory := httptest.NewRecorder()
	app.Handler().ServeHTTP(inventory, httptest.NewRequest(http.MethodGet, "/v1/modules", nil))
	if inventory.Code != http.StatusUnauthorized {
		t.Fatalf("module inventory must share gateway auth: %d", inventory.Code)
	}
}

func TestGatewayAuthRejectsWeakToken(t *testing.T) {
	if _, err := NewGatewayAuth("short"); err == nil {
		t.Fatal("weak gateway token must be rejected")
	}
}
