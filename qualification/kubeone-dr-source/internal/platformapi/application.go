package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type ModuleRuntime interface {
	Run(context.Context) error
	Ready(context.Context) error
	OperationalHealth(context.Context) error
}

type Module struct {
	Name    string
	Prefix  string
	Handler http.Handler
	Runtime ModuleRuntime
}

type Application struct {
	handler http.Handler
	modules []Module
	byName  map[string]Module
}

type moduleState struct {
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	Ready       bool   `json:"ready"`
	Operational bool   `json:"operational"`
}

func NewApplication(modules ...Module) (*Application, error) {
	return newApplication(nil, modules...)
}

func NewAuthenticatedApplication(auth *GatewayAuth, modules ...Module) (*Application, error) {
	if auth == nil {
		return nil, errors.New("LayerSentry authenticated application requires gateway auth")
	}
	return newApplication(auth, modules...)
}

func newApplication(auth *GatewayAuth, modules ...Module) (*Application, error) {
	mux := http.NewServeMux()
	app := &Application{modules: append([]Module(nil), modules...), byName: map[string]Module{}}
	prefixes := map[string]bool{}
	for i := range app.modules {
		module := app.modules[i]
		module.Name = strings.TrimSpace(module.Name)
		module.Prefix = strings.TrimSpace(module.Prefix)
		if module.Name == "" || module.Handler == nil || module.Runtime == nil {
			return nil, errors.New("LayerSentry application module requires name, handler and runtime")
		}
		rootControlPlane := module.Name == "controlplane" && module.Prefix == "/v1/"
		if !rootControlPlane && (!strings.HasPrefix(module.Prefix, "/v1/") || !strings.HasSuffix(module.Prefix, "/") || module.Prefix == "/v1/") {
			return nil, fmt.Errorf("module %s prefix must use /v1/<module>/ form", module.Name)
		}
		if _, exists := app.byName[module.Name]; exists || prefixes[module.Prefix] {
			return nil, fmt.Errorf("duplicate LayerSentry application module %s or prefix %s", module.Name, module.Prefix)
		}
		app.modules[i] = module
		app.byName[module.Name] = module
		prefixes[module.Prefix] = true
		handler := module.Handler
		if auth != nil {
			handler = auth.Middleware(handler)
		}
		mux.Handle(module.Prefix, handler)
	}
	sort.Slice(app.modules, func(i, j int) bool { return app.modules[i].Name < app.modules[j].Name })
	mux.HandleFunc("GET /health/live", app.live)
	mux.HandleFunc("GET /health/ready", app.ready)
	mux.HandleFunc("GET /health/operational", app.operational)
	inventory := http.Handler(http.HandlerFunc(app.moduleInventory))
	if auth != nil {
		inventory = auth.Middleware(inventory)
	}
	mux.Handle("GET /v1/modules", inventory)
	app.handler = securityHeaders(mux)
	return app, nil
}

func (a *Application) Handler() http.Handler { return a.handler }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *Application) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "live"})
}

func (a *Application) states(ctx context.Context) []moduleState {
	states := make([]moduleState, 0, len(a.modules))
	for _, module := range a.modules {
		ready := module.Runtime.Ready(ctx) == nil
		operational := ready && module.Runtime.OperationalHealth(ctx) == nil
		states = append(states, moduleState{Name: module.Name, Prefix: module.Prefix, Ready: ready, Operational: operational})
	}
	return states
}

func (a *Application) ready(w http.ResponseWriter, r *http.Request) {
	states := a.states(r.Context())
	for _, state := range states {
		if !state.Ready {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "modules": states})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "modules": states})
}

func (a *Application) operational(w http.ResponseWriter, r *http.Request) {
	states := a.states(r.Context())
	for _, state := range states {
		if !state.Operational {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "modules": states})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "operational", "modules": states})
}

func (a *Application) moduleInventory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"modules": a.states(r.Context())})
}

func (a *Application) Run(ctx context.Context) error {
	if len(a.modules) == 0 {
		<-ctx.Done()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(a.modules))
	var wg sync.WaitGroup
	for _, module := range a.modules {
		module := module
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- result{name: module.Name, err: module.Runtime.Run(runCtx)}
		}()
	}
	select {
	case <-ctx.Done():
		cancel()
		wg.Wait()
		return nil
	case result := <-results:
		cancel()
		wg.Wait()
		if ctx.Err() != nil && errors.Is(result.err, context.Canceled) {
			return nil
		}
		if result.err == nil || errors.Is(result.err, context.Canceled) {
			return fmt.Errorf("LayerSentry module %s exited unexpectedly", result.name)
		}
		return fmt.Errorf("LayerSentry module %s failed: %w", result.name, result.err)
	}
}
