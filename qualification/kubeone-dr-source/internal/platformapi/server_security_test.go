package platformapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBoundedRequestAdmissionRejectsOverload(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	handler := boundedRequestAdmission(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}), 1, 10*time.Millisecond)

	firstDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/a", nil))
		firstDone <- rec.Code
	}()
	<-entered

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/v1/b", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("overload status=%d body=%s", second.Code, second.Body.String())
	}
	close(release)
	if code := <-firstDone; code != http.StatusNoContent {
		t.Fatalf("admitted request status=%d", code)
	}
}

func TestServerRejectsUnsafeAdmissionBounds(t *testing.T) {
	app, err := NewApplication(Module{Name: "m", Prefix: "/v1/m/", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Runtime: &fakeModuleRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []ServerConfig{
		{AllowInsecureHTTP: true, MaxConcurrentRequests: 1},
		{AllowInsecureHTTP: true, MaxConcurrentRequests: 5000},
		{AllowInsecureHTTP: true, MaxHeaderBytes: 1024},
		{AllowInsecureHTTP: true, MaxHeaderBytes: 2 << 20},
		{AllowInsecureHTTP: true, AdmissionTimeout: 10 * time.Second},
	} {
		if _, err := NewServer(app, cfg); err == nil {
			t.Fatalf("unsafe server config accepted: %#v", cfg)
		}
	}
}
