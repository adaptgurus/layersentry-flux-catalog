package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kubeone "github.com/layersentry/layersentry-platform/internal/kubeone/lifecycle"
	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestServerReadinessIsPublicButPortalRoutesRemainAuthenticated(t *testing.T) {
	portal := &kubeone.Portal{Client: &kubeone.Client{}}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := serverHandler(portal, auth)
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || ready.Body.String() != "ready\n" {
		t.Fatalf("readiness status=%d body=%q", ready.Code, ready.Body.String())
	}
	protected := httptest.NewRecorder()
	handler.ServeHTTP(protected, httptest.NewRequest(http.MethodGet, "/v1/kubernetes/clusters", nil))
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated portal status=%d", protected.Code)
	}
}
