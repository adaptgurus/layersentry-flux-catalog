package testgateway

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

// Opt-in installed-artifact test: bootstrap, serve and revoke are performed by
// the actual RPM binary, not by an in-process substitute. The backend remains
// a private TLS actor-boundary probe; this is not a provider lifecycle test.
func TestInstalledGatewayCommand(t *testing.T) {
	installedGatewayCommand(t, false)
}

func TestInstalledGatewayStepUpCommand(t *testing.T) {
	installedGatewayCommand(t, true)
}

func installedGatewayCommand(t *testing.T, withStepUp bool) {
	binary := os.Getenv("LAYERSENTRY_TEST_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("installed TEST_ONLY artifact required")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(binary) {
		t.Fatal("root-custodied absolute installed artifact required")
	}
	b, f := listener(t), listener(t)
	front := f.Addr().String()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "installed-session")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := func(args ...string) {
		t.Helper()
		if err := exec.CommandContext(ctx, binary, args...).Run(); err != nil {
			t.Fatal("installed command failed", err)
		}
	}
	args := []string{"bootstrap", "-test-only", "-root", path, "-listen", front, "-upstream", "https://" + b.Addr().String(), "-user", "installed-owner", "-uid", "installed-user", "-tenant", "isolated-tenant", "-admin"}
	var password string
	if withStepUp {
		var input string
		input, password = testPassword(t)
		args = append(args, "-step-up-password-file", input)
	}
	command(args...)
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	c, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	backend(t, root, c, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := platformapi.ActorFromContext(r.Context())
		if !ok || !a.Oneadmin || a.UID != c.UID || a.Tenant != c.Tenant {
			t.Error("installed actor mismatch")
			w.WriteHeader(500)
			return
		}
		if withStepUp && r.URL.Path == "/v1/privileged" {
			if !a.HasFreshStepUp(time.Now(), time.Minute) {
				w.WriteHeader(403)
				return
			}
		} else if a.AssuranceLevel != 1 {
			t.Error("certificate-only assurance changed")
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	serve := exec.CommandContext(ctx, binary, "serve", "-test-only", "-root", path)
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serve.Wait() }()
	defer func() {
		_ = serve.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Error("installed gateway shutdown", err)
			}
		case <-time.After(3 * time.Second):
			_ = serve.Process.Kill()
			<-done
			t.Error("installed gateway shutdown timeout")
		}
	}()
	human := client(t, root, "client")
	endpoint := "https://" + front
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := human.Get(endpoint + "/v1/admission")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("installed gateway startup status %d", resp.StatusCode)
			}
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("installed gateway readiness deadline")
	}
	if got := request(t, human, endpoint, "/v1/admission", !withStepUp); got != 200 {
		t.Fatalf("installed authenticated request %d", got)
	}
	if withStepUp {
		if got := request(t, human, endpoint, "/v1/privileged", false); got != 403 {
			t.Fatalf("installed certificate-only privilege: %d", got)
		}
		if got := passwordRequest(t, human, endpoint, c.User, "incorrect"); got != 401 {
			t.Fatalf("installed invalid knowledge factor: %d", got)
		}
		if got := passwordRequest(t, human, endpoint, c.User, password); got != 200 {
			t.Fatalf("installed two-factor verification: %d", got)
		}
	}
	command("revoke", "-test-only", "-root", path)
	if got := request(t, human, endpoint, "/v1/admission", false); got != 401 {
		t.Fatalf("installed revocation %d", got)
	}
	if withStepUp {
		if got := passwordRequest(t, human, endpoint, c.User, password); got != 401 {
			t.Fatalf("installed revoked step-up: %d", got)
		}
	}
	t.Log("INSTALLED_TEST_ONLY_GATEWAY: bootstrap -> verified TLS client -> exact backend actor -> revoke -> same-client 401; no provider credentials or native mutations")
}
