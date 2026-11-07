package testgateway

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestTenantAdministratorBoundary(t *testing.T) {
	b, f := listener(t), listener(t)
	path := filepath.Join(t.TempDir(), "tenant-session")
	input, password := testPassword(t)
	cfg := Config{TestOnly: true, Listen: f.Addr().String(), Upstream: "https://" + b.Addr().String(), User: "tenant-owner", UID: "tenant-owner-id", Tenant: "dedicated-lab", TenantAdmin: true}
	if err := Bootstrap(path, cfg); err == nil {
		t.Fatal("tenant admin without two factors admitted")
	}
	cfg.Admin = true
	if err := BootstrapWithPasswordFile(path, cfg, input); err == nil {
		t.Fatal("tenant admin with super-admin admitted")
	}
	cfg.Admin = false
	if err := BootstrapWithPasswordFile(path, cfg, input); err != nil {
		t.Fatal(err)
	}
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
		if !ok || a.Oneadmin || a.Tenant != c.Tenant || a.UID != c.UID || len(a.Roles) != 1 || a.Roles[0] != "admin" {
			t.Error("tenant actor boundary violated")
			w.WriteHeader(500)
			return
		}
		if !a.HasFreshStepUp(time.Now(), time.Minute) {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	s, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	start(t, s, f)
	endpoint := "https://" + f.Addr().String()
	customer := client(t, root, "client")
	if got := request(t, customer, endpoint, "/v1/privileged", false); got != 403 {
		t.Fatalf("certificate only: %d", got)
	}
	if got := passwordRequest(t, customer, endpoint, c.User, password); got != 200 {
		t.Fatalf("two factors: %d", got)
	}
	if err := Revoke(root); err != nil {
		t.Fatal(err)
	}
	if got := passwordRequest(t, customer, endpoint, c.User, password); got != 401 {
		t.Fatalf("revocation: %d", got)
	}
	// Reopening configuration must retain the scoped role and permanent revocation.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := load(reopened)
	if err != nil || !persisted.TenantAdmin || persisted.Admin {
		t.Fatal("role persistence failed")
	}
	if _, err := reopened.Lstat("revoked"); err != nil {
		t.Fatal("revocation persistence failed")
	}
}
