package testgateway

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func testPassword(t *testing.T) (string, string) {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(raw[:])
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "password")
	if err := os.WriteFile(path, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	return path, password
}

func passwordRequest(t *testing.T, client *http.Client, endpoint, user, password string) int {
	t.Helper()
	r, err := http.NewRequest("GET", endpoint+"/v1/privileged", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.SetBasicAuth(user, password)
	r.Header.Set(platformapi.GatewayAssuranceHeader, "3")
	r.Header.Set(platformapi.GatewayStepUpAtHeader, "1999-01-01T00:00:00Z")
	r.Header.Set(platformapi.GatewayUIDHeader, "foreign")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal("password request transport failed")
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestRealTLSCertificateAndPasswordStepUp(t *testing.T) {
	b, f := listener(t), listener(t)
	path := filepath.Join(t.TempDir(), "session")
	passwordFile, password := testPassword(t)
	cfg := Config{TestOnly: true, Listen: f.Addr().String(), Upstream: "https://" + b.Addr().String(), User: "new-admin", UID: "new-uid", Tenant: "new-test-tenant", Admin: true}
	if err := BootstrapWithPasswordFile(path, cfg, passwordFile); err != nil {
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
	config, err := readPrivate(root, "config.json")
	if err != nil || strings.Contains(string(config), password) {
		t.Fatal("plaintext password persisted")
	}
	var accepted atomic.Int32
	backend(t, root, c, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := platformapi.ActorFromContext(r.Context())
		if !ok || a.User != c.User || a.UID != c.UID || a.Tenant != c.Tenant || !a.Oneadmin || r.Header.Get("Authorization") != "" {
			t.Error("subscriber or credential boundary violated")
			w.WriteHeader(500)
			return
		}
		if !a.HasFreshStepUp(time.Now(), time.Minute) {
			w.WriteHeader(403)
			return
		}
		if a.AssuranceLevel != 2 {
			t.Error("unexpected assurance")
		}
		accepted.Add(1)
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
		t.Fatalf("certificate alone: %d", got)
	}
	if got := request(t, customer, endpoint, "/v1/privileged", true); got != 401 {
		t.Fatalf("forged assurance: %d", got)
	}
	if got := passwordRequest(t, customer, endpoint, c.User, strings.Repeat("x", 64)); got != 401 {
		t.Fatalf("wrong password: %d", got)
	}
	if got := passwordRequest(t, customer, endpoint, "foreign", password); got != 401 {
		t.Fatalf("wrong subscriber: %d", got)
	}
	if got := passwordRequest(t, client(t, root, "gateway"), endpoint, c.User, password); got != 401 {
		t.Fatalf("gateway credential promoted: %d", got)
	}
	if got := passwordRequest(t, customer, endpoint, c.User, password); got != 200 {
		t.Fatalf("two factors rejected: %d", got)
	}
	if got := passwordRequest(t, customer, c.Upstream, c.User, password); got != 401 {
		t.Fatalf("direct backend bypass: %d", got)
	}
	if accepted.Load() != 1 {
		t.Fatalf("unexpected privileged requests: %d", accepted.Load())
	}
	if err := Revoke(root); err != nil {
		t.Fatal(err)
	}
	if got := passwordRequest(t, customer, endpoint, c.User, password); got != 401 {
		t.Fatalf("revoked two factors: %d", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	l := listener(t)
	start(t, restarted, l)
	if got := passwordRequest(t, customer, "https://"+l.Addr().String(), c.User, password); got != 401 {
		t.Fatalf("restart revived enrollment: %d", got)
	}
}

func TestStepUpBudgetConcurrentAndDurable(t *testing.T) {
	root, _, _, _ := fixture(t, true)
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < stepUpAttempts+8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reserveStepUpAttempt(root) == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != stepUpAttempts {
		t.Fatalf("budget reservations=%d", got)
	}
	if _, err := root.Stat("revoked"); err != nil {
		t.Fatal("exhausted enrollment was not revoked")
	}
	reopened, err := Open(root.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reserveStepUpAttempt(reopened); err == nil {
		t.Fatal("reopen reset attempt budget")
	}
}

func TestStepUpEnrollmentCustodyAndValidation(t *testing.T) {
	for _, kind := range []string{"weak", "mode", "symlink", "inside-root"} {
		t.Run(kind, func(t *testing.T) {
			passwordFile, _ := testPassword(t)
			path := filepath.Join(t.TempDir(), "new-session")
			switch kind {
			case "weak":
				if err := os.WriteFile(passwordFile, []byte("weak"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(passwordFile, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(filepath.Dir(passwordFile), "link")
				if err := os.Symlink(passwordFile, link); err != nil {
					t.Fatal(err)
				}
				passwordFile = link
			case "inside-root":
				passwordFile = filepath.Join(path, "password")
			}
			if err := BootstrapWithPasswordFile(path, Config{TestOnly: true}, passwordFile); err == nil {
				t.Fatal("unsafe enrollment accepted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("unsafe enrollment created a root")
			}
		})
	}
	for _, v := range []*StepUpVerifier{{Scheme: "weakened"}, {Scheme: passwordScheme, Salt: strings.Repeat("1", 64), Digest: "invalid"}, {Scheme: passwordScheme, Salt: strings.Repeat("0", 64), Digest: strings.Repeat("1", 64)}} {
		if v.validate() == nil {
			t.Fatal("malformed verifier accepted")
		}
	}
}
