package lifecycle

// All Helm commands execute only the disposable fixture below. Kubernetes
// readbacks use portalRunner; no Helm binary, Kubernetes API or native VM is used.
import (
	"context"
	"encoding/json"
	"fmt"
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

func applicationInventoryFixture(t *testing.T, inventory string) (*Portal, Workspace, http.Handler, string) {
	t.Helper()
	root, ws := tempWorkspace(t)
	ws.ExpectedNodes = 4
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(registry, &portalRunner{namespaceRunner: namespaceRunner{t: t}}, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone-fixture"), KubectlBinary: executable(t, root, "kubectl-fixture"), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "release-inventory.json")
	if err := os.WriteFile(data, []byte(inventory), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "mutation-called")
	helm := filepath.Join(root, "helm-fixture")
	script := "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then cat \"" + data + "\"; exit 0; fi\necho mutation > \"" + marker + "\"\nexit 0\n"
	if err := os.WriteFile(helm, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := portal.ConfigureApplications([]ApplicationProfile{{ID: "test-app", Label: "Test application", Category: "testing", RepositoryURL: "https://charts.invalid/", Chart: "test-chart", Version: "1.2.0", ReleaseName: "test-release", Namespace: "owned-ns"}}, helm); err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(ws.Tenant, ws.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	// Match the existing portal request helpers' fixture-only token.
	auth, err := platformapi.NewGatewayAuth("gggggggggggggggggggggggggggggggg")
	if err != nil {
		t.Fatal(err)
	}
	return portal, resolved, auth.Middleware(portal.Handler()), marker
}

const exactApplicationInventory = `[{"name":"test-release","namespace":"owned-ns","status":"deployed","revision":"1","chart":"test-chart-1.2.0"}]`

func TestApplicationInventoryMalformedOrTruncatedIsUnavailable(t *testing.T) {
	var many []map[string]string
	for i := 0; i < maxHelmInventoryReleases; i++ {
		many = append(many, map[string]string{"name": fmt.Sprintf("release-%d", i), "namespace": "owned-ns", "status": "deployed", "revision": "1", "chart": "test-chart-1.2.0"})
	}
	truncated, _ := json.Marshal(many)
	for name, rows := range map[string]string{
		"duplicate-exact-key": exactApplicationInventory[:len(exactApplicationInventory)-1] + "," + exactApplicationInventory[1:],
		"duplicate-field":     strings.Replace(exactApplicationInventory, `"namespace":`, `"namespace":"foreign-ns","namespace":`, 1),
		"alias-field":         strings.Replace(exactApplicationInventory, `"namespace":`, `"Namespace":`, 1),
		"missing-revision":    strings.Replace(exactApplicationInventory, `"revision":"1",`, "", 1),
		"wrong-revision-type": strings.Replace(exactApplicationInventory, `"revision":"1"`, `"revision":1`, 1),
		"null":                `null`, "truncated-limit": string(truncated), "output-bound": `[` + strings.Repeat(" ", maxHelmInventoryBytes) + `]`,
		"invalid-document": exactApplicationInventory + `{}`, "malformed-status": strings.Replace(exactApplicationInventory, `deployed`, `unrecognized`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, handler, marker := applicationInventoryFixture(t, rows)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				path := "/v1/kubernetes/clusters/cluster-a/applications"
				if method == http.MethodPost {
					path += "/test-app"
				}
				result := portalAdminRequest(t, handler, method, path, "{}", "tenant-a")
				if result.Code != http.StatusBadGateway {
					t.Fatalf("unavailable inventory became absence/success: %d %s", result.Code, result.Body.String())
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("invalid inventory dispatched mutation", err)
			}
		})
	}
}

func TestApplicationPriorEvidenceFailureNeverReplays(t *testing.T) {
	for _, kind := range []string{"malformed", "directory", "symlink", "dangling-symlink", "empty", "wrong-cluster", "wrong-app", "missing-id", "unknown-status", "duplicate-status", "RUNNING", "UNKNOWN", "SUCCEEDED-absent-release"} {
		t.Run(kind, func(t *testing.T) {
			_, ws, handler, marker := applicationInventoryFixture(t, `[]`)
			path := applicationJobPath(ws, "test-app")
			now := time.Now().UTC()
			job := ApplicationInstallJob{ID: "original", ClusterID: ws.ClusterID, Application: "test-app", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now}
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink", "dangling-symlink":
				target := filepath.Join(filepath.Dir(marker), "foreign-job")
				if kind == "symlink" {
					raw, _ := json.Marshal(job)
					if err := os.WriteFile(target, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			default:
				switch kind {
				case "wrong-cluster":
					job.ClusterID = "foreign"
				case "wrong-app":
					job.Application = "foreign"
				case "missing-id":
					job.ID = ""
				case "unknown-status":
					job.Status = "new-state"
				case "RUNNING":
					job.Status = "RUNNING"
				case "SUCCEEDED-absent-release":
					job.Status = "SUCCEEDED"
				}
				raw, _ := json.Marshal(job)
				if kind == "malformed" {
					raw = []byte(`{`)
				}
				if kind == "empty" {
					raw = nil
				}
				if kind == "duplicate-status" {
					raw = []byte(strings.Replace(string(raw), `"status":"UNKNOWN"`, `"status":"RUNNING","status":"UNKNOWN"`, 1))
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
			after, err := os.Lstat(path)
			if result.Code != http.StatusConflict || err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("prior evidence overwritten or replayed: %d %v", result.Code, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("prior evidence fault dispatched mutation", err)
			}
		})
	}
}

func waitApplicationJob(t *testing.T, ws Workspace) *ApplicationInstallJob {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := readApplicationJob(ws, "test-app")
		if err == nil && job.Status != "RUNNING" {
			return job
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fixture job did not terminate")
	return nil
}

func applicationInstallFixtureCommand(t *testing.T, p *Portal, marker, after string, exit int) {
	t.Helper()
	root := filepath.Dir(marker)
	post := filepath.Join(root, "after-inventory.json")
	if err := os.WriteFile(post, []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then if [ -e \"" + marker + "\" ]; then cat \"" + post + "\"; else cat \"" + filepath.Join(root, "release-inventory.json") + "\"; fi; exit 0; fi\nprintf '%s\\n' \"$@\" > \"" + marker + "\"\nexit " + fmt.Sprint(exit) + "\n"
	if err := os.WriteFile(p.HelmBinary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationOriginalCommandAndQualifiedReadback(t *testing.T) {
	for _, tc := range []struct {
		name, after string
		exit        int
		success     bool
	}{
		{"zero-exit-exact", exactApplicationInventory, 0, true},
		{"nonzero-exit-exact", exactApplicationInventory, 1, false},
		{"zero-exit-foreign", strings.Replace(exactApplicationInventory, "owned-ns", "foreign-ns", 1), 0, false},
		{"zero-exit-failed", strings.Replace(exactApplicationInventory, "deployed", "failed", 1), 0, false},
		{"zero-exit-wrong-version", strings.Replace(exactApplicationInventory, "1.2.0", "1.3.0", 1), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ws, handler, marker := applicationInventoryFixture(t, `[]`)
			applicationInstallFixtureCommand(t, p, marker, tc.after, tc.exit)
			result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
			if result.Code != http.StatusAccepted {
				t.Fatal("fresh fixture install not dispatched", result.Code, result.Body.String())
			}
			job := waitApplicationJob(t, ws)
			if (job.Status == "SUCCEEDED") != tc.success {
				t.Fatalf("unqualified invocation completion: %+v", job)
			}
			if tc.success && job.EvidenceLabel != "HELM_RELEASE_CONFIRMED" || !tc.success && job.Status != "UNKNOWN" {
				t.Fatalf("unqualified evidence label/status: %+v", job)
			}
			args, err := os.ReadFile(marker)
			if err != nil || !strings.Contains(string(args), "upgrade\n--install\ntest-release\ntest-chart\n--repo\nhttps://charts.invalid/\n--version\n1.2.0\n--namespace\nowned-ns\n") {
				t.Fatal("original fixture command changed", string(args), err)
			}
			if !tc.success {
				repeat := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
				if repeat.Code != http.StatusConflict {
					t.Fatal("uncertain invocation replayed", repeat.Code)
				}
			}
		})
	}
}

type applicationCallbackRunner struct {
	portalRunner
	once     sync.Once
	callback func()
}

func (r *applicationCallbackRunner) Run(c context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	r.once.Do(r.callback)
	return r.portalRunner.Run(c, dir, binary, args, env)
}

func TestApplicationCatalogFrozenBeforeReadbackAndAsyncCommand(t *testing.T) {
	p, ws, handler, marker := applicationInventoryFixture(t, `[]`)
	profiles := cloneApplicationProfiles(p.Applications)
	profiles[0].Values = map[string]string{"probe": "original"}
	if err := p.ConfigureApplications(profiles, p.HelmBinary); err != nil {
		t.Fatal(err)
	}
	profiles[0].Values["probe"] = "caller-mutated"
	if p.Applications[0].Values["probe"] != "original" {
		t.Fatal("configuration retained caller map")
	}
	applicationInstallFixtureCommand(t, p, marker, exactApplicationInventory, 0)
	p.Client.runner = &applicationCallbackRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}, callback: func() {
		p.Applications[0].RepositoryURL = "https://foreign.invalid/"
		p.Applications[0].Version = "9.0.0"
		p.Applications[0].Values["probe"] = "callback-mutated"
		p.HelmBinary = filepath.Join(filepath.Dir(marker), "unconfigured-helm")
	}}
	result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
	if result.Code != http.StatusAccepted {
		t.Fatal("frozen source profile changed", result.Code, result.Body.String())
	}
	job := waitApplicationJob(t, ws)
	if job.Status != "SUCCEEDED" {
		t.Fatal("original frozen invocation not confirmed", job)
	}
	args, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(args), "https://charts.invalid/") || !strings.Contains(string(args), "probe=original") || strings.Contains(string(args), "mutated") {
		t.Fatal("borrowed alias changed original command", string(args), err)
	}
}

func TestApplicationExactVersionSelectorsAndComponents(t *testing.T) {
	for _, tc := range []struct {
		configured, observed string
		supported, installed bool
	}{
		{"1.2.0", "1.2.0", true, true}, {"1.2.0-rc.1+build.7", "1.2.0-rc.1+build.7", true, true},
		{"1.2.0-rc.1+build.7", "1.2.0-rc.1+build.8", true, false}, {"1.2.0-rc.1", "1.2.0", true, false},
		{"v1.2.0", "1.2.0", false, false}, {"1.2", "1.2.0", false, false}, {"latest", "1.2.0", false, false},
		{"1.2.0-rc.01", "1.2.0-rc.01", false, false},
	} {
		t.Run(tc.configured+"/"+tc.observed, func(t *testing.T) {
			p, _, handler, marker := applicationInventoryFixture(t, strings.Replace(exactApplicationInventory, "1.2.0", tc.observed, 1))
			profiles := cloneApplicationProfiles(p.Applications)
			profiles[0].Version = tc.configured
			if err := p.ConfigureApplications(profiles, p.HelmBinary); err != nil {
				t.Fatal(err)
			}
			result := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/applications", "", "tenant-a")
			var got struct {
				Applications []applicationState `json:"applications"`
			}
			if err := json.Unmarshal(result.Body.Bytes(), &got); err != nil || len(got.Applications) != 1 {
				t.Fatal("inventory decode", err)
			}
			if got.Applications[0].Installed != tc.installed {
				t.Fatal("version components weakened", got.Applications[0])
			}
			if !tc.supported {
				result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
				if result.Code != http.StatusConflict {
					t.Fatal("unsupported selector dispatched", result.Code)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unsupported selector mutated", err)
			}
		})
	}
}

func TestApplicationExistingUnqualifiedTargetNeverAutoUpgrades(t *testing.T) {
	for _, kind := range []string{"failed", "pending-install", "wrong-chart", "wrong-version"} {
		t.Run(kind, func(t *testing.T) {
			rows := exactApplicationInventory
			switch kind {
			case "wrong-chart":
				rows = strings.Replace(rows, "test-chart-1.2.0", "foreign-chart-1.2.0", 1)
			case "wrong-version":
				rows = strings.Replace(rows, "1.2.0", "2.0.0", 1)
			default:
				rows = strings.Replace(rows, "deployed", kind, 1)
			}
			_, ws, handler, marker := applicationInventoryFixture(t, rows)
			result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
			if result.Code != http.StatusConflict {
				t.Fatal("unqualified existing target accepted", result.Code)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unqualified existing target mutated", err)
			}
			if _, err := os.Lstat(applicationJobPath(ws, "test-app")); !os.IsNotExist(err) {
				t.Fatal("conflict created job", err)
			}
		})
	}
}

func TestApplicationDependenciesUseTheirOwnQualifiedNamespace(t *testing.T) {
	for _, kind := range []string{"exact", "foreign-namespace", "failed", "wrong-version"} {
		t.Run(kind, func(t *testing.T) {
			dep := helmRelease{Name: "dependency", Namespace: "dep-ns", Status: "deployed", Chart: "dep-chart-1.2.0", Revision: "1"}
			switch kind {
			case "foreign-namespace":
				dep.Namespace = "foreign-ns"
			case "failed":
				dep.Status = "failed"
			case "wrong-version":
				dep.Chart = "dep-chart-2.0.0"
			}
			rows, _ := json.Marshal([]helmRelease{dep})
			p, ws, handler, marker := applicationInventoryFixture(t, string(rows))
			profiles := cloneApplicationProfiles(p.Applications)
			profiles[0].Dependencies = []string{"dep-app"}
			profiles = append(profiles, ApplicationProfile{ID: "dep-app", Label: "Dependency", Category: "testing", RepositoryURL: "https://charts.invalid/", Chart: "dep-chart", Version: "1.2.0", ReleaseName: "dependency", Namespace: "dep-ns"})
			if err := p.ConfigureApplications(profiles, p.HelmBinary); err != nil {
				t.Fatal(err)
			}
			profiles[0].Dependencies[0] = "caller-mutated"
			post := string(rows[:len(rows)-1]) + "," + exactApplicationInventory[1:]
			applicationInstallFixtureCommand(t, p, marker, post, 0)
			if kind == "exact" {
				p.Client.runner = &applicationCallbackRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}, callback: func() {
					for i := range p.Applications {
						if p.Applications[i].ID == "dep-app" {
							p.Applications[i].Namespace = "callback-mutated"
						}
					}
				}}
			}
			result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
			if kind == "exact" {
				if result.Code != http.StatusAccepted {
					t.Fatal("qualified frozen dependency rejected", result.Code, result.Body.String())
				}
				if job := waitApplicationJob(t, ws); job.Status != "SUCCEEDED" {
					t.Fatal("fresh qualified install not confirmed", job)
				}
			} else {
				if result.Code != http.StatusConflict {
					t.Fatal("foreign/unready dependency admitted", result.Code)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("unqualified dependency dispatched mutation", err)
				}
			}
		})
	}
}

func TestApplicationLateUnknownBlocksFreshAndInstalledBranches(t *testing.T) {
	for _, rows := range []string{`[]`, exactApplicationInventory} {
		t.Run(fmt.Sprint(len(rows)), func(t *testing.T) {
			p, ws, handler, marker := applicationInventoryFixture(t, rows)
			now := time.Now().UTC()
			original := ApplicationInstallJob{ID: "late-original", ClusterID: ws.ClusterID, Application: "test-app", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
			p.Client.runner = &applicationCallbackRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}, callback: func() {
				if err := writeApplicationJob(ws, original); err != nil {
					t.Fatal(err)
				}
			}}
			result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
			if result.Code == http.StatusAccepted {
				waitApplicationJob(t, ws)
			}
			got, err := readApplicationJob(ws, "test-app")
			if result.Code != http.StatusConflict || err != nil || got.ID != original.ID || got.Status != original.Status || !got.UpdatedAt.Equal(original.UpdatedAt) {
				t.Fatalf("late UNKNOWN overwritten or bypassed: status=%d job=%+v err=%v", result.Code, got, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("late UNKNOWN dispatched fixture mutation", err)
			}
		})
	}
}

type applicationOrderingRunner struct {
	portalRunner
	calls            atomic.Int32
	entered, release chan struct{}
}

func (r *applicationOrderingRunner) Run(c context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if r.calls.Add(1) == 1 {
		close(r.entered)
		select {
		case <-r.release:
		case <-c.Done():
			return CommandResult{}, c.Err()
		}
	}
	return r.portalRunner.Run(c, dir, binary, args, env)
}

func TestApplicationConcurrentUnknownCannotBeAdoptedByEarlierRequest(t *testing.T) {
	p, ws, handler, marker := applicationInventoryFixture(t, `[]`)
	applicationInstallFixtureCommand(t, p, marker, exactApplicationInventory, 1)
	runner := &applicationOrderingRunner{portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}, entered: make(chan struct{}), release: make(chan struct{})}
	p.Client.runner = runner
	var released sync.Once
	release := func() { released.Do(func() { close(runner.release) }) }
	defer release()
	first := make(chan int, 1)
	go func() {
		first <- portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a").Code
	}()
	select {
	case <-runner.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first request did not reach callback")
	}
	second := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
	if second.Code != http.StatusAccepted {
		t.Fatal("independently fresh second fixture request not admitted", second.Code)
	}
	original := waitApplicationJob(t, ws)
	if original.Status != "UNKNOWN" {
		t.Fatal("failed originalcommand lost uncertainty", original)
	}
	before, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case code := <-first:
		if code != http.StatusConflict {
			t.Errorf("earlier request adopted later uncertain release: HTTP%d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first request did not finish")
	}
	got, err := readApplicationJob(ws, "test-app")
	after, statErr := os.Stat(marker)
	if err != nil || statErr != nil || got.ID != original.ID || got.Status != "UNKNOWN" || !got.UpdatedAt.Equal(original.UpdatedAt) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("uncertain operation changed or command replayed", got, err, statErr)
	}
}

func TestApplicationInventoryOriginalNamespaceStatus(t *testing.T) {
	for _, tc := range []struct {
		name, rows string
		installed  bool
	}{
		{"exact-deployed", `[{"name":"test-release","namespace":"owned-ns","status":"deployed","revision":"1","chart":"test-chart-1.2.0"}]`, true},
		{"foreign-namespace", `[{"name":"test-release","namespace":"foreign-ns","status":"deployed","revision":"1","chart":"test-chart-1.2.0"}]`, false},
		{"failed", `[{"name":"test-release","namespace":"owned-ns","status":"failed","revision":"1","chart":"test-chart-1.2.0"}]`, false},
		{"pending", `[{"name":"test-release","namespace":"owned-ns","status":"pending-upgrade","revision":"1","chart":"test-chart-1.2.0"}]`, false},
		{"missing-status", `[{"name":"test-release","namespace":"owned-ns","revision":"1","chart":"test-chart-1.2.0"}]`, false},
		{"wrong-chart", `[{"name":"test-release","namespace":"owned-ns","status":"deployed","revision":"1","chart":"other-chart-1.2.0"}]`, false},
		{"two-namespaces-owned-failed", `[{"name":"test-release","namespace":"owned-ns","status":"failed","revision":"1","chart":"test-chart-1.2.0"},{"name":"test-release","namespace":"foreign-ns","status":"deployed","revision":"1","chart":"test-chart-1.2.0"}]`, false},
		{"two-namespaces-owned-deployed", `[{"name":"test-release","namespace":"owned-ns","status":"deployed","revision":"1","chart":"test-chart-1.2.0"},{"name":"test-release","namespace":"foreign-ns","status":"failed","revision":"1","chart":"other-chart-9.0.0"}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, handler, marker := applicationInventoryFixture(t, tc.rows)
			result := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/applications", "", "tenant-a")
			if tc.name == "missing-status" {
				if result.Code != http.StatusBadGateway {
					t.Fatalf("malformed inventory accepted: %d", result.Code)
				}
				return
			}
			var got struct {
				Applications []applicationState `json:"applications"`
			}
			if err := json.Unmarshal(result.Body.Bytes(), &got); err != nil || result.Code != http.StatusOK || len(got.Applications) != 1 {
				t.Fatalf("inventory failed: %d %s %v", result.Code, result.Body.String(), err)
			}
			if tc.installed && got.Applications[0].HelmChart != "test-chart-1.2.0" {
				t.Fatalf("foreign chart leaked into owned release: %s", got.Applications[0].HelmChart)
			}
			if got.Applications[0].Installed != tc.installed {
				t.Fatalf("foreign/unready inventory accepted: installed=%t want=%t", got.Applications[0].Installed, tc.installed)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("inventory executed fixture mutation", err)
			}
		})
	}
}

func TestApplicationUnknownInventoryNeverProvesOriginalInstall(t *testing.T) {
	for _, status := range []string{"deployed", "failed", "pending-install"} {
		for _, namespace := range []string{"owned-ns", "foreign-ns"} {
			t.Run(namespace+"/"+status, func(t *testing.T) {
				rows, _ := json.Marshal([]map[string]string{{"name": "test-release", "namespace": namespace, "status": status, "revision": "1", "chart": "test-chart-1.2.0"}})
				_, ws, handler, marker := applicationInventoryFixture(t, string(rows))
				now := time.Now().UTC()
				original := ApplicationInstallJob{ID: "original-unknown", ClusterID: ws.ClusterID, Application: "test-app", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
				if err := writeApplicationJob(ws, original); err != nil {
					t.Fatal(err)
				}
				result := portalAdminRequest(t, handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/applications/test-app", "{}", "tenant-a")
				got, err := readApplicationJob(ws, "test-app")
				if result.Code != http.StatusConflict || err != nil || got.Status != "UNKNOWN" || got.ID != original.ID || !got.UpdatedAt.Equal(original.UpdatedAt) {
					t.Fatalf("inventory promoted/replaced original UNKNOWN: status=%d job=%+v err=%v", result.Code, got, err)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("UNKNOWN replay executed fixture mutation", err)
				}
			})
		}
	}
}
