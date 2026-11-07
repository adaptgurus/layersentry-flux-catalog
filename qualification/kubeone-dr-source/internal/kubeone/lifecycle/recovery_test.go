package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

type recoveryFakeRunner struct {
	t       *testing.T
	mu      sync.Mutex
	calls   [][]string
	etcd    []byte
	corrupt bool
	portalRunner
}

func (r *recoveryFakeRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{binary}, args...))
	if len(args) > 2 && args[0] == "etcd" && args[1] == "snapshot" {
		r.etcd = bytes.Repeat([]byte("native-etcd-test-snapshot"), 80)
		if err := os.WriteFile(args[2], r.etcd, 0600); err != nil {
			return CommandResult{}, err
		}
		return CommandResult{Stdout: "native snapshot completed"}, nil
	}
	if len(args) > 4 && args[0] == "--repo" {
		repo := args[1]
		switch args[4] {
		case "init":
			if err := os.WriteFile(filepath.Join(repo, "config"), []byte("fixture-restic-config"), 0600); err != nil {
				return CommandResult{}, err
			}
			return CommandResult{Stdout: "repository initialized"}, nil
		case "backup":
			// Plaintext file content enters ONLY the encrypted Restic operation.
			if !strings.Contains(strings.Join(args, " "), "--tag") {
				r.t.Fatal("missing source binding tags")
			}
			return CommandResult{Stdout: `{"message_type":"status","seconds_elapsed":1}` + "\n" +
				`{"message_type":"summary","snapshot_id":"` + strings.Repeat("a", 64) + `"}` + "\n"}, nil
		case "restore":
			target := ""
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--target" {
					target = args[i+1]
				}
			}
			if target == "" {
				r.t.Fatal("missing Restic restore target")
			}
			path := filepath.Join(target, "workspace", "snapshot.db")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return CommandResult{}, err
			}
			content := bytes.Clone(r.etcd)
			if r.corrupt {
				content[0] ^= 1
			}
			if err := os.WriteFile(path, content, 0600); err != nil {
				return CommandResult{}, err
			}
			return CommandResult{Stdout: "restored"}, nil
		}
	}
	return r.portalRunner.Run(ctx, dir, binary, args, env)
}

func recoveryFixture(t *testing.T, withDR bool) (*Portal, Workspace, *recoveryFakeRunner, NFSBackupTarget, http.Handler) {
	t.Helper()
	root, ws := tempWorkspace(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ws.SelfServiceLifecycle = true
	ws.ExpectedNodes = 4
	cfg := RegistryFile{Clusters: []Workspace{ws}}
	if withDR {
		target := ws
		target.ClusterID = "cluster-dr"
		target.Directory = filepath.Join("tenant-a", "cluster-dr")
		path := filepath.Join(root, target.Directory)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"kubeone.yaml", "kubeconfig", "tf.json", "credentials.yaml"} {
			if err := os.WriteFile(filepath.Join(path, name), []byte("dr-native"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		cfg.Clusters = append(cfg.Clusters, target)
	}
	reg, err := NewRegistry(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ws, err = reg.Resolve("tenant-a", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	runner := &recoveryFakeRunner{t: t, portalRunner: portalRunner{namespaceRunner: namespaceRunner{t: t}}}
	kb := executable(t, root, "kubeone")
	kubectl := executable(t, root, "kubectl")
	client, err := NewClient(reg, runner, ClientConfig{KubeOneBinary: kb, KubectlBinary: kubectl, Timeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	nfs := filepath.Join(root, "nfs-mounted-fixture")
	if err := os.Mkdir(nfs, 0700); err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(root, "restic-pass")
	if err := os.WriteFile(pass, []byte(strings.Repeat("P", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	target := NFSBackupTarget{Tenant: "tenant-a", ID: "nfs-dr", DisplayName: "Approved DR NFS", MountPath: nfs, MountSource: "10.0.5.10:/nfs-target", PasswordFile: pass}
	config := RecoveryConfig{ResticBinary: executable(t, root, "restic"), StagingRoot: root, NFSTargets: []NFSBackupTarget{target}}
	if withDR {
		config.DRTargets = []DRClusterTarget{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", APIEndpoint: "https://dr.lab.internal:6443"}}
	}
	if err := p.ConfigureRecovery(config); err != nil {
		t.Fatal(err)
	}
	// The fixture injects a clean mount observation ONLY inside isolated tests.
	p.recovery.mountCheck = func(NFSBackupTarget) error { return nil }
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	return p, ws, runner, target, auth.Middleware(p.Handler())
}

func TestRecoveryConfigRejectsUnsafePathsEndpointsAndSecrets(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	exe := executable(t, root, "restic")
	mount := filepath.Join(root, "nfs")
	os.Mkdir(mount, 0700)
	pass := filepath.Join(root, "password")
	os.WriteFile(pass, []byte(strings.Repeat("p", 32)), 0600)
	base := RecoveryConfig{ResticBinary: exe, StagingRoot: root, NFSTargets: []NFSBackupTarget{{Tenant: "tenant-a", ID: "backup", DisplayName: "Site NFS", MountPath: mount, MountSource: "10.0.0.1:/data", PasswordFile: pass}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://evil:6443", "https://localhost:6443", "https://good:443", "https://good:6443/path", "https://good:6443@evil:6443", "https://127.0.0.1:6443", "https://bad:6443#frag"} {
		if validRecoveryEndpoint(bad) {
			t.Fatalf("unsafe endpoint admitted %q", bad)
		}
	}
	dup := base
	dup.NFSTargets = append(dup.NFSTargets, base.NFSTargets[0])
	if dup.Validate() == nil {
		t.Fatal("duplicate NFS target admitted")
	}
	os.Chmod(pass, 0644)
	if base.Validate() == nil {
		t.Fatal("world-readable password accepted")
	}
	os.Chmod(pass, 0600)
	os.Symlink(pass, filepath.Join(root, "alias"))
	alias := base
	alias.NFSTargets = append([]NFSBackupTarget(nil), base.NFSTargets...)
	alias.NFSTargets[0].PasswordFile = filepath.Join(root, "alias")
	if alias.Validate() == nil {
		t.Fatal("symlink secret accepted")
	}
}

func TestNativeKubeOneSnapshotEncryptedResticNFSDigest(t *testing.T) {
	p, ws, runner, target, _ := recoveryFixture(t, false)
	id, original, err := p.recovery.BackupEtcdToNFS(context.Background(), ws, target.ID, "0123456789abcdef0123456789abcdef")
	if err != nil || id != strings.Repeat("a", 64) {
		t.Fatalf("native snapshot and encrypted restic failed: id=%s err=%v", id, err)
	}
	sum := sha256.Sum256(bytes.Repeat([]byte("native-etcd-test-snapshot"), 80))
	if original != hex.EncodeToString(sum[:]) {
		t.Fatal("native snapshot restore checksum incorrect")
	}
	calls := strings.Join(flattenRecoveryCalls(runner.calls), "\n")
	if !strings.Contains(calls, "etcd snapshot") || !strings.Contains(calls, "--password-file") ||
		!strings.Contains(calls, " init") || !strings.Contains(calls, " backup") || !strings.Contains(calls, " restore") {
		t.Fatalf("incomplete native/restic pipeline: %s", calls)
	}
	for _, call := range flattenRecoveryCalls(runner.calls) {
		if strings.Contains(call, strings.Repeat("P", 32)) {
			t.Fatal("restic password value leaked in argv")
		}
	}
	runner.corrupt = true
	_, _, err = p.recovery.BackupEtcdToNFS(context.Background(), ws, target.ID, "fedcba9876543210fedcba9876543210")
	if err == nil {
		t.Fatal("corrupted restore wrongly accepted")
	}
}

func flattenRecoveryCalls(calls [][]string) []string {
	flat := make([]string, len(calls))
	for i, call := range calls {
		flat[i] = strings.Join(call, " ")
	}
	return flat
}

func TestRecoveryRejectsUnapprovedNFSMountBeforeAnyCommand(t *testing.T) {
	p, ws, r, _, _ := recoveryFixture(t, false)
	p.recovery.mountCheck = func(NFSBackupTarget) error { return errors.New("wrong NFS source") }
	if _, _, err := p.recovery.BackupEtcdToNFS(context.Background(), ws, "nfs-dr", strings.Repeat("a", 32)); err == nil {
		t.Fatal("unapproved mount launched backup")
	}
	if len(r.calls) != 0 {
		t.Fatal("unapproved mount reached provider")
	}
}

func TestOneClickPortalAuthenticatedBackupAndIdempotency(t *testing.T) {
	_, ws, runner, _, h := recoveryFixture(t, false)
	route := "/v1/kubernetes/clusters/cluster-a/backups"
	// Untrusted tenant scope and unsupported FULL scope must never run.
	if got := portalAdminRequest(t, h, http.MethodPost, route, `{"destination_id":"nfs-dr","mode":"FULL_CLUSTER"}`, "tenant-a"); got.Code != 400 {
		t.Fatalf("FULL_CLUSTER falsely accepted: %d %s", got.Code, got.Body.String())
	}
	bad := portalAdminRequest(t, h, http.MethodPost, route, `{"destination_id":"nfs-dr","mode":"ETCD_ONLY"}`, "tenant-b")
	if bad.Code != 404 {
		t.Fatalf("cross-tenant backup admitted: %d", bad.Code)
	}
	request := func(key string) *http.Request {
		r := newRecoveryAdminRequest(http.MethodPost, route, `{"destination_id":"nfs-dr","mode":"ETCD_ONLY"}`, "tenant-a")
		r.Header.Set("Idempotency-Key", key)
		return r
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request(strings.Repeat("b", 32)))
	if rec.Code != 202 {
		t.Fatalf("one-click backup blocked: %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		job, err := readBackupJob(ws)
		if err == nil && job.Status == "SUCCEEDED" {
			if job.Coverage != "ETCD_ONLY" || job.EvidenceLabel != "ETCD_RESTIC_RESTORE_VERIFIED" ||
				strings.Contains(strings.ToLower(job.Message), "pvc included") {
				t.Fatal("unqualified PVC content represented as protected")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup journal never completed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	count := len(runner.calls)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, request(strings.Repeat("b", 32)))
	if second.Code != 202 || len(runner.calls) != count {
		t.Fatal("idempotent duplicate replayed native backup", second.Code)
	}
}

func newRecoveryAdminRequest(method, path, body, tenant string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	r.Header.Set(platformapi.GatewayUserHeader, "test-oneadmin")
	r.Header.Set(platformapi.GatewayUIDHeader, "0")
	r.Header.Set(platformapi.GatewayTenantHeader, tenant)
	r.Header.Set(platformapi.GatewayAdminHeader, "true")
	setLifecycleTestStepUp(r)
	return r
}

func TestDRPolicyPinsIndependentTargetAndBlocksUnsafeFailover(t *testing.T) {
	_, _, _, _, h := recoveryFixture(t, true)
	url := "/v1/kubernetes/clusters/cluster-a/dr"
	tests := []struct {
		body string
		code int
	}{
		{`{"enabled":true,"target_cluster_id":"cluster-a","target_endpoint":"https://dr.lab.internal:6443","destination_id":"nfs-dr"}`, 400},
		{`{"enabled":true,"target_cluster_id":"cluster-dr","target_endpoint":"https://evil.internal:6443","destination_id":"nfs-dr"}`, 400},
		{`{"enabled":true,"target_cluster_id":"cluster-dr","target_endpoint":"https://dr.lab.internal:6443","destination_id":"nfs-dr"}`, 200},
	}
	for _, tc := range tests {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newRecoveryAdminRequest(http.MethodPut, url, tc.body, "tenant-a"))
		if w.Code != tc.code {
			t.Fatalf("plan=%s status=%d want=%d body=%s", tc.body, w.Code, tc.code, w.Body.String())
		}
	}
	policy := portalAdminRequest(t, h, http.MethodGet, url, "", "tenant-a")
	if policy.Code != 200 || !strings.Contains(policy.Body.String(), `"state":"BLOCKED"`) {
		t.Fatal("DR plan made unsafe ACTIVE", policy.Code, policy.Body.String())
	}
	validation := portalAdminRequest(t, h, http.MethodPost, url+"/validate", "{}", "tenant-a")
	if validation.Code != 200 || !strings.Contains(validation.Body.String(), `"ready_for_failover":false`) {
		t.Fatal("KubeOne DR validation falsely claimed data protection", validation.Code, validation.Body.String())
	}
	for _, action := range []string{"/failover", "/failback"} {
		got := portalAdminRequest(t, h, http.MethodPost, url+action, "{}", "tenant-a")
		if got.Code != http.StatusConflict {
			t.Fatal("unqualified DR mutation accepted", action, got.Code)
		}
	}
	disabled := portalAdminRequest(t, h, http.MethodPut, url, `{"enabled":false}`, "tenant-a")
	if disabled.Code != 200 || !strings.Contains(disabled.Body.String(), `"state":"DISABLED"`) {
		t.Fatal("DR disable failed", disabled.Code, disabled.Body.String())
	}
}

func TestRecoveryStateCannotAcceptMalformedOrForeignBackupJob(t *testing.T) {
	_, ws, _, _, _ := recoveryFixture(t, false)
	path := backupJournalPath(ws)
	for _, raw := range []string{`{"status":"SUCCEEDED","status":"RUNNING"}`, `{"status":"SUCCEEDED","unexpected":123}`, `{"id":null}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBackupJob(ws); err == nil {
			t.Fatal("malformed job accepted")
		}
	}
}

func TestBackupUnknownJournalPreventsBlindReplay(t *testing.T) {
	_, ws, runner, _, h := recoveryFixture(t, false)
	now := time.Now().UTC()
	unknown := ClusterBackupJob{
		ID: strings.Repeat("c", 32), ClusterID: ws.ClusterID,
		DestinationID: "nfs-dr", IdempotencyKey: strings.Repeat("d", 32),
		Status: "UNKNOWN", Coverage: "ETCD_ONLY", RequestedAt: now, UpdatedAt: now,
		EvidenceLabel: "UNKNOWN", Message: "original result unknown",
	}
	if err := writeBoundedJob(ws, backupJournalPath(ws), ".layersentry-etcd-backup-test-*.tmp", unknown); err != nil {
		t.Fatal(err)
	}
	r := newRecoveryAdminRequest(http.MethodPost, "/v1/kubernetes/clusters/cluster-a/backups", `{"destination_id":"nfs-dr","mode":"ETCD_ONLY"}`, "tenant-a")
	r.Header.Set("Idempotency-Key", strings.Repeat("e", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || len(runner.calls) != 0 {
		t.Fatalf("unreconciled backup replayed: http%d calls%d", w.Code, len(runner.calls))
	}
}

func TestBackupSnapshotSymlinkCannotEscapePrivateStaging(t *testing.T) {
	p, ws, _, target, _ := recoveryFixture(t, false)
	secret := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(secret, bytes.Repeat([]byte("X"), 1024), 0400); err != nil {
		t.Fatal(err)
	}
	type maliciousRunner struct{ Runner }
	// A custom runner can return a symlink in place of an etcd snapshot. The
	// backup path must never chmod/follow it into a protected outside file.
	_ = maliciousRunner{}
	m := p.recovery
	testRunner := &snapshotSymlinkRunner{target: secret}
	m.client.runner = testRunner
	_, _, err := m.BackupEtcdToNFS(context.Background(), ws, target.ID, strings.Repeat("e", 32))
	if err == nil {
		t.Fatal("symlink pretending to be native snapshot was accepted")
	}
	stat, e := os.Stat(secret)
	if e != nil || stat.Mode().Perm() != 0400 {
		t.Fatal("snapshot handling changed permissions on outside file")
	}
}

type snapshotSymlinkRunner struct{ target string }

func (r *snapshotSymlinkRunner) Run(_ context.Context, _ string, _ string, args, _ []string) (CommandResult, error) {
	if len(args) > 2 && args[0] == "etcd" && args[1] == "snapshot" {
		if err := os.Symlink(r.target, args[2]); err != nil {
			return CommandResult{}, err
		}
		return CommandResult{}, nil
	}
	return CommandResult{}, errors.New("unexpected tool invoked")
}

func TestDRReadRejectsTamperedPersistedIdentity(t *testing.T) {
	_, ws, _, _, h := recoveryFixture(t, true)
	route := "/v1/kubernetes/clusters/cluster-a/dr"
	enable := `{"enabled":true,"target_cluster_id":"cluster-dr","target_endpoint":"https://dr.lab.internal:6443","destination_id":"nfs-dr"}`
	enabled := portalAdminRequest(t, h, http.MethodPut, route, enable, "tenant-a")
	if enabled.Code != 200 {
		t.Fatal(enabled.Code, enabled.Body.String())
	}
	path := drPolicyPath(ws)
	var policy DRProtectionPolicy
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &policy); e != nil {
		t.Fatal(e)
	}
	policy.TargetIdentity = strings.Repeat("0", 64)
	if e = writeBoundedJob(ws, path, ".tampered-policy-*.tmp", policy); e != nil {
		t.Fatal(e)
	}
	validated := portalAdminRequest(t, h, http.MethodPost, route+"/validate", "{}", "tenant-a")
	if validated.Code != 409 {
		t.Fatalf("DR identity drift should not be accepted: %d", validated.Code)
	}
}
func TestRecoveryConfigurationFileRequiresPrivateOwnerAndSchema(t *testing.T) {
	p, _, _, _, _ := recoveryFixture(t, false)
	cfg := p.recovery.config
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recovery.json")
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadRecoveryConfig(path); err != nil || got.NFSTargets[0].ID != "nfs-dr" {
		t.Fatalf("valid protected server config rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryConfig(path); err == nil {
		t.Fatal("world-readable recovery config accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(path), "symlink.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryConfig(alias); err == nil {
		t.Fatal("symlink config accepted")
	}
	invalid := bytes.Replace(blob, []byte(`"restic_binary":`), []byte(`"unknown_field":true,"restic_binary":`), 1)
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryConfig(path); err == nil {
		t.Fatal("unknown root config field accepted")
	}
}

func TestRecoveryRequiresGatewayAuthorizationAndRejectsInjectedPaths(t *testing.T) {
	_, _, runner, _, h := recoveryFixture(t, false)
	route := "/v1/kubernetes/clusters/cluster-a/backups"
	injected := httptest.NewRecorder()
	r := newRecoveryAdminRequest(http.MethodPost, route, `{"destination_id":"nfs-dr","mode":"ETCD_ONLY","mount_path":"/tmp/evil"}`, "tenant-a")
	r.Header.Set("Idempotency-Key", strings.Repeat("f", 32))
	h.ServeHTTP(injected, r)
	if injected.Code != 400 || len(runner.calls) != 0 {
		t.Fatal("browser path accepted", injected.Code)
	}
	noStep := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"destination_id":"nfs-dr","mode":"ETCD_ONLY"}`))
	req.Header.Set(platformapi.GatewayTokenHeader, strings.Repeat("g", 32))
	req.Header.Set(platformapi.GatewayTenantHeader, "tenant-a")
	req.Header.Set(platformapi.GatewayUIDHeader, "test")
	req.Header.Set(platformapi.GatewayUserHeader, "test")
	req.Header.Set(platformapi.GatewayAdminHeader, "true")
	req.Header.Set("Idempotency-Key", strings.Repeat("f", 32))
	h.ServeHTTP(noStep, req)
	if noStep.Code != 403 || len(runner.calls) != 0 {
		t.Fatal("missing MFA bypassed", noStep.Code)
	}
}

func TestRecoveryDestinationListingIsTenantScoped(t *testing.T) {
	_, _, _, _, h := recoveryFixture(t, false)
	ok := portalAdminRequest(t, h, http.MethodGet, "/v1/kubernetes/backup-destinations", "", "tenant-a")
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), "nfs-dr") {
		t.Fatal("authorized destination absent")
	}
	foreign := portalAdminRequest(t, h, http.MethodGet, "/v1/kubernetes/backup-destinations", "", "tenant-b")
	if foreign.Code != 200 || strings.Contains(foreign.Body.String(), "nfs-dr") {
		t.Fatal("foreign backup NFS destination leaked")
	}
}
