package lifecycle

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enableSyntheticZeroTouchDR(p *Portal) {
	p.recovery = &RecoveryManager{client: p.Client, config: RecoveryConfig{
		DRTargets:   []DRClusterTarget{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", APIEndpoint: "https://dr.lab.internal:6443"}},
		ZeroTouchDR: []ZeroTouchDRPolicy{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", Enabled: true}},
	}}
}

func waitZeroTouchIntent(t *testing.T, ws Workspace) ZeroTouchDRIntent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := readZeroTouchDRIntent(ws)
		if err == nil {
			return record
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("auto DR intent corrupt: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("automatic primary-to-DR enrollment intent was not published")
	return ZeroTouchDRIntent{}
}

func TestZeroTouchDRAfterProvisionAutomaticallyQueuesExactTenantSite(t *testing.T) {
	p, handler, ws, runner := provisionAdmissionFixture(t)
	enableSyntheticZeroTouchDR(p)
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	before := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "tenant-a")
	if before.Code != 200 || !strings.Contains(before.Body.String(), `"status":"AWAITING_PRIMARY_CLUSTER"`) {
		t.Fatalf("DR status before source provision inaccurate: %d %s", before.Code, before.Body.String())
	}
	response := portalRequest(t, handler, http.MethodPost, path, "{}", "tenant-a")
	if response.Code != http.StatusAccepted {
		t.Fatal("single primary provision request rejected", response.Code, response.Body.String())
	}
	body := waitPortalJob(t, handler, path, "tenant-a", "SUCCEEDED")
	if !strings.Contains(body, `"evidence_label":"LIVE_PROVEN"`) {
		t.Fatal("primary was not verified")
	}
	record := waitZeroTouchIntent(t, ws)
	if record.Status != "ENROLLMENT_QUEUED" || record.EvidenceLabel != "NOT_RECOVERY_VERIFIED" ||
		record.TargetClusterID != "cluster-dr" || record.SourceClusterID != "cluster-a" || record.Tenant != "tenant-a" ||
		len(record.SourceProvisionID) != 32 || record.RequestedAt.IsZero() {
		t.Fatalf("incorrect server-owned DR enrollment record %+v", record)
	}
	original, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Lstat(zeroTouchDRIntentPath(ws))
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("intent is not private", err)
	}
	sourceJob := ProvisionJob{}
	if err := readBoundedJob(provisionJobPath(ws), &sourceJob); err != nil {
		t.Fatal(err)
	}
	if err := p.queueZeroTouchDR(ws, sourceJob); err != nil {
		t.Fatal("same identity redelivery failed", err)
	}
	after, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil || string(after) != string(original) {
		t.Fatal("idempotent notification rewrote durable intent")
	}
	displayed := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "tenant-a")
	if displayed.Code != 200 || !strings.Contains(displayed.Body.String(), `"status":"ENROLLMENT_QUEUED"`) ||
		!strings.Contains(displayed.Body.String(), `"protected":false`) ||
		!strings.Contains(displayed.Body.String(), `"restore_verified":false`) {
		t.Fatalf("customer was incorrectly told DR is protected: %d %s", displayed.Code, displayed.Body.String())
	}
	if unauthorized := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "another-tenant"); unauthorized.Code != http.StatusNotFound {
		t.Fatal("cross-tenant protection status leaked", unauthorized.Code)
	}
	if runner.applyCalls != 1 {
		t.Fatal("DR enrollment triggered an unqualified second KubeOne apply", runner.applyCalls)
	}
}

func TestZeroTouchDRDefaultDisabledDoesNotCreateIntent(t *testing.T) {
	_, handler, ws, runner := provisionAdmissionFixture(t)
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	res := portalRequest(t, handler, http.MethodPost, path, "{}", "tenant-a")
	if res.Code != 202 {
		t.Fatal("primary provision blocked", res.Code)
	}
	waitPortalJob(t, handler, path, "tenant-a", "SUCCEEDED")
	status := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "tenant-a")
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"status":"NOT_CONFIGURED"`) {
		t.Fatal("default DR opt-out changed", status.Body.String())
	}
	if _, err := os.Lstat(zeroTouchDRIntentPath(ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled DR wrote an enrollment intent", err)
	}
	if runner.applyCalls != 1 {
		t.Fatal("unexpected extra apply")
	}
}

func TestZeroTouchDRUnknownProvisionDoesNotEnroll(t *testing.T) {
	p, handler, ws, runner := provisionAdmissionFixture(t)
	enableSyntheticZeroTouchDR(p)
	runner.applyErr = errors.New("synthetic transport closed after possibly committing")
	path := "/v1/kubernetes/clusters/cluster-a/provision"
	if res := portalRequest(t, handler, http.MethodPost, path, "{}", "tenant-a"); res.Code != 202 {
		t.Fatal(res.Code)
	}
	waitPortalJob(t, handler, path, "tenant-a", "UNKNOWN")
	if _, err := os.Lstat(zeroTouchDRIntentPath(ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ambiguous primary provision enrolled DR", err)
	}
	status := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "tenant-a")
	if status.Code != 200 || strings.Contains(status.Body.String(), `"protected":true`) {
		t.Fatal("unknown provision falsely protected")
	}
}

func TestZeroTouchDRRefusesJournalReplayOrChangedTarget(t *testing.T) {
	p, _, ws, _ := provisionAdmissionFixture(t)
	enableSyntheticZeroTouchDR(p)
	primary := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID, Status: "SUCCEEDED", EvidenceLabel: "LIVE_PROVEN", RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := writeBoundedJob(ws, provisionJobPath(ws), ".test-ztd-primary-*", primary); err != nil {
		t.Fatal(err)
	}
	if err := p.queueZeroTouchDR(ws, primary); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil {
		t.Fatal(err)
	}
	changed := primary
	changed.ID = strings.Repeat("b", 32)
	if err := p.queueZeroTouchDR(ws, changed); err == nil {
		t.Fatal("different original source identity replayed")
	}
	p.recovery.config.ZeroTouchDR[0].TargetClusterID = "foreign-dr"
	p.recovery.config.DRTargets[0].TargetClusterID = "foreign-dr"
	if err := p.queueZeroTouchDR(ws, primary); err == nil {
		t.Fatal("changed DR target rewrote existing intent")
	}
	after, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil || string(after) != string(original) {
		t.Fatal("untrusted state replaced durable DR intent")
	}
	path := zeroTouchDRIntentPath(ws)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws.Directory, "do-not-touch"), path); err != nil {
		t.Fatal(err)
	}
	if err := p.queueZeroTouchDR(ws, primary); err == nil {
		t.Fatal("symlinked journal incorrectly admitted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("foreign symlink mutated")
	}
}

func TestZeroTouchDRPolicyRequiresUniqueTenantBoundSite(t *testing.T) {
	p, _, _, _, _ := recoveryFixture(t, true)
	good := ZeroTouchDRPolicy{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", Enabled: true}
	cfg := p.recovery.config
	cfg.ZeroTouchDR = []ZeroTouchDRPolicy{good}
	if err := cfg.Validate(); err != nil {
		t.Fatal("valid centrally registered site rejected", err)
	}
	cases := []struct {
		name     string
		policies []ZeroTouchDRPolicy
	}{
		{"no_registration", []ZeroTouchDRPolicy{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "not-a-site", Enabled: true}}},
		{"disabled_entry", []ZeroTouchDRPolicy{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", Enabled: false}}},
		{"cross_tenant", []ZeroTouchDRPolicy{{Tenant: "other-tenant", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", Enabled: true}}},
		{"same_site", []ZeroTouchDRPolicy{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-a", Enabled: true}}},
		{"duplicate", []ZeroTouchDRPolicy{good, good}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copy := cfg
			copy.ZeroTouchDR = tc.policies
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe zero-touch DR policy qualified")
			}
		})
	}
}

// A symlink replacement of the entire source workspace must not redirect
// the single-use enrollment intent into a different ownership directory.
func TestZeroTouchDRRejectsReplacedWorkspaceDirectory(t *testing.T) {
	portal, _, ws, _ := provisionAdmissionFixture(t)
	enableSyntheticZeroTouchDR(portal)
	primary := ProvisionJob{ID: strings.Repeat("c", 32), ClusterID: ws.ClusterID, Status: "SUCCEEDED", EvidenceLabel: "LIVE_PROVEN", RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := writeBoundedJob(ws, provisionJobPath(ws), ".test-ztd-primary-*", primary); err != nil {
		t.Fatal(err)
	}
	archived := ws.Directory + "-original"
	if err := os.Rename(ws.Directory, archived); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(archived, ws.Directory); err != nil {
		t.Fatal(err)
	}
	if err := portal.queueZeroTouchDR(ws, primary); err == nil {
		t.Fatal("replaced workspace directory admitted enrollment")
	}
	if _, err := os.Lstat(filepath.Join(archived, zeroTouchDRIntentFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("intent was created under replaced workspace path", err)
	}
}
