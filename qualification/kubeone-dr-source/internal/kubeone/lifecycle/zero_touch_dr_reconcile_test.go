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

func testZeroTouchRecoveryConfig(t *testing.T, ws Workspace) RecoveryConfig {
	t.Helper()
	root := filepath.Dir(ws.Directory)
	staging := filepath.Join(root, "dr-staging")
	mount := filepath.Join(root, "nfs-placeholder")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	password := filepath.Join(root, "restic-test-password")
	if err := os.WriteFile(password, []byte(strings.Repeat("a", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return RecoveryConfig{
		ResticBinary: executable(t, root, "restic"),
		StagingRoot:  staging,
		NFSTargets:   []NFSBackupTarget{{Tenant: "tenant-a", ID: "nfs-test", DisplayName: "Synthetic placeholder only", MountPath: mount, MountSource: "127.0.0.1:/never-mounted", PasswordFile: password}},
		DRTargets:    []DRClusterTarget{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", APIEndpoint: "https://dr.lab.internal:6443"}},
		ZeroTouchDR:  []ZeroTouchDRPolicy{{Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", Enabled: true}},
	}
}
func testSuccessForReconcile(t *testing.T, ws Workspace, status, label string) ProvisionJob {
	t.Helper()
	job := ProvisionJob{ID: strings.Repeat("a", 32), ClusterID: ws.ClusterID, Status: status, ExpectedNodes: ws.ExpectedNodes, ReadyNodes: ws.ExpectedNodes,
		RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), EvidenceLabel: label}
	if err := writeBoundedJob(ws, provisionJobPath(ws), ".test-reconcile-primary-*", job); err != nil {
		t.Fatal(err)
	}
	return job
}

// Regression: original primary success may be published before enrollment
// when the process crashes. After restart, no second customer call is allowed.
func TestZeroTouchDRRestartRepairsPostSuccessCrashWithoutNativeApply(t *testing.T) {
	portal, handler, ws, runner := provisionAdmissionFixture(t)
	testSuccessForReconcile(t, ws, "SUCCEEDED", "LIVE_PROVEN")
	cfg := testZeroTouchRecoveryConfig(t, ws)
	if _, err := os.Lstat(zeroTouchDRIntentPath(ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture already enrolled")
	}
	if err := portal.ConfigureRecovery(cfg); err != nil {
		t.Fatal("startup reconciliation failed", err)
	}
	original, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil {
		t.Fatal("crash-window enrollment not recovered", err)
	}
	intent, err := readZeroTouchDRIntent(ws)
	if err != nil || intent.Status != "ENROLLMENT_QUEUED" || intent.EvidenceLabel != "NOT_RECOVERY_VERIFIED" {
		t.Fatalf("unverified intent wrong: %+v %v", intent, err)
	}
	res := portalRequest(t, handler, http.MethodGet, "/v1/kubernetes/clusters/cluster-a/dr/protection", "", "tenant-a")
	if res.Code != 200 || !strings.Contains(res.Body.String(), "\"protected\":false") {
		t.Fatalf("false DR protection %d %s", res.Code, res.Body.String())
	}
	if runner.applyCalls != 0 {
		t.Fatal("restart reconciliation executed an unqualified native KubeOne apply")
	}
	// A second process start must deliver unchanged bytes, not a new identity.
	restarted, err := NewPortal(portal.Client, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConfigureRecovery(cfg); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(zeroTouchDRIntentPath(ws))
	if err != nil || string(again) != string(original) {
		t.Fatal("restart rewrote immutable enrollment record")
	}
}

func TestZeroTouchDRStartupDoesNotEnrollUnknownOrRewriteConflict(t *testing.T) {
	for _, scenario := range []string{"UNKNOWN", "corrupt_intent", "changed_site"} {
		t.Run(scenario, func(t *testing.T) {
			portal, _, ws, runner := provisionAdmissionFixture(t)
			cfg := testZeroTouchRecoveryConfig(t, ws)
			status, label := "SUCCEEDED", "LIVE_PROVEN"
			if scenario == "UNKNOWN" {
				status, label = "UNKNOWN", "UNKNOWN"
			}
			testSuccessForReconcile(t, ws, status, label)
			path := zeroTouchDRIntentPath(ws)
			var original []byte
			if scenario == "corrupt_intent" {
				original = []byte("{truncated")
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "changed_site" {
				// This intent's tenant/source is valid but the target is not
				// the exact administrator-selected registered target.
				bad := ZeroTouchDRIntent{Version: 1, Tenant: ws.Tenant, SourceClusterID: ws.ClusterID, TargetClusterID: "obsolete-dr", SourceProvisionID: strings.Repeat("a", 32),
					Status: "ENROLLMENT_QUEUED", RequestedAt: time.Now().UTC(), EvidenceLabel: "NOT_RECOVERY_VERIFIED"}
				if err := publishZeroTouchDRIntent(ws, bad); err != nil {
					t.Fatal(err)
				}
				var err error
				original, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := portal.ConfigureRecovery(cfg); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if scenario == "UNKNOWN" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unqualified primary enrolled", err)
				}
			} else if err != nil || string(after) != string(original) {
				t.Fatal("unsafe preexisting journal changed", err)
			}
			if runner.applyCalls != 0 {
				t.Fatal("native KubeOne invoked from recovery configuration")
			}
		})
	}
}
