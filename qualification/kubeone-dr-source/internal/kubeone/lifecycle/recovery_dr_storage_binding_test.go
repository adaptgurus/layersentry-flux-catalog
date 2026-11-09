package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// A syntactically valid but non-existent/revoked opaque reference must not
// generate any signed DR restore intent or native Kubernetes Restore.
func TestDRStorageCredentialBindingRejectsMissingRevokedAndWrongLocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*drTestSite)
	}{
		{"no_provider_adapter", func(x *drTestSite) { x.portal.recovery.storageBindingVerifier = nil }},
		{"revoked_or_missing_reference", func(x *drTestSite) {
			for i := range x.config.Workloads {
				x.config.Workloads[i].ManagedCredentialRef = "revoked-managed-ref"
			}
			x.portal.recovery.config.DRExecutions[0] = x.config
		}},
		{"wrong_bsl", func(x *drTestSite) {
			for i := range x.config.Workloads {
				x.config.Workloads[i].StorageLocation = "other-s3"
			}
			x.portal.recovery.config.DRExecutions[0] = x.config
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			tc.change(x)
			if err := x.portal.recovery.config.Validate(); err != nil {
				t.Fatal("syntactically valid registration rejected before verifier", err)
			}
			nonce := strings.Repeat("7", 32)
			x.fence(nonce, "FAILOVER", nil)
			r := x.begin(nonce, "FAILOVER")
			if r.Code != http.StatusConflict {
				t.Fatalf("unqualified storage admitted: %d %s", r.Code, r.Body.String())
			}
			if x.runner.restoreCalls != 0 || x.runner.modifierCalls != 0 {
				t.Fatal("unqualified storage caused restore mutation")
			}
			if _, err := os.Lstat(drTransitionPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unqualified storage created durable restore intent: %v", err)
			}
			assertNoDRFenceIntentFixture(t, x)
		})
	}
}

// Automatic mode must reject unbound storage BEFORE the non-authoritative
// fencing request is written. Only its status record is allowed to change.
func TestDRAutomationStorageBindingBlocksBeforeFenceIntent(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	x.portal.recovery.storageBindingVerifier = nil
	target, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	state := AutoDRStatus{ClusterID: x.ws.ClusterID, TargetClusterID: target.ClusterID, ObservedAt: time.Now().UTC()}
	if err := x.portal.automaticDRStart(context.Background(), a, x.ws, target, DRTransitionJob{}, "FAILOVER", &state); err != nil {
		t.Fatal(err)
	}
	if state.State != "STORAGE_CREDENTIAL_NOT_QUALIFIED" {
		t.Fatalf("unbound storage did not stop automation: %+v", state)
	}
	assertNoDRFenceIntentFixture(t, x)
	if _, err := os.Lstat(drTransitionPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DR restore started despite missing storage auth binding: %v", err)
	}
	if x.runner.restoreCalls != 0 || x.runner.modifierCalls != 0 {
		t.Fatal("native mutation occurred without qualified storage")
	}
}
