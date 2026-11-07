package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The signed fence is checked before target Kubernetes/PVC reads. The
// external physical fencing authority may revoke or change that fence before
// the transition is finally committed, so check the SAME epoch and lineage
// again after native readback. This is a fake-runner test, not a live fencer.
func TestDRCompletionRejectsFenceChangedDuringPVCReadback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*DRFenceProof)
	}{
		{"fence_epoch_changed", func(v *DRFenceProof) { v.FenceEpoch++ }},
		{"fence_lease_expired", func(v *DRFenceProof) {
			v.IssuedAt = time.Now().UTC().Add(-4 * time.Minute)
			v.ExpiresAt = time.Now().UTC().Add(-time.Second)
		}},
		{"fenced_backup_uid_changed", func(v *DRFenceProof) {
			v.Workloads[1].BackupUID = strings.Repeat("f", 36)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("7", 32)
			x.fence(nonce, "FAILOVER", nil)
			if response := x.begin(nonce, "FAILOVER"); response.Code != 202 {
				t.Fatalf("could not stage restore: %d %s", response.Code, response.Body.String())
			}
			job := x.waitRestore(nonce)
			if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatalf("expected unpromoted restore: %+v", job)
			}
			x.completion(job, nil)
			proof, digest, err := verifiedDRCompletion(x.config, job, time.Now().UTC())
			if err != nil || proof.Version != 2 {
				t.Fatal("initial signed proof invalid", err)
			}
			x.runner.mu.Lock()
			x.runner.onRecoveredPVCRead = func() { x.fence(nonce, "FAILOVER", tc.change) }
			x.runner.mu.Unlock()
			if _, err := x.portal.finalizeDRTransitionWithProof(context.Background(), x.ws, digest, 300); err == nil {
				t.Fatal("revoked/changed independently signed fence accepted after PVC readback")
			}
			state, err := readDRTransition(x.ws)
			if err != nil || state.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || state.RecoveryProofSHA256 != "" {
				t.Fatalf("revoked fence must not promote journal: %+v err=%v", state, err)
			}
		})
	}
}
