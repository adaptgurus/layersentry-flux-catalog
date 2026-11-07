package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A signed fence which expires almost immediately is not authority to
// publish a new writable DR epoch. The finalizer's native PVC readbacks and
// durable commit need a nonzero safety margin for external lease renewal.
func TestDRCompletionRejectsNearExpiryFenceLease(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("d", 32)
	x.fence(nonce, "FAILOVER", nil)
	if resp := x.begin(nonce, "FAILOVER"); resp.Code != 202 {
		t.Fatal(resp.Code, resp.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal(job.Status)
	}
	x.completion(job, nil)
	_, digest, err := verifiedDRCompletion(x.config, job, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	x.fence(nonce, "FAILOVER", func(v *DRFenceProof) {
		v.ExpiresAt = time.Now().UTC().Add(10 * time.Second)
	})
	if _, err := x.portal.finalizeDRTransitionWithProof(context.Background(), x.ws, digest, 300); err == nil {
		t.Fatal("nearly expired source-writer fence accepted at new DR writer promotion")
	}
	recorded, err := readDRTransition(x.ws)
	if err != nil || recorded.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("expired-before-rollout fence advanced durable recovery", recorded, err)
	}
}

// Previously VERIFIED is historical journal evidence, not current fencing.
// Automatic coordinator must withdraw its green active status (without
// assuming it can turn off traffic itself) whenever the independent physical
// source-writer exclusion can no longer be reverified.
func TestDRAutomationActiveFenceRevocationStopsTransitions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*DRFenceProof)
	}{
		{"lease_expired", func(p *DRFenceProof) {
			p.IssuedAt = time.Now().UTC().Add(-4 * time.Minute)
			p.ExpiresAt = time.Now().UTC().Add(-time.Second)
		}},
		{"wrong_epoch", func(p *DRFenceProof) { p.FenceEpoch++ }},
		{"wrong_backup_uid", func(p *DRFenceProof) { p.Workloads[1].BackupUID = strings.Repeat("f", 36) }},
		{"margin_too_short", func(p *DRFenceProof) { p.ExpiresAt = time.Now().UTC().Add(10 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			state := AutoDRStatus{}
			autoDRSustainedOutage(t, x, a, &state)
			intent, err := readAutoDRFenceIntent(x.ws)
			if err != nil {
				t.Fatal(err)
			}
			x.fence(intent.OperationID, "FAILOVER", nil)
			automaticDRTickFixture(t, x, a, &state)
			job := x.waitRestore(intent.OperationID)
			x.completion(job, nil)
			automaticDRTickFixture(t, x, a, &state)
			if state.State != "DR_ACTIVE" {
				t.Fatalf("fixture did not establish signed DR: %+v", state)
			}
			calls := x.runner.restoreCalls
			x.fence(intent.OperationID, "FAILOVER", tc.revoke)
			automaticDRTickFixture(t, x, a, &state)
			if state.State != "ACTIVE_FENCE_RECHECK_REQUIRED" {
				t.Fatalf("current physical fencing lost, but controller reports active: %+v", state)
			}
			if calls != x.runner.restoreCalls {
				t.Fatal("unverified active fence triggered a new restore")
			}
			old, err := readDRTransition(x.ws)
			if err != nil || old.Status != "VERIFIED" {
				t.Fatal("historical recovery journal was overwritten to hide custody loss", old, err)
			}
			// A subsequent genuine same-operation signed reaffirmation,
			// not a coordinator-issued fence, permits monitoring again.
			x.fence(intent.OperationID, "FAILOVER", nil)
			automaticDRTickFixture(t, x, a, &state)
			if state.State != "WAITING_FOR_STABLE_PRIMARY" {
				t.Fatalf("fresh independent same-epoch fence did not restore guarded failback monitoring: %+v", state)
			}
		})
	}
}

func TestDRAutomationPreviouslyVerifiedTargetOutageIsNotGreen(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	autoDRSustainedOutage(t, x, a, &state)
	intent, err := readAutoDRFenceIntent(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	x.fence(intent.OperationID, "FAILOVER", nil)
	automaticDRTickFixture(t, x, a, &state)
	job := x.waitRestore(intent.OperationID)
	x.completion(job, nil)
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "DR_ACTIVE" {
		t.Fatal("fixture missing verified DR", state)
	}
	calls := x.runner.restoreCalls
	x.runner.mu.Lock()
	x.runner.drDown = true
	x.runner.mu.Unlock()
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "ACTIVE_DR_SITE_UNHEALTHY" {
		t.Fatalf("unavailable active DR controller incorrectly reported healthy/ready: %+v", state)
	}
	if x.runner.restoreCalls != calls {
		t.Fatal("unhealthy DR triggered another restore")
	}
	persisted, err := readDRTransition(x.ws)
	if err != nil || persisted.Status != "VERIFIED" {
		t.Fatal("temporary health outage corrupted historical verified receipt", persisted, err)
	}
	x.runner.mu.Lock()
	x.runner.drDown = false
	x.runner.mu.Unlock()
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "WAITING_FOR_STABLE_PRIMARY" {
		t.Fatalf("healthy site failed to resume correctly guarded monitoring: %+v", state)
	}
}
