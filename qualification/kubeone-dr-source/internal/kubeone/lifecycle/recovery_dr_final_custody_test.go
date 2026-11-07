package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Losing the distributed controller Lease after the final PVC read must
// still prevent historical data from becoming a new writable DR epoch.
// Signed app and physical fence proofs are necessary, not sufficient:
// the automatic caller's ownership context must remain alive at publish.
func TestDRCompletionRejectsOwnerCancellationAfterPVCReadback(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("e", 32)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x.runner.mu.Lock()
	x.runner.onRecoveredPVCRead = func() { cancel() }
	x.runner.mu.Unlock()
	if _, err := x.portal.finalizeDRTransitionWithProof(ctx, x.ws, digest, 300); err == nil {
		t.Fatal("canceled automatic owner published VERIFIED despite losing leader during PVC verification")
	}
	state, err := readDRTransition(x.ws)
	if err != nil || state.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("lost leader promoted DR anyway", state, err)
	}
}

// A durable fencing INTENT is unsigned. It may request a fresh reverse
// fencing receipt but cannot replace the currently signed forward fence
// until a valid, separately signed reverse receipt for the exact nonce
// and strictly newer epoch has actually been enrolled.
func TestDRUnsignedReverseIntentNeverBypassesActiveFence(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	autoDRSustainedOutage(t, x, a, &state)
	forward, err := readAutoDRFenceIntent(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	x.fence(forward.OperationID, "FAILOVER", nil)
	automaticDRTickFixture(t, x, a, &state)
	job := x.waitRestore(forward.OperationID)
	x.completion(job, nil)
	automaticDRTickFixture(t, x, a, &state)
	prior, err := readDRTransition(x.ws)
	if err != nil || prior.Status != "VERIFIED" || state.State != "DR_ACTIVE" {
		t.Fatal("precondition missing signed forward recovery", prior, state, err)
	}
	reverse, err := ensureDRAutomationFenceIntent(x.ws, a, prior, "FAILBACK", state, time.Now().UTC())
	if err != nil || reverse.MinimumFenceEpoch <= prior.FenceEpoch {
		t.Fatal(err, reverse)
	}
	previousCalls := x.runner.restoreCalls
	x.fence(forward.OperationID, "FAILOVER", func(p *DRFenceProof) {
		p.ExpiresAt = time.Now().UTC().Add(-time.Second)
	})
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "ACTIVE_FENCE_RECHECK_REQUIRED" {
		t.Fatalf("unsigned reverse request replaced current independent writer fence: %+v", state)
	}
	if x.runner.restoreCalls != previousCalls {
		t.Fatal("unsigned request triggered restore")
	}
	x.fence(reverse.OperationID, "FAILBACK", nil)
	automaticDRTickFixture(t, x, a, &state)
	if state.State == "ACTIVE_FENCE_RECHECK_REQUIRED" {
		t.Fatal("valid NEW reverse signer receipt could not avoid circular old-fence gate")
	}
}

// The API health reads can consume seconds. The fence must be checked with a
// new timestamp AFTER those reads; tick-start time is not current authority.
func TestDRActiveFenceRecheckedAfterSlowKubernetesHealthReads(t *testing.T) {
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
		t.Fatal("fixture lacks verified signed DR", state)
	}
	x.fence(intent.OperationID, "FAILOVER", func(v *DRFenceProof) {
		v.ExpiresAt = time.Now().UTC().Add(33 * time.Second)
	})
	x.runner.mu.Lock()
	x.runner.healthReadDelay = 2 * time.Second
	x.runner.mu.Unlock()
	started := time.Now()
	automaticDRTickFixture(t, x, a, &state)
	if time.Since(started) < 4*time.Second {
		t.Fatal("fake slow health-read precondition was not satisfied")
	}
	if state.State != "ACTIVE_FENCE_RECHECK_REQUIRED" {
		t.Fatalf("stale tick-start wall clock authorized physical source fence with under 30s left: %+v", state)
	}
}
