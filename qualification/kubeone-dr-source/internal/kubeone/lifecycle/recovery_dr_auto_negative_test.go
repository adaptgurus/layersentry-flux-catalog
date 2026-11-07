package lifecycle

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func autoDRSustainedOutage(t *testing.T, x *drTestSite, a DRAutomationPolicy, state *AutoDRStatus) {
	t.Helper()
	x.runner.mu.Lock()
	x.runner.sourceDown = true
	x.runner.mu.Unlock()
	for i := 0; i < a.SourceFailureChecks+1; i++ {
		automaticDRTickFixture(t, x, a, state)
	}
}

// A journal that cannot be parsed after a coordinator restart must never be
// treated as "no previous operation": automatic recovery stops and requires
// human reconciliation, with no fencing request and no Kubernetes restore.
func TestDRAutomationRefusesRestartOnAmbiguousJournal(t *testing.T) {
	for _, fault := range []string{"truncated", "unknown-field", "foreign-cluster"} {
		t.Run(fault, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			body := map[string]string{
				"truncated":       `{"id":"` + strings.Repeat("1", 32),
				"unknown-field":   `{"id":"` + strings.Repeat("1", 32) + `","status":"VERIFIED","unexpected":true}`,
				"foreign-cluster": `{"id":"` + strings.Repeat("1", 32) + `","cluster_id":"cluster-other","direction":"FAILOVER","status":"VERIFIED"}`,
			}[fault]
			if err := os.WriteFile(drTransitionPath(x.ws), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			x.runner.mu.Lock()
			x.runner.sourceDown = true
			x.runner.mu.Unlock()
			dest, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
			if err != nil {
				t.Fatal(err)
			}
			state := AutoDRStatus{}
			for i := 0; i < a.SourceFailureChecks+1; i++ {
				err = x.portal.automaticDRTick(context.Background(), a, x.ws, dest, &state)
				if err == nil || state.State != "AMBIGUOUS_TRANSITION" {
					t.Fatalf("ambiguous journal did not stop automation: err=%v state=%+v", err, state)
				}
			}
			if _, err := os.Lstat(autoDRFenceIntentPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("ambiguous journal produced a fencing request")
			}
			if x.runner.restoreCalls != 0 {
				t.Fatal("ambiguous journal started a restore", x.runner.restoreCalls)
			}
			if raw, _ := os.ReadFile(drTransitionPath(x.ws)); string(raw) != body {
				t.Fatal("automation rewrote the ambiguous journal")
			}
		})
	}
}

// A crash during restore (journal left RUNNING) or an UNKNOWN restore outcome
// must not be automatically replayed even when the DC outage persists.
func TestDRAutomationNeverReplaysUnreconciledRestore(t *testing.T) {
	for _, status := range []string{"UNKNOWN", "RUNNING"} {
		t.Run(status, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			nonce := strings.Repeat("2", 32)
			x.fence(nonce, "FAILOVER", nil)
			if status == "UNKNOWN" {
				x.runner.mu.Lock()
				x.runner.failRestore = true
				x.runner.mu.Unlock()
			}
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatalf("setup: %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			if status == "RUNNING" {
				// Simulate process loss between durable RUNNING publication and
				// the asynchronous executor's outcome write.
				job.Status, job.EvidenceLabel = "RUNNING", "UNKNOWN"
				if err := writeBoundedJob(x.ws, drTransitionPath(x.ws), ".layersentry-kubeone-dr-transition-*.tmp", job); err != nil {
					t.Fatal(err)
				}
			} else if job.Status != "UNKNOWN" {
				t.Fatal("restore failure was not recorded UNKNOWN", job)
			}
			calls := x.runner.restoreCalls
			state := AutoDRStatus{}
			autoDRSustainedOutage(t, x, a, &state)
			if state.State != "UNRECONCILED_OPERATION" || x.runner.restoreCalls != calls {
				t.Fatalf("unreconciled restore replayed: %+v calls=%d->%d", state, calls, x.runner.restoreCalls)
			}
			if _, err := os.Lstat(autoDRFenceIntentPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unreconciled journal produced a new fencing request")
			}
			if got, err := readDRTransition(x.ws); err != nil || got.ID != nonce || got.Status != status {
				t.Fatal("unreconciled journal mutated", err, got)
			}
		})
	}
}

// Failback must present a NEW, higher fencing generation. Re-using the
// failover epoch (or any lower epoch) under the reverse nonce is refused
// without touching Kubernetes.
func TestDRAutomationFailbackRefusesReusedFenceEpoch(t *testing.T) {
	for _, epoch := range []uint64{55, 54, 1} {
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
		x.completion(x.waitRestore(intent.OperationID), nil)
		automaticDRTickFixture(t, x, a, &state)
		verified, err := readDRTransition(x.ws)
		if err != nil || verified.Status != "VERIFIED" || verified.FenceEpoch != 55 {
			t.Fatal("setup failover", err, verified)
		}
		x.runner.mu.Lock()
		x.runner.sourceDown = false
		x.runner.backupUID = strings.Repeat("c", 36)
		x.runner.backupStartedAt = verified.UpdatedAt.Add(time.Second)
		x.runner.mu.Unlock()
		for i := 0; i < a.FailbackHealthyChecks; i++ {
			automaticDRTickFixture(t, x, a, &state)
		}
		state.SourceHealthySince = time.Now().UTC().Add(-time.Duration(a.FailbackHoldSeconds+1) * time.Second)
		automaticDRTickFixture(t, x, a, &state)
		reverse, err := readAutoDRFenceIntent(x.ws)
		if err != nil || reverse.Direction != "FAILBACK" || reverse.MinimumFenceEpoch != 56 {
			t.Fatal("reverse intent", err, reverse)
		}
		calls := x.runner.restoreCalls
		x.fence(reverse.OperationID, "FAILBACK", func(p *DRFenceProof) { p.FenceEpoch = epoch })
		automaticDRTickFixture(t, x, a, &state)
		if state.State != "AWAITING_CORRECT_FENCING_EPOCH" || x.runner.restoreCalls != calls {
			t.Fatalf("epoch %d reused for failback: %+v calls=%d", epoch, state, x.runner.restoreCalls)
		}
		if j, err := readDRTransition(x.ws); err != nil || j.Direction != "FAILOVER" || j.Status != "VERIFIED" {
			t.Fatal("refused failback mutated journal", err, j)
		}
	}
}

// Automatic promotion re-checks the current physical fence AFTER restore. If
// the fencer's short lease lapses (old writer may be back), a valid
// application/route proof alone must not promote the DR writer.
func TestDRAutomationCompletionWaitsForCurrentFence(t *testing.T) {
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
	x.fence(intent.OperationID, "FAILOVER", func(p *DRFenceProof) {
		p.IssuedAt = time.Now().UTC().Add(-4 * time.Minute)
		p.ExpiresAt = time.Now().UTC().Add(-time.Second)
	})
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "WAITING_FOR_CURRENT_FENCE" {
		t.Fatalf("lapsed fence did not block automatic promotion: %+v", state)
	}
	if j, err := readDRTransition(x.ws); err != nil || j.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("journal promoted without current fence", err, j)
	}
	// The fencer re-affirms the same epoch: promotion may now proceed.
	x.fence(intent.OperationID, "FAILOVER", nil)
	x.completion(job, nil)
	automaticDRTickFixture(t, x, a, &state)
	if j, err := readDRTransition(x.ws); err != nil || j.Status != "VERIFIED" || state.State != "DR_ACTIVE" {
		t.Fatal("reaffirmed fence did not permit promotion", err, j, state)
	}
}

// A legacy signed application proof with an RPO integer but no committed
// transaction reference may be manually reviewed; it must never promote the
// automatic DR writer, even when the original source API is unreachable.
func TestDRAutomationRefusesLegacyRPOWithoutApplicationWatermark(t *testing.T) {
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
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("expected restored-but-unpromoted DR", job)
	}
	x.completion(job, func(v *DRCompletionProof) {
		v.Version = 1
		v.LastRecoverableWriteAt = time.Time{}
		v.FailureObservedAt = time.Time{}
		v.RecoveryWatermark = ""
	})
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "RECOVERY_WATERMARK_PENDING" {
		t.Fatalf("legacy unmeasured RPO accepted for automatic promotion: %+v", state)
	}
	observed, err := readDRTransition(x.ws)
	if err != nil || observed.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("legacy receipt unexpectedly promoted the DR writer", err, observed)
	}
}

// A completed Velero Restore plus even a freshly signed app/PVC/route proof
// cannot promote a writer if the DR Kubernetes API loses quorum between
// restore observation and final promotion. This reproduces the fail-closed
// decision required by the original live NAS/etcd incident (#239), but uses
// only the isolated fake native runner and temporary test workspace: no NAS/VM effects.
func TestDRAutomationCompletionRequiresTargetQuorumAfterRestore(t *testing.T) {
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
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatalf("unexpected restore phase before quorum regression: %+v", job)
	}
	x.completion(job, nil)
	restoreCalls := x.runner.restoreCalls

	x.runner.mu.Lock()
	x.runner.drDown = true
	x.runner.mu.Unlock()
	for sample := 0; sample < 2; sample++ {
		automaticDRTickFixture(t, x, a, &state)
		if state.State != "RECOVERY_VERIFICATION_PENDING" {
			t.Fatalf("DR API unavailable but promotion was not blocked: sample=%d %+v", sample, state)
		}
		held, err := readDRTransition(x.ws)
		if err != nil || held.ID != job.ID || held.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
			t.Fatalf("DR quorum loss incorrectly committed a writer: sample=%d err=%v job=%+v", sample, err, held)
		}
		if x.runner.restoreCalls != restoreCalls {
			t.Fatal("DR quorum loss retried restore or created another writer")
		}
	}

	// A repaired API alone does not sign a new receipt: this next transition
	// may complete only because the *original*, still-valid independent
	// fence and application/PVC/route proof remain cryptographically pinned.
	x.runner.mu.Lock()
	x.runner.drDown = false
	x.runner.mu.Unlock()
	automaticDRTickFixture(t, x, a, &state)
	verified, err := readDRTransition(x.ws)
	if err != nil || verified.Status != "VERIFIED" || verified.Direction != "FAILOVER" ||
		state.State != "DR_ACTIVE" || x.runner.restoreCalls != restoreCalls {
		t.Fatalf("repaired simulated quorum did not reconcile same signed operation: err=%v job=%+v state=%+v", err, verified, state)
	}
}

// A target can lose just one worker AFTER a signed, observed restore, while
// /readyz, all three control planes, kube-system, PVC and signed app proof
// remain healthy. Automatic VERIFIED would violate the same all-node baseline
// required at DR admission. Exercise both DR and repaired-DC restore targets.
// Only test-owned workspaces, fake native output, and ephemeral test signers.
func TestDRAutomationFinalPromotionBlocksWorkerDeficitInBothDirections(t *testing.T) {
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
	forwardJob := x.waitRestore(forward.OperationID)
	if forwardJob.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("forward restore was not observed", forwardJob)
	}
	x.completion(forwardJob, nil)
	calls := x.runner.restoreCalls

	// Simulate the real operator's 3/4-ready test baseline: only the DR
	// worker is down, not the API, any CP, kube-system or signed proof.
	x.runner.mu.Lock()
	x.runner.workerUnreadySite = "cluster-dr"
	x.runner.mu.Unlock()
	dr, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	health, err := x.portal.Client.Status(context.Background(), dr)
	if err != nil || !health.APIReady || health.ReadyControlPlanes != dr.ExpectedCPNodes ||
		health.ReadyNodes != dr.ExpectedNodes-1 || health.KubeSystemNonReady != 0 {
		t.Fatalf("simulated DR worker deficit did not preserve CP health: err=%v health=%+v", err, health)
	}
	automaticDRTickFixture(t, x, a, &state)
	held, err := readDRTransition(x.ws)
	if err != nil || held.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
		state.State != "RECOVERY_VERIFICATION_PENDING" || x.runner.restoreCalls != calls {
		t.Fatalf("automatic DR promoted despite lost worker: err=%v job=%+v state=%+v", err, held, state)
	}
	x.runner.mu.Lock()
	x.runner.workerUnreadySite = ""
	x.runner.mu.Unlock()
	automaticDRTickFixture(t, x, a, &state)
	verified, err := readDRTransition(x.ws)
	if err != nil || verified.Status != "VERIFIED" || state.State != "DR_ACTIVE" {
		t.Fatalf("restored DR baseline failed to reconcile original signed proof: err=%v job=%+v state=%+v", err, verified, state)
	}

	// Repaired original DC becomes the restore TARGET for reverse transfer.
	x.runner.mu.Lock()
	x.runner.sourceDown = false
	x.runner.backupUID = strings.Repeat("c", 36)
	x.runner.backupStartedAt = verified.UpdatedAt.Add(time.Second)
	x.runner.mu.Unlock()
	for i := 0; i < a.FailbackHealthyChecks; i++ {
		automaticDRTickFixture(t, x, a, &state)
	}
	state.SourceHealthySince = time.Now().UTC().Add(-time.Duration(a.FailbackHoldSeconds+1) * time.Second)
	automaticDRTickFixture(t, x, a, &state)
	reverse, err := readAutoDRFenceIntent(x.ws)
	if err != nil || reverse.Direction != "FAILBACK" || reverse.MinimumFenceEpoch <= verified.FenceEpoch {
		t.Fatalf("reverse fencing intent absent: err=%v intent=%+v", err, reverse)
	}
	x.fence(reverse.OperationID, "FAILBACK", nil)
	automaticDRTickFixture(t, x, a, &state)
	reverseJob := x.waitRestore(reverse.OperationID)
	if reverseJob.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("reverse restore was not observed", reverseJob)
	}
	x.completion(reverseJob, nil)
	calls = x.runner.restoreCalls
	x.runner.mu.Lock()
	x.runner.workerUnreadySite = "cluster-a"
	x.runner.mu.Unlock()
	health, err = x.portal.Client.Status(context.Background(), x.ws)
	if err != nil || !health.APIReady || health.ReadyControlPlanes != x.ws.ExpectedCPNodes ||
		health.ReadyNodes != x.ws.ExpectedNodes-1 || health.KubeSystemNonReady != 0 {
		t.Fatalf("simulated DC worker deficit did not preserve CP health: err=%v health=%+v", err, health)
	}
	automaticDRTickFixture(t, x, a, &state)
	held, err = readDRTransition(x.ws)
	if err != nil || held.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
		state.State != "RECOVERY_VERIFICATION_PENDING" || x.runner.restoreCalls != calls {
		t.Fatalf("automatic failback promoted with lost original DC worker: err=%v job=%+v state=%+v", err, held, state)
	}
	x.runner.mu.Lock()
	x.runner.workerUnreadySite = ""
	x.runner.mu.Unlock()
	automaticDRTickFixture(t, x, a, &state)
	final, err := readDRTransition(x.ws)
	if err != nil || final.Status != "VERIFIED" || final.Direction != "FAILBACK" ||
		state.State != "DC_ACTIVE" || x.runner.restoreCalls != calls {
		t.Fatalf("repaired DC baseline failed to reconcile reverse signed proof: err=%v job=%+v state=%+v", err, final, state)
	}
}
