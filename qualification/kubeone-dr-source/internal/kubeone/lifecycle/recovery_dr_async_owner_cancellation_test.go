package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The manual endpoint intentionally persists a long-running restore after
// sending HTTP 202. The AUTOMATIC path must be bound to its DR leader's
// lifetime instead: cancellation before dispatch may record an UNKNOWN
// durable journal, but may not start a new potentially writable restore.
func TestDRAutomaticAsyncRestoreStopsWhenLeaderAlreadyLost(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("e", 32)
	x.fence(nonce, "FAILOVER", nil)
	ownerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	job, err := x.portal.dispatchDRTransitionOwned(
		context.Background(), ownerCtx, x.ws, "FAILOVER", nonce)
	if err != nil {
		t.Fatal("failed to record signed DR intent before async stop", err)
	}
	if job.Status != "RUNNING" {
		t.Fatal("signed restore intent was not journaled", job)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state, err := readDRTransition(x.ws)
		if err == nil && state.Status == "UNKNOWN" {
			x.runner.mu.Lock()
			restores := x.runner.restoreCalls
			x.runner.mu.Unlock()
			if restores != 0 {
				t.Fatalf("auto restore created %d workloads after leadership had been lost", restores)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("canceled automatic DR restore did not publish UNKNOWN for reconciliation")
}

// This composes the actual lease watchdog with an already dispatched async
// restore. The first verification GET is held only after the create response's
// exact UID has been durably recorded. Replacing the synthetic Lease holder
// must cancel that read and preserve UNKNOWN custody without a second mutation.
// Every runner below is inert; all journal and lock files belong to TempDir.
func TestDRAutomaticAsyncRestoreStopsAfterWatchdogLosesLease(t *testing.T) {
	x, local, leader, target := drWatchdogFixture(t)
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	var watchFailures <-chan error
	defer func() {
		cancelOwner()
		if watchFailures != nil {
			if err := waitDROwnerLossWatchdogStopped(watchFailures, 3*time.Second); err != nil {
				t.Error(err)
			}
		}
		if err := waitDROwnerLossExecutorReleased(x, target, 3*time.Second); err != nil {
			t.Error(err)
		}
		if err := local.Close(); err != nil {
			t.Error(err)
		}
	}()

	type observation struct {
		job       DRTransitionJob
		name, uid string
		err       error
	}
	observed := make(chan observation, 1)
	var restoreReadAttempts, createAttempts atomic.Int64
	base := x.runner
	forwardedRestoreReads := 0
	base.beforeRestoreRead = func(string) { forwardedRestoreReads++ }
	x.portal.Client.runner = drIdentityCommandRunner(func(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " create -f ") {
			createAttempts.Add(1)
		}
		if err := ctx.Err(); err != nil {
			return CommandResult{}, err
		}
		if !strings.Contains(joined, " get restores.velero.io ") {
			return base.Run(ctx, dir, binary, args, env)
		}
		if restoreReadAttempts.Add(1) != 1 {
			return CommandResult{}, errors.New("unexpected additional Restore verification read")
		}
		name := ""
		for i, arg := range args {
			if arg == "restores.velero.io" && i+1 < len(args) {
				name = args[i+1]
			}
		}
		job, err := readDRTransition(x.ws)
		base.mu.Lock()
		uid := base.restored[name].Metadata.UID
		base.mu.Unlock()
		observed <- observation{job: job, name: name, uid: uid, err: err}
		// Do not hold base.mu here: the real watchdog must be able to issue
		// its own inert Lease read and observe the foreign holder.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return CommandResult{}, ctx.Err()
		case <-timer.C:
			return CommandResult{}, errors.New("held Restore verification did not receive owner cancellation")
		}
	})

	watchFailures = startDRAutomationLeaseWatchdog(
		ownerCtx, cancelOwner, local, leader, x.ws, 5*time.Millisecond,
	)
	nonce := strings.Repeat("f", 32)
	x.fence(nonce, "FAILOVER", nil)
	accepted, err := x.portal.dispatchDRTransitionOwned(
		context.Background(), ownerCtx, x.ws, "FAILOVER", nonce,
	)
	if err != nil || accepted.Status != "RUNNING" {
		t.Fatalf("signed async restore was not admitted: status=%s err=%v", accepted.Status, err)
	}

	var beforeLoss observation
	select {
	case beforeLoss = <-observed:
	case <-time.After(3 * time.Second):
		t.Fatal("first Restore verification did not reach the post-create barrier")
	}
	if beforeLoss.err != nil || len(beforeLoss.job.Steps) != 2 {
		t.Fatalf("post-create durable journal is unavailable: %+v err=%v", beforeLoss.job, beforeLoss.err)
	}
	if beforeLoss.uid == "" || beforeLoss.job.ID != nonce ||
		beforeLoss.job.Status != "RUNNING" ||
		beforeLoss.job.RestoreIdentityVersion != drRestoreIdentityVersion ||
		beforeLoss.job.Steps[0].RestoreName != beforeLoss.name ||
		beforeLoss.job.Steps[0].RestoreUID != beforeLoss.uid ||
		beforeLoss.job.Steps[0].State != "SUBMITTED" ||
		beforeLoss.job.Steps[1].RestoreUID != "" ||
		beforeLoss.job.Steps[1].State != "PENDING" {
		t.Fatalf("leader-loss barrier preceded exact durable create custody: %+v", beforeLoss.job)
	}
	if err := leader.Check(ownerCtx); err != nil {
		t.Fatal("controller was not the valid owner before the injected loss", err)
	}

	// Change only the already-owned synthetic Lease. The watchdog's real
	// Renew path must detect this; the test does not call cancelOwner here.
	base.drKubeLeader.mu.Lock()
	holder := base.drKubeLeader.record.Spec.HolderIdentity
	if holder == leader.identity {
		base.drKubeLeader.record.Spec.HolderIdentity = "other-DR-controller"
	}
	base.drKubeLeader.mu.Unlock()
	if holder != leader.identity {
		t.Fatal("synthetic Lease holder changed before the intended fault")
	}
	select {
	case err, ok := <-watchFailures:
		if !ok || err == nil || !strings.Contains(err.Error(), "DR native Kubernetes leader renewal failed") {
			t.Fatalf("foreign holder did not fail the watchdog renewal: open=%v err=%v", ok, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog did not detect the foreign Lease holder")
	}
	select {
	case <-ownerCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("failed watchdog renewal did not cancel the async owner")
	}
	if err := waitDROwnerLossExecutorReleased(x, target, 3*time.Second); err != nil {
		t.Fatal(err)
	}

	stopped, err := readDRTransition(x.ws)
	if err != nil || len(stopped.Steps) != 2 {
		t.Fatalf("interrupted restore lost its readable journal: %+v err=%v", stopped, err)
	}
	if stopped.ID != nonce || stopped.Status != "UNKNOWN" || stopped.EvidenceLabel != "UNKNOWN" ||
		stopped.FenceEpoch != accepted.FenceEpoch ||
		stopped.FenceProofSHA256 != accepted.FenceProofSHA256 ||
		stopped.RecoveryProofSHA256 != "" ||
		stopped.Steps[0].State != "SUBMITTED" ||
		stopped.Steps[0].RestoreUID != beforeLoss.uid ||
		stopped.Steps[1].State != "PENDING" || stopped.Steps[1].RestoreUID != "" {
		t.Fatalf("owner loss discarded custody or promoted incomplete recovery: %+v", stopped)
	}
	beforeSteps, err := json.Marshal(beforeLoss.job.Steps)
	if err != nil {
		t.Fatal(err)
	}
	stoppedSteps, err := json.Marshal(stopped.Steps)
	if err != nil || !bytes.Equal(beforeSteps, stoppedSteps) {
		t.Fatal("owner loss changed the captured workload identities or advanced a pending step", err)
	}
	assertStoppedEffects := func() {
		t.Helper()
		base.mu.Lock()
		restores, modifiers, reads := base.restoreCalls, base.modifierCalls, forwardedRestoreReads
		base.mu.Unlock()
		if restores != 1 || modifiers != 0 || reads != 0 ||
			createAttempts.Load() != 1 || restoreReadAttempts.Load() != 1 {
			t.Fatalf("owner loss allowed further restore activity: restores=%d modifiers=%d forwarded_GETs=%d create_attempts=%d verification_attempts=%d",
				restores, modifiers, reads, createAttempts.Load(), restoreReadAttempts.Load())
		}
	}
	assertStoppedEffects()
	journalBeforeReplay, err := os.ReadFile(drTransitionPath(x.ws))
	if err != nil {
		t.Fatal(err)
	}

	// A fresh caller may read the same durable result, but neither the same
	// nonce nor a new signed nonce may replay the interrupted operation.
	replay := x.begin(nonce, "FAILOVER")
	if replay.Code != http.StatusAccepted {
		t.Fatalf("same-nonce result was not returned: HTTP %d %s", replay.Code, replay.Body.String())
	}
	var replayBody struct {
		Job DRTransitionJob `json:"job"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayBody); err != nil {
		t.Fatal(err)
	}
	replayedJSON, err := json.Marshal(replayBody.Job)
	if err != nil {
		t.Fatal(err)
	}
	stoppedJSON, err := json.Marshal(stopped)
	if err != nil || !bytes.Equal(replayedJSON, stoppedJSON) {
		t.Fatal("same-nonce response did not preserve the exact stored UNKNOWN result", err)
	}
	freshNonce := strings.Repeat("a", 32)
	x.fence(freshNonce, "FAILOVER", nil)
	rejected := x.begin(freshNonce, "FAILOVER")
	if rejected.Code != http.StatusConflict {
		t.Fatalf("fresh nonce bypassed interrupted-operation reconciliation: HTTP %d %s", rejected.Code, rejected.Body.String())
	}
	assertStoppedEffects()
	journalAfterReplay, err := os.ReadFile(drTransitionPath(x.ws))
	if err != nil || !bytes.Equal(journalBeforeReplay, journalAfterReplay) {
		t.Fatal("replay attempts changed the interrupted-operation journal", err)
	}
}

// The executor clears its running flags just before its deferred operation
// locks close. Acquire and release both fixture locks to observe that final
// boundary before a replay assertion or TempDir cleanup; flags alone can race.
func waitDROwnerLossExecutorReleased(x *drTestSite, target Workspace, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		x.portal.mu.Lock()
		running := x.portal.running[registryKey(x.ws.Tenant, x.ws.ClusterID)] ||
			x.portal.running[registryKey(target.Tenant, target.ClusterID)]
		x.portal.mu.Unlock()
		if !running {
			first, err := lockRecoveryWorkspace(x.ws)
			if err == nil {
				second, secondErr := lockRecoveryWorkspace(target)
				if secondErr == nil {
					secondClose := second.Close()
					firstClose := first.Close()
					return errors.Join(secondClose, firstClose)
				}
				if err := first.Close(); err != nil {
					return err
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("async DR executor did not release both fixture operation locks within %s", timeout)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitDROwnerLossWatchdogStopped(failures <-chan error, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case _, open := <-failures:
			if !open {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("DR lease watchdog did not stop within %s", timeout)
		}
	}
}
