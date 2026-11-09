package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The shared synthetic runner supplies native-shaped responses but does not
// reject canceled contexts. This test-only wrapper models ExecRunner's
// cancellation boundary without launching a command or reading live resources.
type drAdmissionContextRunner struct {
	Runner
	beforeBackup        func()
	backupOnce          sync.Once
	canceledCalls       atomic.Int64
	canceledBackupCalls atomic.Int64
}

func (r *drAdmissionContextRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	backupRead := strings.Contains(strings.Join(args, " "), "get backups.velero.io ")
	if backupRead {
		r.backupOnce.Do(func() {
			if r.beforeBackup != nil {
				r.beforeBackup()
			}
		})
	}
	if err := ctx.Err(); err != nil {
		r.canceledCalls.Add(1)
		if backupRead {
			r.canceledBackupCalls.Add(1)
		}
		return CommandResult{}, err
	}
	return r.Runner.Run(ctx, dir, binary, args, env)
}

func TestDRAdmissionContextSurvivesTargetHealth(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("9", 32)
	x.fence(nonce, "FAILOVER", nil)
	runner := &drAdmissionContextRunner{Runner: x.runner}
	x.portal.Client.runner = runner

	rec := x.begin(nonce, "FAILOVER")
	if rec.Code != http.StatusAccepted {
		x.runner.mu.Lock()
		restores, modifiers := x.runner.restoreCalls, x.runner.modifierCalls
		x.runner.mu.Unlock()
		t.Fatalf("healthy target rejected before restore: status=%d canceled_commands=%d canceled_backup_reads=%d restores=%d modifiers=%d body=%s",
			rec.Code, runner.canceledCalls.Load(), runner.canceledBackupCalls.Load(), restores, modifiers, rec.Body.String())
	}
	job := x.waitRestore(nonce)
	x.runner.mu.Lock()
	restores := x.runner.restoreCalls
	x.runner.mu.Unlock()
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
		job.EvidenceLabel != "UNKNOWN" || restores != len(x.config.Workloads) {
		t.Fatalf("context-aware restore did not reach the unpromoted app-verification boundary: status=%s evidence=%s restores=%d",
			job.Status, job.EvidenceLabel, restores)
	}
	if runner.canceledCalls.Load() != 0 {
		t.Fatal("a completed health check canceled subsequent admission or restore commands")
	}
}

func TestDRAdmissionContextCancellationStopsBeforeIntent(t *testing.T) {
	for _, stage := range []string{"before_health", "before_backup"} {
		t.Run(stage, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("8", 32)
			x.fence(nonce, "FAILOVER", nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &drAdmissionContextRunner{Runner: x.runner}
			x.portal.Client.runner = runner
			if stage == "before_health" {
				cancel()
			} else {
				// Cancel the caller after the healthy target readback and
				// immediately before its first backup read is executed.
				runner.beforeBackup = cancel
			}

			job, err := x.portal.dispatchDRTransition(ctx, x.ws, "FAILOVER", nonce)
			if err == nil {
				x.waitRestore(job.ID)
				t.Fatal("canceled caller admitted a durable restore intent")
			}
			if drActionStatus(err) != http.StatusConflict {
				t.Fatal("canceled admission did not return the fixed conflict status")
			}
			if _, err := os.Lstat(drTransitionPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canceled admission created a restore journal: %v", err)
			}
			x.runner.mu.Lock()
			restores, modifiers, backups := x.runner.restoreCalls, x.runner.modifierCalls, x.runner.backupReads
			x.runner.mu.Unlock()
			if restores != 0 || modifiers != 0 || backups != 0 {
				t.Fatalf("canceled admission reached a native operation: restores=%d modifiers=%d backups=%d",
					restores, modifiers, backups)
			}
			if stage == "before_health" {
				// Canceled requests now fail at the explicit admission
				// boundary, before any native command is attempted.
				if runner.canceledCalls.Load() != 0 || runner.canceledBackupCalls.Load() != 0 {
					t.Fatal("pre-canceled admission reached a native command")
				}
			} else if runner.canceledCalls.Load() != 1 || runner.canceledBackupCalls.Load() != 1 {
				t.Fatal("cancellation during native backup admission was not preserved")
			}
		})
	}
}
