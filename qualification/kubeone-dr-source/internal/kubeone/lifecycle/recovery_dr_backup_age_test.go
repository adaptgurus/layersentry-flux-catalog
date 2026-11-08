package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDRAutomationBackupAgeUsesCompletedObservations(t *testing.T) {
	const maxAge = 60 * time.Second
	for _, tc := range []struct {
		name          string
		delayedRecord int
		stale         bool
	}{
		{"response_expired_during_read", 0, true},
		{"earlier_backup_expired_during_later_read", 1, true},
		{"fresh_backups_after_delayed_read", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			a.MaxBackupAgeSeconds = int(maxAge / time.Second)
			x.portal.recovery.config.DRAutomation = []DRAutomationPolicy{a}
			if err := x.portal.recovery.config.Validate(); err != nil {
				t.Fatalf("registered 60-second backup-age policy is invalid: %v", err)
			}
			state := AutoDRStatus{}
			autoDRSustainedOutage(t, x, a, &state)
			intent, err := readAutoDRFenceIntent(x.ws)
			if err != nil {
				t.Fatal(err)
			}
			x.fence(intent.OperationID, "FAILOVER", nil)
			target, err := x.portal.Client.Workspace(a.Tenant, a.TargetClusterID)
			if err != nil {
				t.Fatal(err)
			}

			// Fix completion timestamps once and retain them across admission
			// and async readbacks. Only a test response is delayed; no production
			// clock hook or live command is used.
			firstName := x.config.Workloads[0].BackupName
			delayName := x.config.Workloads[tc.delayedRecord].BackupName
			completions := make(map[string]time.Time)
			var observeOnce, delayOnce sync.Once
			var observedAt, releaseAt, delayedResponseAt time.Time
			var delayErr error
			x.portal.Client.runner = drIdentityCommandRunner(func(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
				if err := ctx.Err(); err != nil {
					return CommandResult{}, err
				}
				out, err := x.runner.Run(ctx, dir, binary, args, env)
				if err != nil || !strings.Contains(strings.Join(args, " "), "get backups.velero.io ") {
					return out, err
				}
				var backup nativeVeleroBackup
				if err := json.Unmarshal([]byte(out.Stdout), &backup); err != nil {
					return CommandResult{}, err
				}
				observeOnce.Do(func() {
					observedAt = time.Now().UTC()
					for _, workload := range x.config.Workloads {
						completions[workload.BackupName] = observedAt.Add(-5 * time.Second)
					}
					releaseAt = observedAt.Add(2 * time.Second)
					if tc.stale {
						completions[firstName] = observedAt.Add(-(maxAge - time.Second))
						// Hold until one full second beyond the valid cutoff,
						// normally two seconds from the initial observation.
						releaseAt = completions[firstName].Add(maxAge + time.Second)
					}
				})
				completed, ok := completions[backup.Metadata.Name]
				if !ok {
					return CommandResult{}, errors.New("unexpected synthetic backup identity")
				}
				backup.Status.CompletionTimestamp = completed
				backup.Status.StartTimestamp = completed.Add(-time.Second)
				if backup.Metadata.Name == delayName {
					delayOnce.Do(func() {
						wait := time.Until(releaseAt)
						if wait > 3*time.Second {
							delayErr = errors.New("synthetic response hold exceeded its bound")
							return
						}
						if wait > 0 {
							timer := time.NewTimer(wait)
							defer timer.Stop()
							select {
							case <-ctx.Done():
								delayErr = ctx.Err()
								return
							case <-timer.C:
							}
						}
						delayedResponseAt = time.Now().UTC()
					})
					if delayErr != nil {
						return CommandResult{}, delayErr
					}
				}
				raw, err := json.Marshal(backup)
				if err != nil {
					return CommandResult{}, err
				}
				out.Stdout = string(raw)
				return out, nil
			})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := x.portal.automaticDRTick(ctx, a, x.ws, target, &state); err != nil {
				t.Fatal(err)
			}
			decisionAt := time.Now().UTC()
			if observedAt.IsZero() || delayedResponseAt.IsZero() {
				t.Fatal("bounded synthetic backup observations did not complete")
			}
			initialAge := observedAt.Sub(completions[firstName])
			responseAge := delayedResponseAt.Sub(completions[firstName])
			decisionAge := decisionAt.Sub(completions[firstName])
			if initialAge <= 0 || initialAge >= maxAge {
				t.Fatal("synthetic backup was not initially eligible under the validated policy")
			}

			// The baseline incorrectly dispatches the stale negative cases.
			// Drain any such synthetic job before failing so TempDir cleanup
			// cannot race its asynchronous executor.
			var job DRTransitionJob
			if state.LastOperationID != "" {
				job = x.waitRestore(state.LastOperationID)
			}
			x.runner.mu.Lock()
			restores, modifiers := x.runner.restoreCalls, x.runner.modifierCalls
			x.runner.mu.Unlock()
			t.Logf("max_age=%s initial_age=%s response_age=%s decision_age=%s state=%s restores=%d modifiers=%d",
				maxAge, initialAge, responseAge, decisionAge, state.State, restores, modifiers)
			if tc.stale {
				if responseAge <= maxAge || decisionAge <= maxAge {
					t.Fatal("synthetic backup did not actually age beyond policy before admission")
				}
				if state.State != "AWAITING_FRESH_OFFSITE_BACKUPS" {
					t.Fatalf("stale completed observation admitted: state=%s age=%s limit=%s restores=%d modifiers=%d",
						state.State, decisionAge, maxAge, restores, modifiers)
				}
				if _, err := os.Lstat(drTransitionPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stale backup created a restore journal: %v", err)
				}
				if restores != 0 || modifiers != 0 {
					t.Fatal("stale backup created native restore resources")
				}
				return
			}
			if responseAge >= maxAge || decisionAge >= maxAge {
				t.Fatal("fresh positive control exceeded its backup-age policy")
			}
			if state.State != "RESTORE_REQUESTED" ||
				job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
				job.EvidenceLabel != "UNKNOWN" || restores != len(x.config.Workloads) {
				t.Fatalf("fresh delayed observations did not reach the unpromoted restore boundary: state=%s job=%s evidence=%s restores=%d",
					state.State, job.Status, job.EvidenceLabel, restores)
			}
		})
	}
}
