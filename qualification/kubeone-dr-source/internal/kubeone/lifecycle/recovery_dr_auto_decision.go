package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// One monitoring sample cannot authorize DR. A sustained control-plane outage
// only requests review of an independently signed source-writer fence.
func autoDRSourceQuorumLost(ws Workspace, status Status, err error) bool {
	if err != nil || !status.APIReady {
		return true
	}
	if ws.ExpectedCPNodes < 3 || ws.ExpectedCPNodes%2 == 0 {
		return false
	}
	return status.ReadyControlPlanes < (ws.ExpectedCPNodes/2 + 1)
}
func autoDRFullyHealthy(ws Workspace, status Status, err error) bool {
	return err == nil && ws.ExpectedCPNodes >= 3 &&
		ws.ExpectedCPNodes%2 == 1 && ws.ExpectedNodes >= ws.ExpectedCPNodes &&
		status.APIReady && status.ReadyControlPlanes == ws.ExpectedCPNodes &&
		status.ReadyNodes >= ws.ExpectedNodes && status.KubeSystemNonReady == 0
}
func autoDRIncrement(value, max int) int {
	if value < max {
		value++
	}
	return value
}

func (p *Portal) automaticDRTick(ctx context.Context, a DRAutomationPolicy,
	source, target Workspace, state *AutoDRStatus) error {
	now := time.Now().UTC()
	// Never inherit stale health counters across coordinator restarts or
	// clock discontinuities; that could skip the operator's hysteresis budget.
	maxGap := time.Duration(a.PollSeconds*2) * time.Second
	if state.ObservedAt.IsZero() || now.Before(state.ObservedAt) ||
		now.Sub(state.ObservedAt) > maxGap {
		state.SourceFailures = 0
		state.SourceHealthy = 0
		state.TargetHealthy = 0
		state.SourceHealthySince = time.Time{}
	}
	state.ClusterID = source.ClusterID
	state.TargetClusterID = target.ClusterID
	state.ObservedAt = now

	statusCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	primary, primaryErr := p.Client.Status(statusCtx, source)
	cancel()
	statusCtx, cancel = context.WithTimeout(ctx, 20*time.Second)
	standby, standbyErr := p.Client.Status(statusCtx, target)
	cancel()
	sourceOK := autoDRFullyHealthy(source, primary, primaryErr)
	targetOK := autoDRFullyHealthy(target, standby, standbyErr)
	outage := autoDRSourceQuorumLost(source, primary, primaryErr)
	if outage {
		state.SourceFailures = autoDRIncrement(state.SourceFailures, a.SourceFailureChecks)
		state.SourceHealthy = 0
		state.SourceHealthySince = time.Time{}
	} else if sourceOK {
		state.SourceFailures = 0
		state.SourceHealthy = autoDRIncrement(state.SourceHealthy, a.FailbackHealthyChecks)
		if state.SourceHealthySince.IsZero() {
			state.SourceHealthySince = now
		}
	} else {
		// Worker deficits while the original CP quorum is healthy are NOT
		// proof of whole-site failure; use normal KubeOne worker repair.
		state.SourceFailures = 0
		state.SourceHealthy = 0
		state.SourceHealthySince = time.Time{}
	}
	if targetOK {
		state.TargetHealthy = autoDRIncrement(state.TargetHealthy, a.TargetReadyChecks)
	} else {
		state.TargetHealthy = 0
	}

	policy, err := readDRPolicy(source)
	if err != nil || !policy.Enabled || policy.State != "BLOCKED" ||
		policy.TargetClusterID != target.ClusterID {
		state.State = "POLICY_NOT_ENABLED"
		state.Reason = "Automatic recovery requires a separately enabled and registered KubeOne DR policy."
		return persistAutoDRStatus(source, *state)
	}
	previous, err := readDRTransition(source)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		state.State = "AMBIGUOUS_TRANSITION"
		state.Reason = "Existing DR operation journal cannot be verified; no automatic retry."
		if e := persistAutoDRStatus(source, *state); e != nil {
			return e
		}
		return fmt.Errorf("%w: previous DR transition requires manual reconciliation", ErrValidation)
	}
	hasPrevious := err == nil
	if hasPrevious && previous.RestoreIdentityVersion != drRestoreIdentityVersion {
		state.State = "RESTORE_IDENTITY_RECONCILIATION_REQUIRED"
		state.Reason = "Legacy recovery has no durable original Restore UID binding; no promotion, active-writer claim or automatic replay is allowed."
		return persistAutoDRStatus(source, *state)
	}

	if hasPrevious && previous.Status == "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		state.State = "AWAITING_APP_AND_TRAFFIC_PROOF"
		state.Reason = "Restored resources require fresh, independently signed application/PVC and routed-endpoint checks."
		if err := persistAutoDRStatus(source, *state); err != nil {
			return err
		}
		if (previous.Direction == "FAILOVER" && !a.AutoFailover) ||
			(previous.Direction == "FAILBACK" && !a.AutoFailback) {
			return nil
		}
		return p.automaticDRComplete(ctx, a, source, previous, state)
	}
	if hasPrevious && previous.Status != "VERIFIED" {
		state.State = "UNRECONCILED_OPERATION"
		state.Reason = "RUNNING or UNKNOWN recovery requires explicit reconciliation; no automatic replay."
		return persistAutoDRStatus(source, *state)
	}
	if hasPrevious && previous.Direction == "FAILOVER" {
		// VERIFIED is a historical journal event, not a permanent
		// physically fenced single-writer lease. Recheck the independent
		// signer on every controller tick BEFORE reporting DR_ACTIVE or
		// considering automatic failback. Never silently trust a running
		// QEMU guest or a previously green Kubernetes Ready sample.
		//
		// After a distinct reverse (FAILBACK) request has been durably
		// issued, the independent fencer is allowed to replace the single
		// signed file with the NEW higher-epoch reverse proof. Subsequent
		// transition admission verifies that reverse proof separately;
		// rechecking the superseded forward proof would block valid failback.
		intent, intentErr := readAutoDRFenceIntent(source)
		if intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) {
			state.State = "ACTIVE_FENCE_RECHECK_REQUIRED"
			state.Reason = "Existing fencing intent is ambiguous; signed physical writer isolation requires manual reconciliation."
			return persistAutoDRStatus(source, *state)
		}
		profile, enrolled := p.recovery.drExecution(source.Tenant, source.ClusterID, target.ClusterID)
		if !enrolled {
			state.State = "ACTIVE_FENCE_RECHECK_REQUIRED"
			state.Reason = "Independent fencing issuer for this protection group is unavailable."
			return persistAutoDRStatus(source, *state)
		}
		// API/quorum health checks above may consume their full timeout;
		// tick-start now is NOT a valid clock for a short-lived fencing
		// lease. Require a fresh wall-clock read at the actual current
		// writer/fence decision boundary.
		fenceCheckNow := time.Now().UTC()
		// The durable reverse INTENT is not signed fencing authority. Only a
		// NEW independent physical/storage CLOSED receipt for this exact
		// registered pair, direction, nonce and strictly newer epoch may
		// supersede the previous forward fence. The upcoming restore still
		// separately validates fresh reverse backups and target custody.
		reverseInProgress := a.AutoFailback && intentErr == nil &&
			intent.Tenant == a.Tenant &&
			intent.SourceClusterID == source.ClusterID &&
			intent.TargetClusterID == target.ClusterID &&
			intent.ControllerClusterID == a.ControllerClusterID &&
			intent.MaxRPOSeconds == a.MaxRPOSeconds &&
			intent.Direction == "FAILBACK" &&
			intent.OperationID != previous.ID &&
			intent.MinimumFenceEpoch > previous.FenceEpoch &&
			intent.RequestedAt.After(previous.RequestedAt)
		reverseFenced := false
		if reverseInProgress {
			signed, _, signErr := verifiedDRFence(profile, intent.OperationID, "FAILBACK", fenceCheckNow)
			if signErr == nil && (signed.FenceEpoch < intent.MinimumFenceEpoch ||
				signed.FenceEpoch <= previous.FenceEpoch) {
				// Independently signed, but cannot reuse an already committed
				// writer generation. Preserve the existing actionable state
				// rather than reporting this as a generic unsigned request.
				state.State = "AWAITING_CORRECT_FENCING_EPOCH"
				state.Reason = "Reverse recovery requires the exact independently signed newer physical/storage fencing generation."
				return persistAutoDRStatus(source, *state)
			}
			reverseFenced = signErr == nil &&
				signed.FenceEpoch >= intent.MinimumFenceEpoch &&
				signed.FenceEpoch > previous.FenceEpoch &&
				signed.ExpiresAt.Sub(fenceCheckNow) >= 30*time.Second
		}
		if !reverseFenced && currentDRFenceMatches(profile, previous, fenceCheckNow) != nil {
			state.State = "ACTIVE_FENCE_RECHECK_REQUIRED"
			state.Reason = "Neither original forward nor exact independently signed reverse writer isolation is current; no automatic transitions."
			return persistAutoDRStatus(source, *state)
		}
		// A historical verified transition cannot turn an unavailable active
		// DR Kubernetes cluster into a green service. Site failures are not
		// themselves proof of a new source writer and must never cause an
		// automatic alternative promotion or failback.
		if !targetOK {
			state.State = "ACTIVE_DR_SITE_UNHEALTHY"
			state.Reason = "Previously verified DR is no longer API/quorum/worker healthy; recovery and sole-writer status require separate validation."
			return persistAutoDRStatus(source, *state)
		}
		if reverseFenced {
			state.State = "REVERSE_FENCE_CONFIRMED"
			state.Reason = "A new signed reverse fence has excluded the former DR writer; the original DC is not active until independent restore/route proof."
		} else {
			state.State = "DR_ACTIVE"
			state.Reason = "Signed failover verified; no new DC writer is allowed until a qualified reverse recovery."
		}
		if !a.AutoFailback {
			return persistAutoDRStatus(source, *state)
		}
		hold := time.Duration(a.FailbackHoldSeconds) * time.Second
		if !sourceOK || !targetOK ||
			state.SourceHealthy < a.FailbackHealthyChecks ||
			state.TargetHealthy < a.TargetReadyChecks ||
			state.SourceHealthySince.IsZero() ||
			now.Sub(state.SourceHealthySince) < hold {
			state.State = "WAITING_FOR_STABLE_PRIMARY"
			state.Reason = "Automatic failback waits for a healthy repaired DC, a stable hold period, and an accessible DR recovery controller."
			return persistAutoDRStatus(source, *state)
		}
		state.State = "AWAITING_REVERSE_BACKUP_AND_FENCE"
		state.Reason = "Failback requires NEW DR-writer backups, a newer independently signed fencing epoch, and a clean DC restore target."
		if err := persistAutoDRStatus(source, *state); err != nil {
			return err
		}
		return p.automaticDRStart(ctx, a, source, target, previous, "FAILBACK", state)
	}
	if hasPrevious && previous.Direction != "FAILBACK" {
		state.State = "UNKNOWN_DIRECTION"
		state.Reason = "Unsupported historical DR direction cannot be automatically resumed."
		return persistAutoDRStatus(source, *state)
	}

	if !a.AutoFailover {
		state.State = "MONITORING_ONLY"
		state.Reason = "Automatic failover is disabled by policy."
		return persistAutoDRStatus(source, *state)
	}
	if !outage || state.SourceFailures < a.SourceFailureChecks {
		state.State = "WATCHING_PRIMARY"
		state.Reason = "Original cluster control-plane failure threshold not met."
		return persistAutoDRStatus(source, *state)
	}
	if !targetOK || state.TargetHealthy < a.TargetReadyChecks {
		state.State = "DR_SITE_NOT_HEALTHY"
		state.Reason = "DR API/quorum/worker baseline is not independently verified."
		return persistAutoDRStatus(source, *state)
	}
	state.State = "AWAITING_INDEPENDENT_FENCE"
	state.Reason = "DC outage detected; automatic restore requires externally signed proof DC writers have been fenced."
	if err := persistAutoDRStatus(source, *state); err != nil {
		return err
	}
	return p.automaticDRStart(ctx, a, source, target, previous, "FAILOVER", state)
}

// This reads an external signer-provided nonce and then verifies the actual
// signed fence with the existing first-party DR signer trust boundary. It
// cannot produce or renew a signature or turn a timeout into fencing.
func autoDRSignedNonce(execution DRExecutionProfile, direction string, now time.Time) (string, DRFenceProof, error) {
	if err := protectedRecoveryFile(execution.FenceEvidenceFile); err != nil {
		return "", DRFenceProof{}, err
	}
	raw, err := os.ReadFile(execution.FenceEvidenceFile)
	if err != nil || len(raw) > 32<<10 {
		return "", DRFenceProof{}, ErrValidation
	}
	var doc DRSignedFence
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", DRFenceProof{}, ErrValidation
	}
	id := doc.Payload.OperationID
	if !backupIdempotencyPattern.MatchString(id) {
		return "", DRFenceProof{}, ErrValidation
	}
	proof, _, err := verifiedDRFence(execution, id, direction, now)
	if err != nil {
		return "", DRFenceProof{}, err
	}
	// No permission to switch traffic if the fence is about to expire.
	if proof.ExpiresAt.Sub(now) < 30*time.Second {
		return "", DRFenceProof{}, ErrValidation
	}
	return id, proof, nil
}
