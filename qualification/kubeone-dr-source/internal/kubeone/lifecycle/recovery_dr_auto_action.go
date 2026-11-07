package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// automaticDRStart can run only after the configured DR-side monitor has
// satisfied its hysteresis, a different authority has physically fenced the
// writer, and the exact application+PVC backup objects are recent and proven.
func (p *Portal) automaticDRStart(ctx context.Context, a DRAutomationPolicy,
	source, target Workspace, previous DRTransitionJob, direction string,
	state *AutoDRStatus) error {
	execution, ok := p.recovery.drExecution(source.Tenant, source.ClusterID, target.ClusterID)
	if !ok {
		return fmt.Errorf("%w: signed DR execution profile absent", ErrValidation)
	}
	now := time.Now().UTC()
	intent, err := ensureDRAutomationFenceIntent(source, a, previous, direction, *state, now)
	if err != nil {
		return err
	}
	nonce, proof, err := autoDRSignedNonce(execution, direction, now)
	if err != nil {
		state.State = "AWAITING_INDEPENDENT_FENCE"
		state.Reason = "No fresh independently signed source-writer fencing attestation for this direction."
		return persistAutoDRStatus(source, *state)
	}
	if nonce != intent.OperationID || proof.FenceEpoch < intent.MinimumFenceEpoch {
		state.State = "AWAITING_CORRECT_FENCING_EPOCH"
		state.Reason = "Externally signed evidence does not match the durable request identity."
		return persistAutoDRStatus(source, *state)
	}
	if direction == "FAILBACK" {
		// Prevent generation reuse, including after a restart. A reverse
		// transfer may only follow VERIFIED failover and a NEW fence epoch.
		if previous.Status != "VERIFIED" || previous.Direction != "FAILOVER" ||
			proof.FenceEpoch <= previous.FenceEpoch {
			state.State = "AWAITING_NEW_FENCE_EPOCH"
			state.Reason = "Reverse transfer requires a verified prior failover and newer fencing generation."
			return persistAutoDRStatus(source, *state)
		}
	}
	restoreSite := target
	if direction == "FAILBACK" {
		restoreSite = source
	}
	// Do not restore stale backup data simply because an old Velero Backup CR
	// reports Completed; bind each object UID to the external signed witness.
	backupCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for i, workload := range execution.Workloads {
		config := workload
		if direction == "FAILBACK" {
			config.BackupName = config.FailbackBackupName
		}
		backup, err := p.recovery.readVeleroBackup(backupCtx, restoreSite, config, proof.Workloads[i].BackupUID)
		if err != nil || backup.Status.CompletionTimestamp.After(now.Add(15*time.Second)) ||
			now.Sub(backup.Status.CompletionTimestamp) > time.Duration(a.MaxBackupAgeSeconds)*time.Second ||
			(previous.Status == "VERIFIED" && !drBackupGenerationAfter(backup, previous.UpdatedAt)) {
			state.State = "AWAITING_FRESH_OFFSITE_BACKUPS"
			state.Reason = "Exact independent application/PVC backup UID or freshness is unavailable."
			return persistAutoDRStatus(source, *state)
		}
	}
	if err := persistAutoDRStatus(source, *state); err != nil {
		return err
	}
	// The exact same first-party admission/operation lock, signed fence,
	// clean-restore and native Velero implementation handles manual calls.
	job, err := p.dispatchDRTransitionOwned(backupCtx, ctx, source, direction, nonce)
	if err != nil {
		state.State = "RESTORE_ADMISSION_BLOCKED"
		state.Reason = "Signed fencing or native Kubernetes restore admission is unavailable."
		return persistAutoDRStatus(source, *state)
	}
	state.LastAction = job.Direction
	state.LastOperationID = job.ID
	state.State = "RESTORE_REQUESTED"
	state.Reason = "Signed recovery submitted; independent application integrity and cutover proof still required."
	return persistAutoDRStatus(source, *state)
}

// automaticDRComplete never creates its own data-integrity or traffic receipt.
// A different signed verifier must already have checked HTTP, PostgreSQL
// transaction hash, restored PVC and the actual routed endpoint.
func (p *Portal) automaticDRComplete(ctx context.Context, a DRAutomationPolicy,
	source Workspace, job DRTransitionJob, state *AutoDRStatus) error {
	profile, ok := p.recovery.drExecution(source.Tenant, source.ClusterID, job.TargetClusterID)
	if !ok {
		return fmt.Errorf("%w: independently registered recovery verifier absent", ErrValidation)
	}
	policy, err := readDRPolicy(source)
	if err != nil || !policy.Enabled || policy.TargetClusterID != job.TargetClusterID {
		return fmt.Errorf("%w: enabled DR policy identity unavailable", ErrValidation)
	}
	now := time.Now().UTC()
	fence, _, err := verifiedDRFence(profile, job.ID, job.Direction, now)
	if err != nil || fence.FenceEpoch != job.FenceEpoch {
		state.State = "WAITING_FOR_CURRENT_FENCE"
		state.Reason = "The current writer's physical fence must be independently reaffirmed before service promotion."
		return persistAutoDRStatus(source, *state)
	}
	result, digest, err := verifiedDRCompletion(profile, job, now)
	if err != nil {
		state.State = "AWAITING_APPLICATION_CUTOVER"
		state.Reason = "No valid independent signed PVC/transaction/HTTP and route-cutover proof is available."
		return persistAutoDRStatus(source, *state)
	}
	// V1 completion may be used by a manually controlled workflow, but
	// automatic site promotion requires V2 independently signed source
	// application write time and failure/cutover time with derived RPO.
	if _, err := measuredDRRecoveryPointRPO(result, now); err != nil {
		state.State = "RECOVERY_WATERMARK_PENDING"
		state.Reason = "Independent recoverable write / outage watermark proof is missing or inconsistent."
		return persistAutoDRStatus(source, *state)
	}
	// A signed pair from a prior incident cannot be replayed with a fresh
	// issuance timestamp. Bound the failure reference to this job's
	// qualified backup-age window; the external signer must still prove
	// the actual outage/writer epoch independently.
	if result.FailureObservedAt.Before(job.RequestedAt.Add(-time.Duration(a.MaxBackupAgeSeconds) * time.Second)) {
		state.State = "RECOVERY_WATERMARK_PENDING"
		state.Reason = "Signed failure reference predates this recovery job's maximum admissible incident window."
		return persistAutoDRStatus(source, *state)
	}
	if result.MeasuredRPOSeconds > int64(a.MaxRPOSeconds) {
		state.State = "RECOVERY_RPO_LIMIT_EXCEEDED"
		state.Reason = "Independent recovery measurement violates the configured automatic RPO limit."
		return persistAutoDRStatus(source, *state)
	}
	finishCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	completed, err := p.finalizeDRTransitionWithProof(finishCtx, source, digest, int64(a.MaxRPOSeconds))
	if err != nil || completed.ID != job.ID || completed.Status != "VERIFIED" {
		state.State = "RECOVERY_VERIFICATION_PENDING"
		state.Reason = "Independent signed recovery or final KubeOne/PVC readback not completed."
		return persistAutoDRStatus(source, *state)
	}
	if completed.Direction == "FAILOVER" {
		state.State = "DR_ACTIVE"
		state.Reason = "DR became the verified single writer; automatic failback still requires a stable DC and new reverse backup."
	} else if completed.Direction == "FAILBACK" {
		state.State = "DC_ACTIVE"
		state.Reason = "Repaired DC became the verified single writer after signed reverse recovery and actual cutover."
	} else {
		return errors.New("unknown recovered direction")
	}
	state.LastAction = completed.Direction
	state.LastOperationID = completed.ID
	return persistAutoDRStatus(source, *state)
}
