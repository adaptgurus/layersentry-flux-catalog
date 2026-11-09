package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// This workflow coordinates the independently registered Kubernetes-aware
// Velero restore owner. KubeOne's native etcd/PKI recovery is a separate
// MANUAL cold-reconstruction path, never restored into the warm DR etcd.
func (p *Portal) getDRTransition(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	job, err := readDRTransition(ws)
	if errors.Is(err, os.ErrNotExist) {
		portalJSON(w, http.StatusOK, map[string]any{"job": nil, "state": "NOT_STARTED"})
		return
	}
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("DR transition journal cannot be reconciled"))
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (p *Portal) startDRTransition(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh authorized DR step-up required"))
		return
	}
	if !boundedRecoveryJSON(w, r, new(struct{}), "") {
		return
	}
	direction := "FAILOVER"
	if strings.HasSuffix(r.URL.Path, "/dr/failback") {
		direction = "FAILBACK"
	} else if !strings.HasSuffix(r.URL.Path, "/dr/failover") {
		portalError(w, http.StatusBadRequest, ErrValidation)
		return
	}
	// The HTTP boundary requires an authenticated human actor and fresh
	// step-up. The independent automation path never fabricates that actor.
	job, err := p.dispatchDRTransition(r.Context(), ws, direction, r.Header.Get("Idempotency-Key"))
	if err != nil {
		portalError(w, drActionStatus(err), err)
		return
	}
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

// dispatchDRTransition is the shared fail-closed KubeOne/Velero transition
// engine for manual calls and explicitly opted-in, externally signed DR automation.
func (p *Portal) dispatchDRTransition(ctx context.Context, ws Workspace, direction, nonce string) (DRTransitionJob, error) {
	// Manually authenticated recovery is a DURABLE job and must outlive the
	// HTTP response; its normal independent signed fence remains mandatory.
	return p.dispatchDRTransitionOwned(ctx, context.Background(), ws, direction, nonce)
}

// Automatic recovery is different: an async restore MUST NOT continue as
// an independent background writer after its DR controller loses the
// distributed Kubernetes leader Lease. The owner context is canceled by
// the coordinator watchdog on lost ownership; the job becomes UNKNOWN,
// not silently replayed or promoted by another controller.
func (p *Portal) dispatchDRTransitionOwned(ctx, ownerCtx context.Context, ws Workspace, direction, nonce string) (DRTransitionJob, error) {
	if ownerCtx == nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	if p == nil || p.recovery == nil || (direction != "FAILOVER" && direction != "FAILBACK") {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	if ctx.Err() != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("DR admission canceled before dispatch"))
	}
	policy, err := readDRPolicy(ws)
	if err != nil || !policy.Enabled || policy.State != "BLOCKED" {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("registered independent DR plan unavailable"))
	}
	execution, ok := p.recovery.drExecution(ws.Tenant, ws.ClusterID, policy.TargetClusterID)
	targetCfg, registered := p.recovery.target(ws.Tenant, ws.ClusterID, policy.TargetClusterID)
	target, err := p.Client.Workspace(ws.Tenant, policy.TargetClusterID)
	if !ok || !registered || err != nil || targetCfg.APIEndpoint != policy.TargetEndpoint || target.ClusterID == ws.ClusterID {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("qualified independent DR target missing"))
	}
	// Reject an unqualified volume path before requesting/using a physical
	// fence or dispatching any native restore mutation.
	for _, workload := range execution.Workloads {
		if err := drVolumeRestoreQualification(workload); err != nil {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, err)
		}
	}
	// A site without an externally registered fencing/restore owner returns
	// BLOCKED before validating per-request idempotency details.
	if !backupIdempotencyPattern.MatchString(nonce) {
		return DRTransitionJob{}, drActionFault(http.StatusBadRequest, errors.New("bounded idempotency key required"))
	}
	currentIdentity, err := identityDigest(target.Kubeconfig)
	if err != nil || currentIdentity != policy.TargetIdentity {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("DR target identity mismatch"))
	}
	targetWS := target
	if direction == "FAILBACK" {
		targetWS = ws
	}
	if err := p.recovery.verifyDRStorageCredentialBindings(ctx, execution, targetWS); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("managed DR storage credential or exact BackupStorageLocation not qualified"))
	}
	proof, digest, err := verifiedDRFence(execution, nonce, direction, time.Now().UTC())
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("externally signed exact native source-writer fencing unavailable"))
	}
	key := registryKey(ws.Tenant, ws.ClusterID)
	targetKey := registryKey(target.Tenant, target.ClusterID)
	p.mu.Lock()
	defer p.mu.Unlock()
	// Same first-party operation lock is used for both registered sites; no
	// simultaneous source/DR cluster lifecycle or backup while restoring.
	first, err := lockRecoveryWorkspace(ws)
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("DC cluster mutation lease unavailable"))
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = first.Close()
		}
	}()
	second, err := lockRecoveryWorkspace(target)
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("DR cluster mutation lease unavailable"))
	}
	defer func() {
		if !transferred {
			_ = second.Close()
		}
	}()
	old, e := readDRTransition(ws)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("existing DR result ambiguous; reconcile without retry"))
	}
	if e == nil {
		if old.ID == nonce && old.Direction == direction {
			return old, nil
		}
		if !drRestoreIdentitiesBound(old) {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("prior DR restore identities require reconciliation before a new transition"))
		}
		if old.Status != "VERIFIED" || old.Direction == direction ||
			proof.FenceEpoch <= old.FenceEpoch ||
			(direction == "FAILBACK" && old.Direction != "FAILOVER") {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("prior DR state not verified for reverse operation"))
		}
		if len(old.Steps) != len(proof.Workloads) {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("prior DR data lineage ambiguous"))
		}
		for i, witness := range proof.Workloads {
			if witness.BackupUID == old.Steps[i].SourceBackupUID {
				return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("reverse DR requires a newly created backup generation"))
			}
		}
	} else if direction == "FAILBACK" {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("failback requires completed verified failover"))
	}
	if p.running[key] || p.running[targetKey] {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("site lifecycle operation in progress"))
	}
	for _, cluster := range []Workspace{ws, target} {
		pending, err := reconciliationState(cluster)
		if err != nil || pending {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("existing KubeOne state or DR intent unreconciled"))
		}
	}
	// Only the newly active site must be healthy. A failed/offline DC is not
	// assumed fenced; a separate fresh signed native fence proof is mandatory.
	statusCtx, statusCancel := context.WithTimeout(ctx, 35*time.Second)
	status, err := p.Client.Status(statusCtx, targetWS)
	statusCancel()
	if err != nil || !status.APIReady || targetWS.ExpectedCPNodes < 3 ||
		status.ReadyControlPlanes != targetWS.ExpectedCPNodes || status.KubeSystemNonReady != 0 {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("target independent KubeOne quorum unavailable"))
	}
	if !p.Client.KubeconfigExists(targetWS) {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("independent target Kubernetes authentication unavailable"))
	}
	steps := make([]DRRestoreStep, 0, 2)
	// Read the exact pre-existing offsite Velero backups from the restore site
	// BEFORE the first mutating Kubernetes API call. Backup CR metadata is not
	// by itself proof of stateful payload integrity; the signed independent
	// witness binds each immutable expected application data digest.
	for i, workload := range execution.Workloads {
		wcfg := workload
		if direction == "FAILBACK" {
			wcfg.BackupName = wcfg.FailbackBackupName
		}
		ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		backup, err := p.recovery.readVeleroBackup(ctx, targetWS, wcfg, proof.Workloads[i].BackupUID)
		// After a VERIFIED transition the other site is the single writer.
		// Only a generation started after that verification can carry its
		// data; an older CR with a merely different UID is stale lineage.
		if err == nil && e == nil && !drBackupGenerationAfter(backup, old.UpdatedAt) {
			err = fmt.Errorf("%w: backup generation predates prior verified writer transition", ErrValidation)
		}
		if err == nil {
			err = p.recovery.targetNamespaceEmpty(ctx, targetWS, wcfg)
		}
		cancel()
		if err != nil {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("offsite stateless/stateful backup or clean independent target not qualified"))
		}
		steps = append(steps, DRRestoreStep{Namespace: wcfg.Namespace, Kind: wcfg.Kind,
			BackupName: wcfg.BackupName, SourceBackupUID: proof.Workloads[i].BackupUID, RestoreName: drRestoreName(nonce, wcfg),
			ExpectedDataSHA256: proof.Workloads[i].DataSHA256, State: "PENDING"})
	}
	now := time.Now().UTC()
	job := DRTransitionJob{
		RestoreIdentityVersion: drRestoreIdentityVersion,
		ID:                     nonce, ClusterID: ws.ClusterID, TargetClusterID: target.ClusterID,
		Direction: direction, Status: "RUNNING", FenceProofSHA256: digest,
		FenceEpoch: proof.FenceEpoch, Steps: steps, RequestedAt: now, UpdatedAt: now,
		EvidenceLabel: "UNKNOWN",
		Message:       "external native fence attested; Kubernetes-aware restore in progress; application integrity and endpoint cutover not yet verified",
	}
	if err := writeBoundedJob(ws, drTransitionPath(ws), ".layersentry-kubeone-dr-transition-*.tmp", job); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusInternalServerError, errors.New("durable DR restore intent could not be published"))
	}
	p.running[key], p.running[targetKey] = true, true
	transferred = true
	// A job struct is copied by value, but Steps is a slice. Make an isolated
	// copy before handing it to the asynchronous executor: no response JSON
	// encoder may share mutable state with the goroutine.
	asyncJob := job
	asyncJob.Steps = append([]DRRestoreStep(nil), job.Steps...)
	go p.runDRTransition(ownerCtx, ws, targetWS, execution, asyncJob, first, second, key, targetKey)
	return job, nil
}

func (p *Portal) runDRTransition(ownerCtx context.Context, source Workspace, target Workspace, execution DRExecutionProfile, job DRTransitionJob,
	first, second *nativeWorkspaceLease, key, targetKey string) {
	defer first.Close()
	defer second.Close()
	ctx, cancel := context.WithTimeout(ownerCtx, 55*time.Minute)
	defer cancel()
	var outcomeErr error
	for i := range job.Steps {
		if err := ctx.Err(); err != nil {
			outcomeErr = fmt.Errorf("DR restore canceled after controller or execution lease loss: %w", err)
			break
		}
		wcfg := execution.Workloads[i]
		if job.Direction == "FAILBACK" {
			wcfg.BackupName = wcfg.FailbackBackupName
		}
		// Fresh external signer lease is rechecked immediately before each new
		// Kubernetes mutating action, not only at request admission.
		proof, digest, e := verifiedDRFence(execution, job.ID, job.Direction, time.Now().UTC())
		// The external fencer can renew its short signed lease while the
		// first restore is in progress. Its epoch, writer direction and
		// immutable workload data hashes must stay identical.
		if e != nil || proof.FenceEpoch != job.FenceEpoch {
			outcomeErr = errors.New("fresh independent native fencing cannot be re-established")
			break
		}
		if digest == "" {
			outcomeErr = ErrValidation
			break
		}
		for n, check := range proof.Workloads {
			if check.DataSHA256 != job.Steps[n].ExpectedDataSHA256 || check.BackupName != job.Steps[n].BackupName ||
				check.BackupUID != job.Steps[n].SourceBackupUID {
				outcomeErr = errors.New("renewed fence changed protected backup lineage")
				break
			}
		}
		if outcomeErr != nil {
			break
		}
		// A Restore references its Backup by NAME. Re-bind that name to the
		// signed UID immediately before and after the restore: a CR replaced
		// since admission (deleted, re-synced, other generation) carries data
		// the external witness never attested.
		if _, e := p.recovery.readVeleroBackup(ctx, target, wcfg, job.Steps[i].SourceBackupUID); e != nil {
			outcomeErr = errors.New("signed Velero backup generation no longer present; restore not created")
			break
		}
		if err := ctx.Err(); err != nil {
			outcomeErr = fmt.Errorf("DR controller lost execution lease before Velero creation: %w", err)
			break
		}
		id, e := p.recovery.createVeleroRestore(ctx, target, wcfg, job.Steps[i].RestoreName)
		if id != "" {
			job.Steps[i].RestoreUID = id
			job.Steps[i].State = "SUBMITTED"
			job.UpdatedAt = time.Now().UTC()
			// A controller interruption must not lose the identity that the
			// native create returned. No GET, next restore or promotion may
			// proceed if that custody cannot be durably recorded.
			if err := writeBoundedJob(source, drTransitionPath(source), ".layersentry-kubeone-dr-transition-*.tmp", job); err != nil {
				outcomeErr = fmt.Errorf("created Velero restore identity could not be durably recorded: %w", err)
				break
			}
		}
		if e != nil {
			outcomeErr = fmt.Errorf("Velero restore outcome unknown: %w", e)
			break
		}
		if e = p.recovery.verifyVeleroRestore(ctx, target, wcfg, job.Steps[i].RestoreName, id); e != nil {
			outcomeErr = fmt.Errorf("Velero restore could not be independently verified: %w", e)
			break
		}
		if _, e := p.recovery.readVeleroBackup(ctx, target, wcfg, job.Steps[i].SourceBackupUID); e != nil {
			outcomeErr = errors.New("Velero backup generation changed while restoring; restored data lineage UNKNOWN")
			break
		}
		job.Steps[i].State = "RESTORE_COMPLETED"
	}
	job.UpdatedAt = time.Now().UTC()
	if outcomeErr != nil {
		job.Status = "UNKNOWN"
		job.Message = "Kubernetes restore outcome UNKNOWN. Preserve original backup, fencing and DR intent; reconcile resources and do not auto-replay"
	} else {
		// Do NOT publish failover/active-writer success until application-specific
		// SQL transaction/checksum, PVC and routed service readbacks are signed by
		// independent owners AFTER restore and traffic cutover.
		job.Status = "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC"
		job.Message = "Velero objects restored; independent application data, PVC and actual traffic cutover proof REQUIRED before promotion"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = writeBoundedJob(source, drTransitionPath(source), ".layersentry-kubeone-dr-transition-*.tmp", job)
	delete(p.running, key)
	delete(p.running, targetKey)
}

// drBackupGenerationAfter requires native Velero start/completion ordering and
// a start strictly after the prior VERIFIED transition. Missing timestamps are
// not assumed fresh.
func drBackupGenerationAfter(b nativeVeleroBackup, prior time.Time) bool {
	start, done := b.Status.StartTimestamp, b.Status.CompletionTimestamp
	return !prior.IsZero() && !start.IsZero() && !done.IsZero() &&
		!done.Before(start) && start.After(prior)
}
