package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// A second, independent trust domain checks application transactions, PVC
// storage, exact target workload, route cutover and writer fencing AFTER the
// Velero restore. The KubeOne portal never signs this proof or infers data
// integrity from a Completed Restore object.
type DRCompletedWorkload struct {
	Namespace                 string `json:"namespace"`
	Kind                      string `json:"kind"`
	PVCName                   string `json:"pvc_name"`
	ExpectedDataSHA256        string `json:"expected_data_sha256"`
	ObservedDataSHA256        string `json:"observed_data_sha256"`
	ApplicationReadbackSHA256 string `json:"application_readback_sha256"`
	// V2: independently attested *per-stateful-workload* recoverable commit.
	// The global recovery point must be the oldest of these signed writes.
	LastRecoverableWriteAt time.Time `json:"last_recoverable_write_at,omitempty"`
	RecoveryWatermark      string    `json:"recovery_watermark,omitempty"`
	// V2: signed independent target-PVC fsync/readback of a versioned,
	// operation-and-fence-bound marker, not inferred from Kubernetes Ready.
	StorageProbePVCUID         string    `json:"storage_probe_pvc_uid,omitempty"`
	StorageProbeCompletedAt    time.Time `json:"storage_probe_completed_at,omitempty"`
	StorageProbeReadbackSHA256 string    `json:"storage_probe_readback_sha256,omitempty"`
}
type DRCompletionProof struct {
	Version                int                   `json:"version"`
	OperationID            string                `json:"operation_id"`
	Tenant                 string                `json:"tenant"`
	SourceClusterID        string                `json:"source_cluster_id"`
	TargetClusterID        string                `json:"target_cluster_id"`
	Direction              string                `json:"direction"`
	ActiveWriterClusterID  string                `json:"active_writer_cluster_id"`
	FencedClusterID        string                `json:"fenced_cluster_id"`
	FenceEpoch             uint64                `json:"fence_epoch"`
	RoutedEndpoint         string                `json:"routed_endpoint"`
	EndpointReadbackSHA256 string                `json:"endpoint_readback_sha256"`
	Workloads              []DRCompletedWorkload `json:"workloads"`
	// V2: an independent verifier attests the last recoverable committed
	// application write and the failure/cutover reference. A signed integer
	// alone is insufficient evidence of actual recoverable data.
	LastRecoverableWriteAt time.Time `json:"last_recoverable_write_at,omitempty"`
	FailureObservedAt      time.Time `json:"failure_observed_at,omitempty"`
	RecoveryWatermark      string    `json:"recovery_watermark,omitempty"`
	MeasuredRPOSeconds     int64     `json:"measured_rpo_seconds"`
	MeasuredRTOSeconds     int64     `json:"measured_rto_seconds"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}
type DRSignedCompletion struct {
	Payload   DRCompletionProof `json:"payload"`
	Signature string            `json:"signature"`
}

// The routed endpoint is the registered public workload route for BOTH
// directions; ActiveWriterClusterID binds which site now serves it.
func verifiedDRCompletion(p DRExecutionProfile, job DRTransitionJob, now time.Time) (DRCompletionProof, string, error) {
	if err := protectedRecoveryFile(p.RecoveryVerifierPublicKeyFile); err != nil {
		return DRCompletionProof{}, "", err
	}
	rawKey, err := os.ReadFile(p.RecoveryVerifierPublicKeyFile)
	if err != nil || len(rawKey) > 128 {
		return DRCompletionProof{}, "", ErrValidation
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return DRCompletionProof{}, "", ErrValidation
	}
	if err := protectedRecoveryFile(p.RecoveryVerificationFile); err != nil {
		return DRCompletionProof{}, "", err
	}
	st, err := os.Lstat(p.RecoveryVerificationFile)
	if err != nil || st.Size() < 96 || st.Size() > 32<<10 {
		return DRCompletionProof{}, "", ErrValidation
	}
	raw, err := os.ReadFile(p.RecoveryVerificationFile)
	if err != nil {
		return DRCompletionProof{}, "", err
	}
	if err := applicationJSONFields(raw, "payload signature"); err != nil {
		return DRCompletionProof{}, "", err
	}
	var record DRSignedCompletion
	if err := json.Unmarshal(raw, &record); err != nil {
		return DRCompletionProof{}, "", err
	}
	signature, err := hex.DecodeString(record.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return DRCompletionProof{}, "", ErrValidation
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return DRCompletionProof{}, "", ErrValidation
	}
	signed, err := json.Marshal(record.Payload)
	if err != nil || !ed25519.Verify(key, signed, signature) {
		return DRCompletionProof{}, "", errors.New("independent post-recovery signature invalid")
	}
	v := record.Payload
	current, fenced := p.TargetClusterID, p.SourceClusterID
	if job.Direction == "FAILBACK" {
		current, fenced = fenced, current
	}
	if (v.Version != 1 && v.Version != 2) || v.OperationID != job.ID || v.Tenant != p.Tenant ||
		v.SourceClusterID != p.SourceClusterID || v.TargetClusterID != p.TargetClusterID ||
		v.Direction != job.Direction || v.ActiveWriterClusterID != current ||
		v.FencedClusterID != fenced || v.FenceEpoch != job.FenceEpoch ||
		p.ServiceRoute == "" || v.RoutedEndpoint != p.ServiceRoute || !isSHA256Hex(v.EndpointReadbackSHA256) ||
		v.MeasuredRPOSeconds < 0 || v.MeasuredRPOSeconds > 86400 ||
		v.MeasuredRTOSeconds < 0 || v.MeasuredRTOSeconds > 86400 ||
		v.IssuedAt.IsZero() || v.IssuedAt.Before(job.UpdatedAt) ||
		v.IssuedAt.After(now.Add(15*time.Second)) || !now.Before(v.ExpiresAt) ||
		v.ExpiresAt.Sub(v.IssuedAt) > 5*time.Minute || len(v.Workloads) != len(job.Steps) {
		return DRCompletionProof{}, "", ErrValidation
	}
	if v.Version == 2 {
		if _, err := measuredDRRecoveryPointRPO(v, now); err != nil {
			return DRCompletionProof{}, "", ErrValidation
		}
		if err := verifyConservativeDRWorkloadRPO(v); err != nil {
			return DRCompletionProof{}, "", ErrValidation
		}
	}
	for i, w := range v.Workloads {
		b := job.Steps[i]
		cfg := p.Workloads[i]
		if w.Namespace != b.Namespace || w.Kind != b.Kind || w.PVCName != cfg.PVCName ||
			!isSHA256Hex(w.ApplicationReadbackSHA256) || w.ExpectedDataSHA256 != b.ExpectedDataSHA256 ||
			w.ObservedDataSHA256 != w.ExpectedDataSHA256 || b.State != "RESTORE_COMPLETED" ||
			!validDRCompletedStorageProbe(v, job, w, now) {
			return DRCompletionProof{}, "", ErrValidation
		}
	}
	h := sha256.Sum256(signed)
	return v, hex.EncodeToString(h[:]), nil
}

// The independent verifier signs an application transaction/FS watermark,
// not a Velero backup-completion timestamp or an uncorroborated RPO integer.
// Ceil avoids rounding 300.001s down to a purported 300s SLO.
var drWatermarkPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$`)

func measuredDRRecoveryPointRPO(v DRCompletionProof, now time.Time) (int64, error) {
	if v.Version != 2 || v.LastRecoverableWriteAt.IsZero() ||
		v.FailureObservedAt.IsZero() || !drWatermarkPattern.MatchString(v.RecoveryWatermark) ||
		v.LastRecoverableWriteAt.After(v.FailureObservedAt) ||
		v.FailureObservedAt.After(v.IssuedAt) ||
		v.FailureObservedAt.After(now.Add(15*time.Second)) {
		return 0, ErrValidation
	}
	lag := v.FailureObservedAt.Sub(v.LastRecoverableWriteAt)
	seconds := int64(lag / time.Second)
	if lag%time.Second != 0 {
		seconds++
	}
	if seconds != v.MeasuredRPOSeconds || seconds > 86400 {
		return 0, ErrValidation
	}
	return seconds, nil
}

// verifyConservativeDRWorkloadRPO binds the GLOBAL signed RPO to the oldest
// recoverable committed stateful workload. Otherwise a current HTTP/DB
// watermark can mask an older lost database/PVC in the same protection group.
// Neither timestamp nor LSN is generated by LayerSentry; both are part of
// the independently signed application-verifier completion proof. The
// verifier must establish durable transaction semantics per engine.
func verifyConservativeDRWorkloadRPO(v DRCompletionProof) error {
	if v.Version != 2 || len(v.Workloads) == 0 {
		return ErrValidation
	}
	seen := false
	oldest := time.Time{}
	oldestWatermarks := make(map[string]bool)
	for _, w := range v.Workloads {
		if w.Kind != "STATEFUL" {
			// Stateless service/route integrity has separate signed readback.
			// It must not inject a fictitious database recovery watermark.
			if !w.LastRecoverableWriteAt.IsZero() || w.RecoveryWatermark != "" {
				return ErrValidation
			}
			continue
		}
		if w.LastRecoverableWriteAt.IsZero() ||
			w.LastRecoverableWriteAt.After(v.FailureObservedAt) ||
			w.LastRecoverableWriteAt.After(v.IssuedAt) ||
			!drWatermarkPattern.MatchString(w.RecoveryWatermark) {
			return ErrValidation
		}
		if !seen || w.LastRecoverableWriteAt.Before(oldest) {
			oldest = w.LastRecoverableWriteAt
			oldestWatermarks = map[string]bool{w.RecoveryWatermark: true}
		} else if w.LastRecoverableWriteAt.Equal(oldest) {
			oldestWatermarks[w.RecoveryWatermark] = true
		}
		seen = true
	}
	if !seen || !oldest.Equal(v.LastRecoverableWriteAt) ||
		!oldestWatermarks[v.RecoveryWatermark] {
		return ErrValidation
	}
	return nil
}

// validateRecoveredPVC requires that the live, Bound application PVC is the
// exact claim Velero wrote for this operation's own Restore object. A claim
// re-provisioned empty under the same name after restore is not recovered data.
func (m *RecoveryManager) validateRecoveredPVC(ctx context.Context, ws Workspace, p DRWorkloadProfile, step DRRestoreStep) error {
	if p.Kind != "STATEFUL" {
		return nil
	}
	restore, err := m.observeVeleroRestore(ctx, ws, step.RestoreName)
	if err != nil || restore.Spec.BackupName != step.BackupName ||
		len(restore.Spec.IncludedNamespaces) != 1 || restore.Spec.IncludedNamespaces[0] != p.Namespace ||
		restore.Status.Phase != "Completed" || restore.Status.Errors != 0 || restore.Status.Warnings != 0 {
		return ErrValidation
	}
	return m.verifyVolumeRestoreEvidence(ctx, ws, p, step.RestoreName, restore.Metadata.UID)
}

func (m *RecoveryManager) recoveredPVCUID(ctx context.Context, ws Workspace, p DRWorkloadProfile) (string, error) {
	if !kubernetesNamespacePattern.MatchString(p.Namespace) || !kubernetesNamespacePattern.MatchString(p.PVCName) {
		return "", ErrValidation
	}
	result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "-n", p.Namespace, "get", "persistentvolumeclaims", p.PVCName, "-o", "json"}, m.client.cfg.Environment)
	if err != nil || result.StdoutTruncated || len(result.Stdout) > 1<<20 {
		return "", ErrValidation
	}
	var pvc struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &pvc); err != nil ||
		pvc.Metadata.Name != p.PVCName || pvc.Metadata.Namespace != p.Namespace ||
		pvc.Status.Phase != "Bound" || len(pvc.Metadata.UID) < 16 || len(pvc.Metadata.UID) > 64 {
		return "", ErrValidation
	}
	return pvc.Metadata.UID, nil
}

// Finish a previously observed restore only upon a second independently
// signed app+traffic attestation, and independently recheck KubeOne quorum/PVC.
// No automatic failback can occur before a VERIFIED failover.
// completeDRTransition keeps the authenticated human API boundary. Automatic
// completion cannot fabricate an Actor; it needs an independent signed proof.
func (p *Portal) completeDRTransition(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh independent DR completion step-up required"))
		return
	}
	if !boundedRecoveryJSON(w, r, new(struct{}), "") {
		return
	}
	job, err := p.finalizeDRTransition(r.Context(), ws)
	if err != nil {
		portalError(w, drActionStatus(err), err)
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

// finalizeDRTransition enforces one identical signed app/PVC/traffic and
// Kubernetes quorum verification for human and server-owned automatic paths.
// Manual completion remains under fresh authenticated operator step-up.
// Automatic completion MUST pass the exact prechecked signed proof digest and
// RPO policy so a second valid receipt cannot be swapped before journal commit.
func (p *Portal) finalizeDRTransition(ctx context.Context, ws Workspace) (DRTransitionJob, error) {
	return p.finalizeDRTransitionWithProof(ctx, ws, "", 0)
}

func (p *Portal) finalizeDRTransitionWithProof(ctx context.Context, ws Workspace,
	expectedProofDigest string, maxRPOSeconds int64) (DRTransitionJob, error) {
	if p == nil || p.recovery == nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	job, err := readDRTransition(ws)
	if err != nil || job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("verified restore awaiting independent recovery proof not found"))
	}
	policy, err := readDRPolicy(ws)
	if err != nil || !policy.Enabled || policy.TargetClusterID != job.TargetClusterID {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	profile, ok := p.recovery.drExecution(ws.Tenant, ws.ClusterID, job.TargetClusterID)
	if !ok {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	dest, err := p.Client.Workspace(ws.Tenant, job.TargetClusterID)
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	actualTarget := dest
	if job.Direction == "FAILBACK" {
		actualTarget = ws
	}
	// Network cutover of the registered workload route remains owned and
	// attested by an independent signer; the portal never moves it.
	doc, digest, err := verifiedDRCompletion(profile, job, time.Now().UTC())
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("application and route recovery evidence signature unavailable"))
	}
	if expectedProofDigest != "" {
		// The same independently signed record AND the same enforced RPO
		// budget must still hold under the finalization lock. No state
		// transition or second writer after proof replacement.
		if digest != expectedProofDigest || maxRPOSeconds <= 0 {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("automatic recovery proof changed before finalization"))
		}
		rpo, err := measuredDRRecoveryPointRPO(doc, time.Now().UTC())
		if err != nil || rpo > maxRPOSeconds {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("automatic recovery RPO is not independently reproducible"))
		}
	}
	first, err := lockRecoveryWorkspace(ws)
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	defer first.Close()
	second, err := lockRecoveryWorkspace(dest)
	if err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, ErrValidation)
	}
	defer second.Close()
	if p.running[registryKey(ws.Tenant, ws.ClusterID)] || p.running[registryKey(dest.Tenant, dest.ClusterID)] {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("KubeOne operation active"))
	}
	// Re-confirm, under both site leases, that the independent fencer still
	// attests the SAME epoch and backup lineage for this operation. A lapsed
	// lease or changed epoch means the old writer may be back: never promote
	// a second writer on any path, manual or automatic.
	if err := currentDRFenceMatches(profile, job, time.Now().UTC()); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("current independent source-writer fence not reaffirmed"))
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	health, err := p.Client.Status(ctx, actualTarget)
	if err != nil || !health.APIReady || actualTarget.ExpectedCPNodes < 3 ||
		health.ReadyControlPlanes != actualTarget.ExpectedCPNodes || health.KubeSystemNonReady != 0 {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("post-recovery target KubeOne quorum unavailable"))
	}
	// The automatic controller admitted only a fully healthy configured
	// target. Recheck that SAME all-node baseline under both workspace leases
	// immediately before VERIFIED publication: a worker can fail after the
	// Restore and signed application proof without losing API/CP quorum.
	// Human step-up completion keeps its existing quorum-only contract;
	// expectedProofDigest is provided only by the signed automatic caller.
	if expectedProofDigest != "" && !autoDRFullyHealthy(actualTarget, health, nil) {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("automatic recovery target all-node readiness unavailable"))
	}
	for i, workload := range profile.Workloads {
		if err := p.recovery.validateRecoveredPVC(ctx, actualTarget, workload, job.Steps[i]); err != nil {
			return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("recovered stateful PVC identity/Bound not verified"))
		}
		if doc.Version == 2 && workload.Kind == "STATEFUL" {
			// The independent fsync attestation must bind to the *current*
			// restored PVC UID, not an older, recycled or foreign claim.
			liveUID, err := p.recovery.recoveredPVCUID(ctx, actualTarget, workload)
			if err != nil || liveUID != doc.Workloads[i].StorageProbePVCUID {
				return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("signed storage fsync readback does not match current restored PVC identity"))
			}
		}
	}
	// Reaffirm the SAME signed recovery data and routed-endpoint proof
	// after all native site/PVC readbacks, immediately before publication.
	// A changed/revoked proof cannot be silently replaced mid-finalize.
	_, finalDigest, err := verifiedDRCompletion(profile, job, time.Now().UTC())
	if err != nil || finalDigest != digest {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("signed recovery evidence changed during finalization"))
	}
	// The independent physical/storage fence can expire or be revoked while
	// checking Kubernetes, PVCs and the external recovery receipt. The
	// initial fence check does not authorize publication after those reads:
	// require an independently valid SAME epoch, writer and backup lineage
	// immediately before publishing VERIFIED. This applies to BOTH manual
	// completion and automatic promotion/failback.
	if err := currentDRFenceMatches(profile, job, time.Now().UTC()); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("independent source-writer fence changed during final recovery verification"))
	}
	// Kubernetes/PVC and signer readbacks may have succeeded just as the DR
	// controller lost its native distributed leader Lease. A canceled
	// automatic owner must never publish a fresh VERIFIED writer generation.
	// Manual recovery retains its authorized caller's live context.
	if err := ctx.Err(); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusConflict, errors.New("DR recovery owner lost execution authority before final publication"))
	}
	job.Status = "VERIFIED"
	job.EvidenceLabel = "EXTERNAL_RECOVERY_VERIFIED"
	job.RecoveryProofSHA256 = digest
	job.MeasuredRPOSeconds = doc.MeasuredRPOSeconds
	job.MeasuredRTOSeconds = doc.MeasuredRTOSeconds
	job.UpdatedAt = time.Now().UTC()
	job.Message = "KubeOne target, independent signed application/PVC integrity and service endpoint proof verified; measured recovery values recorded"
	if err := writeBoundedJob(ws, drTransitionPath(ws), ".layersentry-kubeone-dr-transition-*.tmp", job); err != nil {
		return DRTransitionJob{}, drActionFault(http.StatusInternalServerError, errors.New("verified DR receipt could not be durably published"))
	}
	return job, nil
}

func currentDRFenceMatches(profile DRExecutionProfile, job DRTransitionJob, now time.Time) error {
	fence, _, err := verifiedDRFence(profile, job.ID, job.Direction, now)
	// A fence with milliseconds of validity left cannot authorize a new
	// writable epoch. Align this final site/PVC publication guard with the
	// initial 30-second signed-fence admission margin. An enrolled external
	// authority must renew the SAME operation, epoch and backup lineage.
	if err != nil || fence.FenceEpoch != job.FenceEpoch ||
		fence.ExpiresAt.Sub(now) < 30*time.Second ||
		len(fence.Workloads) != len(job.Steps) {
		return ErrValidation
	}
	for i, w := range fence.Workloads {
		s := job.Steps[i]
		if w.Namespace != s.Namespace || w.BackupName != s.BackupName ||
			w.BackupUID != s.SourceBackupUID || w.DataSHA256 != s.ExpectedDataSHA256 {
			return ErrValidation
		}
	}
	return nil
}
