package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DRFenceProof is issued by an external, separately custodied first-party
// fencing authority, not by the KubeOne portal. A network timeout or owner
// approval is never treated as evidence of physical single-writer fencing.
type DRFenceWorkload struct {
	Namespace  string `json:"namespace"`
	BackupName string `json:"backup_name"`
	DataSHA256 string `json:"data_sha256"`
	BackupUID  string `json:"backup_uid"`
}
type DRFenceProof struct {
	Version               int               `json:"version"`
	OperationID           string            `json:"operation_id"`
	Tenant                string            `json:"tenant"`
	SourceClusterID       string            `json:"source_cluster_id"`
	TargetClusterID       string            `json:"target_cluster_id"`
	Direction             string            `json:"direction"`
	FencedClusterID       string            `json:"fenced_cluster_id"`
	ActiveWriterClusterID string            `json:"active_writer_cluster_id"`
	FenceEpoch            uint64            `json:"fence_epoch"`
	FenceReadbackSHA256   string            `json:"fence_readback_sha256"`
	Workloads             []DRFenceWorkload `json:"workloads"`
	IssuedAt              time.Time         `json:"issued_at"`
	ExpiresAt             time.Time         `json:"expires_at"`
}
type DRSignedFence struct {
	Payload   DRFenceProof `json:"payload"`
	Signature string       `json:"signature"`
}

func verifiedDRFence(profile DRExecutionProfile, nonce, direction string, now time.Time) (DRFenceProof, string, error) {
	if !backupIdempotencyPattern.MatchString(nonce) || (direction != "FAILOVER" && direction != "FAILBACK") {
		return DRFenceProof{}, "", ErrValidation
	}
	if err := protectedRecoveryFile(profile.FencePublicKeyFile); err != nil {
		return DRFenceProof{}, "", err
	}
	rawKey, err := os.ReadFile(profile.FencePublicKeyFile)
	if err != nil || len(rawKey) > 128 {
		return DRFenceProof{}, "", ErrValidation
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return DRFenceProof{}, "", ErrValidation
	}
	if err := protectedRecoveryFile(profile.FenceEvidenceFile); err != nil {
		return DRFenceProof{}, "", err
	}
	st, err := os.Lstat(profile.FenceEvidenceFile)
	if err != nil || st.Size() < 96 || st.Size() > 32<<10 {
		return DRFenceProof{}, "", ErrValidation
	}
	body, err := os.ReadFile(profile.FenceEvidenceFile)
	if err != nil {
		return DRFenceProof{}, "", err
	}
	if err := applicationJSONFields(body, "payload signature"); err != nil {
		return DRFenceProof{}, "", err
	}
	var doc DRSignedFence
	if err := json.Unmarshal(body, &doc); err != nil {
		return DRFenceProof{}, "", err
	}
	signature, err := hex.DecodeString(doc.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return DRFenceProof{}, "", ErrValidation
	}
	canonical, canonErr := json.Marshal(doc)
	if canonErr != nil || !bytes.Equal(bytes.TrimSpace(body), canonical) {
		return DRFenceProof{}, "", ErrValidation
	}
	signed, err := json.Marshal(doc.Payload)
	if err != nil || !ed25519.Verify(key, signed, signature) {
		return DRFenceProof{}, "", errors.New("external native fence attestation signature invalid")
	}
	v := doc.Payload
	fenced, writable := v.SourceClusterID, v.TargetClusterID
	if direction == "FAILBACK" {
		fenced, writable = writable, fenced
	}
	if v.Version != 1 || v.OperationID != nonce || v.Tenant != profile.Tenant ||
		v.SourceClusterID != profile.SourceClusterID || v.TargetClusterID != profile.TargetClusterID ||
		v.Direction != direction || v.FencedClusterID != fenced || v.ActiveWriterClusterID != writable ||
		v.FenceEpoch == 0 || !isSHA256Hex(v.FenceReadbackSHA256) ||
		v.IssuedAt.IsZero() || v.ExpiresAt.IsZero() ||
		v.IssuedAt.After(now.Add(15*time.Second)) || !now.Before(v.ExpiresAt) ||
		v.ExpiresAt.Sub(v.IssuedAt) > 5*time.Minute || v.ExpiresAt.Before(v.IssuedAt) ||
		len(v.Workloads) != len(profile.Workloads) {
		return DRFenceProof{}, "", ErrValidation
	}
	for i, w := range v.Workloads {
		p := profile.Workloads[i]
		expectedBackup := p.BackupName
		if direction == "FAILBACK" {
			expectedBackup = p.FailbackBackupName
		}
		if w.Namespace != p.Namespace || w.BackupName != expectedBackup ||
			!isSHA256Hex(w.DataSHA256) || len(w.BackupUID) < 16 || len(w.BackupUID) > 64 ||
			strings.ContainsAny(w.BackupUID, " \r\n/\\") {
			return DRFenceProof{}, "", ErrValidation
		}
	}
	h := sha256.Sum256(signed)
	return v, hex.EncodeToString(h[:]), nil
}
func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

func (m *RecoveryManager) drExecution(tenant, source, target string) (DRExecutionProfile, bool) {
	for _, p := range m.config.DRExecutions {
		if p.Tenant == tenant && p.SourceClusterID == source && p.TargetClusterID == target {
			return p, true
		}
	}
	return DRExecutionProfile{}, false
}

type DRRestoreStep struct {
	Namespace          string `json:"namespace"`
	Kind               string `json:"kind"`
	BackupName         string `json:"backup_name"`
	SourceBackupUID    string `json:"source_backup_uid"`
	RestoreName        string `json:"restore_name"`
	ExpectedDataSHA256 string `json:"expected_data_sha256"`
	State              string `json:"state"`
}
type DRTransitionJob struct {
	ID                  string          `json:"id"`
	ClusterID           string          `json:"cluster_id"`
	TargetClusterID     string          `json:"target_cluster_id"`
	Direction           string          `json:"direction"`
	Status              string          `json:"status"`
	FenceProofSHA256    string          `json:"fence_proof_sha256"`
	FenceEpoch          uint64          `json:"fence_epoch"`
	Steps               []DRRestoreStep `json:"steps"`
	RequestedAt         time.Time       `json:"requested_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	EvidenceLabel       string          `json:"evidence_label"`
	Message             string          `json:"message"`
	RecoveryProofSHA256 string          `json:"recovery_proof_sha256,omitempty"`
	MeasuredRPOSeconds  int64           `json:"measured_rpo_seconds,omitempty"`
	MeasuredRTOSeconds  int64           `json:"measured_rto_seconds,omitempty"`
}

func drTransitionPath(ws Workspace) string {
	return filepath.Join(ws.Directory, ".layersentry-kubeone-dr-transition.json")
}
func readDRTransition(ws Workspace) (DRTransitionJob, error) {
	var j DRTransitionJob
	err := readRecoveryRecord(drTransitionPath(ws), &j, "id cluster_id target_cluster_id direction status fence_proof_sha256 fence_epoch steps requested_at updated_at evidence_label message recovery_proof_sha256 measured_rpo_seconds measured_rto_seconds")
	if err != nil {
		return j, err
	}
	if !backupIdempotencyPattern.MatchString(j.ID) || j.ClusterID != ws.ClusterID ||
		!recoveryIDPattern.MatchString(j.TargetClusterID) ||
		(j.Direction != "FAILOVER" && j.Direction != "FAILBACK") ||
		!isSHA256Hex(j.FenceProofSHA256) || j.FenceEpoch == 0 ||
		j.RequestedAt.IsZero() || j.UpdatedAt.Before(j.RequestedAt) || len(j.Steps) != 2 {
		return DRTransitionJob{}, ErrValidation
	}
	switch j.Status {
	case "RUNNING", "UNKNOWN", "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC":
		if j.EvidenceLabel != "UNKNOWN" {
			return DRTransitionJob{}, ErrValidation
		}
	case "VERIFIED":
		if j.EvidenceLabel != "EXTERNAL_RECOVERY_VERIFIED" || !isSHA256Hex(j.RecoveryProofSHA256) ||
			j.MeasuredRPOSeconds < 0 || j.MeasuredRTOSeconds < 0 {
			return DRTransitionJob{}, ErrValidation
		}
	default:
		return DRTransitionJob{}, fmt.Errorf("%w: unsupported DR transition state", ErrValidation)
	}
	for _, step := range j.Steps {
		if len(step.SourceBackupUID) < 16 || len(step.SourceBackupUID) > 64 ||
			strings.ContainsAny(step.SourceBackupUID, " \r\n/\\") ||
			!recoveryIDPattern.MatchString(step.BackupName) ||
			!kubernetesNamespacePattern.MatchString(step.Namespace) ||
			!recoveryIDPattern.MatchString(step.RestoreName) ||
			!isSHA256Hex(step.ExpectedDataSHA256) ||
			(step.Kind != "STATELESS" && step.Kind != "STATEFUL") {
			return DRTransitionJob{}, ErrValidation
		}
	}
	if j.Steps[0].Kind != "STATELESS" || j.Steps[1].Kind != "STATEFUL" {
		return DRTransitionJob{}, ErrValidation
	}
	if j.Status == "VERIFIED" {
		for _, step := range j.Steps {
			if step.State != "RESTORE_COMPLETED" {
				return DRTransitionJob{}, ErrValidation
			}
		}
	}
	return j, nil
}
