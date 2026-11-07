package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const autoDRFenceIntentFile = ".layersentry-kubeone-auto-fence-request.json"

// DRAutomationFenceIntent is a durable REQUEST, never a fencing receipt.
// A separately enrolled and authorized native infrastructure fencer must
// independently assess site identity, storage ownership and physical writer
// isolation, then issue the DRFenceProof signed by its independent key.
type DRAutomationFenceIntent struct {
	OperationID         string    `json:"operation_id"`
	Tenant              string    `json:"tenant"`
	SourceClusterID     string    `json:"source_cluster_id"`
	TargetClusterID     string    `json:"target_cluster_id"`
	ControllerClusterID string    `json:"controller_cluster_id"`
	Direction           string    `json:"direction"`
	State               string    `json:"state"`
	Reason              string    `json:"reason"`
	MinimumFenceEpoch   uint64    `json:"minimum_fence_epoch"`
	FailureSamples      int       `json:"failure_samples"`
	ReadySamples        int       `json:"ready_samples"`
	MaxRPOSeconds       int       `json:"max_rpo_seconds"`
	RequestedAt         time.Time `json:"requested_at"`
}

func autoDRFenceIntentPath(ws Workspace) string {
	return filepath.Join(ws.Directory, autoDRFenceIntentFile)
}

func readAutoDRFenceIntent(ws Workspace) (DRAutomationFenceIntent, error) {
	var intent DRAutomationFenceIntent
	err := readRecoveryRecord(autoDRFenceIntentPath(ws), &intent,
		"operation_id tenant source_cluster_id target_cluster_id controller_cluster_id direction state reason minimum_fence_epoch failure_samples ready_samples max_rpo_seconds requested_at")
	if err != nil {
		return intent, err
	}
	if intent.SourceClusterID != ws.ClusterID || intent.Tenant != ws.Tenant ||
		!recoveryIDPattern.MatchString(intent.TargetClusterID) ||
		intent.ControllerClusterID != intent.TargetClusterID ||
		!backupIdempotencyPattern.MatchString(intent.OperationID) ||
		(intent.Direction != "FAILOVER" && intent.Direction != "FAILBACK") ||
		intent.State != "REQUESTED" || intent.MinimumFenceEpoch == 0 ||
		intent.FailureSamples < 0 || intent.ReadySamples < 0 ||
		intent.MaxRPOSeconds < 1 || intent.MaxRPOSeconds > 3600 ||
		intent.RequestedAt.IsZero() || len(intent.Reason) > 128 {
		return DRAutomationFenceIntent{}, fmt.Errorf("%w: DR fence request journal identity differs", ErrValidation)
	}
	return intent, nil
}

// The controller publishes intent only after health hysteresis and with an
// epoch strictly higher than the last VERIFIED recovery. The already signed
// native fence MUST match this exact operation ID; no prior nonce reuse.
func ensureDRAutomationFenceIntent(ws Workspace, a DRAutomationPolicy,
	previous DRTransitionJob, direction string, state AutoDRStatus, now time.Time) (DRAutomationFenceIntent, error) {
	wantEpoch := uint64(1)
	if previous.Status == "VERIFIED" {
		if previous.FenceEpoch == ^uint64(0) {
			return DRAutomationFenceIntent{}, ErrValidation
		}
		wantEpoch = previous.FenceEpoch + 1
	}
	intent, err := readAutoDRFenceIntent(ws)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return DRAutomationFenceIntent{}, fmt.Errorf("%w: previous fencing request requires human reconciliation", ErrValidation)
	}
	if err == nil {
		if intent.TargetClusterID != a.TargetClusterID || intent.ControllerClusterID != a.ControllerClusterID ||
			intent.MaxRPOSeconds != a.MaxRPOSeconds {
			return DRAutomationFenceIntent{}, ErrValidation
		}
		if intent.Direction == direction && intent.MinimumFenceEpoch >= wantEpoch {
			return intent, nil
		}
		if previous.Status != "VERIFIED" || previous.Direction == direction {
			return DRAutomationFenceIntent{}, fmt.Errorf("%w: cannot replace unconsumed fencing request", ErrValidation)
		}
	}
	id, err := newLifecycleJobID()
	if err != nil {
		return DRAutomationFenceIntent{}, err
	}
	reason := "DC_CONTROL_PLANE_QUORUM_LOST"
	if direction == "FAILBACK" {
		reason = "ORIGINAL_DC_STABLE_REVERSE_REPLICATION_READY"
	}
	intent = DRAutomationFenceIntent{
		OperationID: id, Tenant: a.Tenant, SourceClusterID: a.SourceClusterID,
		TargetClusterID: a.TargetClusterID, ControllerClusterID: a.ControllerClusterID,
		Direction: direction, State: "REQUESTED", Reason: reason,
		MinimumFenceEpoch: wantEpoch, FailureSamples: state.SourceFailures,
		ReadySamples: state.TargetHealthy, MaxRPOSeconds: a.MaxRPOSeconds,
		RequestedAt: now,
	}
	if err := writeBoundedJob(ws, autoDRFenceIntentPath(ws),
		".layersentry-auto-dr-fence-*.tmp", intent); err != nil {
		return DRAutomationFenceIntent{}, fmt.Errorf("%w: automatic fencing request not durably published", ErrValidation)
	}
	return intent, nil
}
