package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const zeroTouchDRIntentFile = ".layersentry-zero-touch-dr-intent.json"

// ZeroTouchDRIntent is a durable, server-generated enrollment request
// following a confirmed primary KubeOne deployment. It MUST NEVER be used as
// proof of backup, restore, independent fencing or production-ready DR.
// A separate, independently admitted platform controller must actually
// provision a target and prove recovery; there is no default worker here.
type ZeroTouchDRIntent struct {
	Version           int       `json:"version"`
	Tenant            string    `json:"tenant"`
	SourceClusterID   string    `json:"source_cluster_id"`
	TargetClusterID   string    `json:"target_cluster_id"`
	SourceProvisionID string    `json:"source_provision_id"`
	Status            string    `json:"status"`
	RequestedAt       time.Time `json:"requested_at"`
	EvidenceLabel     string    `json:"evidence_label"`
}

func zeroTouchDRIntentPath(ws Workspace) string {
	return filepath.Join(ws.Directory, zeroTouchDRIntentFile)
}

func (p *Portal) zeroTouchDRPolicy(ws Workspace) (ZeroTouchDRPolicy, bool) {
	if p == nil || p.recovery == nil {
		return ZeroTouchDRPolicy{}, false
	}
	for _, policy := range p.recovery.config.ZeroTouchDR {
		if policy.Enabled && policy.Tenant == ws.Tenant && policy.SourceClusterID == ws.ClusterID {
			return policy, true
		}
	}
	return ZeroTouchDRPolicy{}, false
}

func readZeroTouchDRIntent(ws Workspace) (ZeroTouchDRIntent, error) {
	var intent ZeroTouchDRIntent
	if err := readRecoveryRecord(zeroTouchDRIntentPath(ws), &intent,
		"version tenant source_cluster_id target_cluster_id source_provision_id status requested_at evidence_label"); err != nil {
		return ZeroTouchDRIntent{}, err
	}
	if intent.Version != 1 || intent.Tenant != ws.Tenant || intent.SourceClusterID != ws.ClusterID ||
		!recoveryIDPattern.MatchString(intent.TargetClusterID) || intent.TargetClusterID == intent.SourceClusterID ||
		len(intent.SourceProvisionID) != 32 || intent.Status != "ENROLLMENT_QUEUED" ||
		intent.EvidenceLabel != "NOT_RECOVERY_VERIFIED" || intent.RequestedAt.IsZero() {
		return ZeroTouchDRIntent{}, ErrValidation
	}
	return intent, nil
}

// publishZeroTouchDRIntent writes exactly once with O_EXCL and syncs the
// record and workspace directory. An ambiguous/partial record is retained,
// never overwritten or used as automatic retry authority.
func publishZeroTouchDRIntent(ws Workspace, intent ZeroTouchDRIntent) error {
	raw, err := json.Marshal(intent)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return ErrValidation
	}
	st, err := os.Lstat(ws.Directory)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ErrValidation
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) ||
		!filepath.IsAbs(ws.Directory) || filepath.Clean(ws.Directory) != ws.Directory {
		return ErrValidation
	}
	resolved, err := filepath.EvalSymlinks(ws.Directory)
	if err != nil || resolved != ws.Directory {
		return ErrValidation
	}
	directory, err := os.Open(ws.Directory)
	if err != nil {
		return ErrValidation
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return ErrValidation
	}
	// All I/O uses the verified directory handle, not a replaceable parent
	// pathname. O_EXCL ensures any existing or ambiguous intent blocks replay.
	fd, err := unix.Openat(int(directory.Fd()), zeroTouchDRIntentFile,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrValidation
	}
	file := os.NewFile(uintptr(fd), zeroTouchDRIntentFile)
	count, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	dirSyncErr := directory.Sync()
	if writeErr != nil || count != len(raw) || syncErr != nil || closeErr != nil || dirSyncErr != nil {
		return ErrValidation
	}
	return nil
}

// queueZeroTouchDR is called only after primary provisioning achieved a
// durably published SUCCEEDED/LIVE_PROVEN result. No customer request follows.
// Under the same Portal's admission lock, a second notification cannot issue
// a second intent. A restarted/foreign/ambiguous record blocks replay.
func (p *Portal) queueZeroTouchDR(ws Workspace, primary ProvisionJob) error {
	if p == nil || primary.ClusterID != ws.ClusterID || primary.Status != "SUCCEEDED" ||
		primary.EvidenceLabel != "LIVE_PROVEN" || primary.ID == "" {
		return ErrValidation
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, enabled := p.zeroTouchDRPolicy(ws)
	if !enabled {
		return nil
	} // zero-touch DR is centrally opt-in, never implicit
	if policy.TargetClusterID == ws.ClusterID {
		return ErrValidation
	}
	target, registered := p.recovery.target(ws.Tenant, ws.ClusterID, policy.TargetClusterID)
	if !registered || target.TargetClusterID != policy.TargetClusterID {
		return ErrValidation
	}
	var recorded ProvisionJob
	if err := readBoundedJob(provisionJobPath(ws), &recorded); err != nil ||
		recorded.ID != primary.ID || recorded.Status != "SUCCEEDED" || recorded.EvidenceLabel != "LIVE_PROVEN" {
		return ErrValidation
	}
	previous, err := readZeroTouchDRIntent(ws)
	if err == nil {
		if previous.TargetClusterID == policy.TargetClusterID && previous.SourceProvisionID == primary.ID {
			return nil
		}
		return ErrValidation
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrValidation
	}
	intent := ZeroTouchDRIntent{Version: 1, Tenant: ws.Tenant, SourceClusterID: ws.ClusterID,
		TargetClusterID: policy.TargetClusterID, SourceProvisionID: primary.ID,
		Status: "ENROLLMENT_QUEUED", RequestedAt: time.Now().UTC(), EvidenceLabel: "NOT_RECOVERY_VERIFIED"}
	return publishZeroTouchDRIntent(ws, intent)
}

// This read-only tenant-scoped endpoint exposes the actual enrollment stage,
// never a fake "DR Protected" result. A registered site is not a proven
// native KubeOne target and an intent is not an admitted protection job.
func (p *Portal) getZeroTouchDRProtection(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, enabled := p.zeroTouchDRPolicy(ws)
	if !enabled {
		portalJSON(w, http.StatusOK, map[string]any{"enabled": false, "status": "NOT_CONFIGURED", "protected": false})
		return
	}
	intent, err := readZeroTouchDRIntent(ws)
	if err == nil {
		if intent.TargetClusterID != policy.TargetClusterID {
			portalError(w, http.StatusConflict, fmt.Errorf("%w: protected DR site identity changed", ErrValidation))
			return
		}
		portalJSON(w, http.StatusOK, map[string]any{"enabled": true, "status": intent.Status,
			"target_cluster_id": intent.TargetClusterID, "source_provision_id": intent.SourceProvisionID,
			"protected": false, "restore_verified": false, "evidence_label": intent.EvidenceLabel})
		return
	}
	if !errors.Is(err, os.ErrNotExist) {
		portalError(w, http.StatusConflict, fmt.Errorf("%w: DR enrollment journal requires reconciliation", ErrValidation))
		return
	}
	var source ProvisionJob
	readErr := readBoundedJob(provisionJobPath(ws), &source)
	state := "AWAITING_PRIMARY_CLUSTER"
	if readErr == nil && source.Status == "SUCCEEDED" && source.EvidenceLabel == "LIVE_PROVEN" {
		state = "AWAITING_ENROLLMENT_RECONCILIATION"
	} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		state = "PRIMARY_PROVISION_OUTCOME_UNKNOWN"
	}
	portalJSON(w, http.StatusOK, map[string]any{"enabled": true, "status": state,
		"target_cluster_id": policy.TargetClusterID, "protected": false, "restore_verified": false})
}
