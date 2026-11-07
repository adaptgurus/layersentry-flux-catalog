package lifecycle

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const autoDRStatusFile = ".layersentry-kubeone-auto-dr.json"
const autoDRControllerLockFile = ".layersentry-kubeone-auto-dr-controller.lock"

// AutoDRStatus is an audit and hysteresis record, not signed infrastructure
// authority. Only real fencing, immutable backups and recovered app/route
// attestations can permit a Kubernetes site to become the writer.
type AutoDRStatus struct {
	ClusterID          string    `json:"cluster_id"`
	TargetClusterID    string    `json:"target_cluster_id"`
	State              string    `json:"state"`
	Reason             string    `json:"reason"`
	SourceFailures     int       `json:"source_failures"`
	SourceHealthy      int       `json:"source_healthy"`
	TargetHealthy      int       `json:"target_healthy"`
	SourceHealthySince time.Time `json:"source_healthy_since"`
	ObservedAt         time.Time `json:"observed_at"`
	LastAction         string    `json:"last_action"`
	LastOperationID    string    `json:"last_operation_id"`
}

func autoDRStatusPath(ws Workspace) string {
	return filepath.Join(ws.Directory, autoDRStatusFile)
}

func readAutoDRStatus(ws Workspace) (AutoDRStatus, error) {
	var state AutoDRStatus
	err := readRecoveryRecord(autoDRStatusPath(ws), &state,
		"cluster_id target_cluster_id state reason source_failures source_healthy target_healthy source_healthy_since observed_at last_action last_operation_id")
	if err != nil {
		return AutoDRStatus{}, err
	}
	if state.ClusterID != ws.ClusterID || state.ObservedAt.IsZero() ||
		state.SourceFailures < 0 || state.SourceHealthy < 0 || state.TargetHealthy < 0 ||
		len(state.Reason) > 512 || len(state.State) > 64 ||
		!recoveryIDPattern.MatchString(state.TargetClusterID) ||
		(state.LastOperationID != "" && !backupIdempotencyPattern.MatchString(state.LastOperationID)) {
		return AutoDRStatus{}, ErrValidation
	}
	return state, nil
}

func persistAutoDRStatus(ws Workspace, state AutoDRStatus) error {
	if state.ClusterID != ws.ClusterID || state.ObservedAt.IsZero() {
		return ErrValidation
	}
	return writeBoundedJob(ws, autoDRStatusPath(ws), ".layersentry-auto-dr-*.tmp", state)
}

// This is a singleton lock for one explicitly selected DR-side coordinator.
// Multi-instance deployments additionally need a real distributed lease,
// not independent local files with the same path.
type autoDRControllerLease struct {
	file                  *os.File
	originalDirectory     string
	originalDirectoryInfo os.FileInfo
}

func acquireAutoDRControllerLease(ws Workspace) (*autoDRControllerLease, error) {
	dir, err := os.Lstat(ws.Directory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("%w: unqualified DR automation journal ownership", ErrValidation)
	}
	path := filepath.Join(ws.Directory, autoDRControllerLockFile)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	reject := func() (*autoDRControllerLease, error) { file.Close(); return nil, ErrValidation }
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != 0 {
		return reject()
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return reject()
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return reject()
	}
	if after, err := os.Lstat(path); err != nil || !os.SameFile(st, after) {
		return reject()
	}
	return &autoDRControllerLease{
		file:                  file,
		originalDirectory:     ws.Directory,
		originalDirectoryInfo: dir,
	}, nil
}

// Check rejects a local controller whose original filesystem directory or
// lockfile inode was replaced after flock acquisition. It detects a common
// unsafe lost-ownership case. This is NOT distributed leader election:
// another physical host or a racing replacement can still exist, and real
// production automation requires separately qualified HA lease+witness.
func (l *autoDRControllerLease) Check(ws Workspace) error {
	if l == nil || l.file == nil || l.originalDirectoryInfo == nil ||
		ws.Directory != l.originalDirectory {
		return ErrValidation
	}
	dir, err := os.Lstat(ws.Directory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 ||
		!os.SameFile(l.originalDirectoryInfo, dir) {
		return ErrValidation
	}
	locked, err := l.file.Stat()
	if err != nil || !locked.Mode().IsRegular() || locked.Mode().Perm() != 0600 ||
		locked.Size() != 0 {
		return ErrValidation
	}
	current, err := os.Lstat(filepath.Join(ws.Directory, autoDRControllerLockFile))
	if err != nil || !os.SameFile(locked, current) {
		return ErrValidation
	}
	return nil
}

func (l *autoDRControllerLease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (p *Portal) autoDRPolicy(tenant, clusterID string) (DRAutomationPolicy, bool) {
	if p == nil || p.recovery == nil {
		return DRAutomationPolicy{}, false
	}
	for _, policy := range p.recovery.config.DRAutomation {
		if policy.Tenant == tenant && policy.SourceClusterID == clusterID {
			return policy, true
		}
	}
	return DRAutomationPolicy{}, false
}

func (p *Portal) getDRAutomation(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	policy, ok := p.autoDRPolicy(ws.Tenant, ws.ClusterID)
	if !ok {
		portalJSON(w, http.StatusOK, map[string]any{"enabled": false, "status": nil})
		return
	}
	state, err := readAutoDRStatus(ws)
	if errors.Is(err, os.ErrNotExist) {
		portalJSON(w, http.StatusOK, map[string]any{
			"enabled": policy.Enabled, "auto_failover": policy.AutoFailover,
			"auto_failback": policy.AutoFailback, "status": nil})
		return
	}
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("automatic DR journal requires manual reconciliation"))
		return
	}
	// A fresh timestamp does not permit a retired or foreign DR target to
	// inherit an older DR_ACTIVE journal. The current registered tenant,
	// source and target pair MUST match the persisted audit identity,
	// otherwise the operator must reconcile the journal explicitly.
	if state.ClusterID != ws.ClusterID || state.TargetClusterID != policy.TargetClusterID {
		portalError(w, http.StatusConflict, errors.New("automatic DR journal target no longer matches the registered site policy"))
		return
	}
	// A persisted VERIFIED/DR_ACTIVE entry is HISTORICAL, not evidence that
	// the coordinator, its distributed Kubernetes Lease or the original
	// physical writer fence is still alive. If a process stalls/exits, a
	// deceptively green last status must expire even without a new tick.
	// This read-only projection never mutates the immutable audit journal.
	now := time.Now().UTC()
	maxAge := time.Duration(policy.PollSeconds*2+20) * time.Second
	if maxAge < time.Minute {
		maxAge = time.Minute
	}
	fresh := !state.ObservedAt.After(now.Add(15*time.Second)) &&
		!state.ObservedAt.IsZero() &&
		now.Sub(state.ObservedAt) <= maxAge
	if !fresh {
		state.State = "STALE_CONTROLLER_STATUS"
		state.Reason = "Automatic DR controller observation is stale or from a future clock; live ownership and physical fencing are unverified."
	}
	portalJSON(w, http.StatusOK, map[string]any{
		"enabled": policy.Enabled, "auto_failover": policy.AutoFailover,
		"auto_failback": policy.AutoFailback, "status": state,
		"status_fresh": fresh})
}
