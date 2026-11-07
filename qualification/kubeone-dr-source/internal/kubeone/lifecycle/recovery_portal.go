package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const backupRequestBodyLimit int64 = 4096

var backupIdempotencyPattern = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_.-]{15,127}$")

func (p *Portal) ConfigureRecovery(config RecoveryConfig) error {
	if p == nil || p.Client == nil {
		return ErrValidation
	}
	manager, err := NewRecoveryManager(p.Client, config)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recovery != nil {
		return fmt.Errorf("%w: recovery already configured", ErrValidation)
	}
	p.recovery = manager
	return nil
}

func readRecoveryRecord(path string, out any, allowed string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() <= 0 || info.Size() > maxPortalBodyBytes {
		return fmt.Errorf("%w: unsafe recovery record", ErrValidation)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	current, e1 := f.Stat()
	final, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !os.SameFile(info, current) || !os.SameFile(info, final) {
		return fmt.Errorf("%w: recovery record changed", ErrValidation)
	}
	native, ok := current.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return ErrValidation
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPortalBodyBytes+1))
	if err != nil || len(raw) > int(maxPortalBodyBytes) {
		return ErrValidation
	}
	if err := applicationJSONFields(raw, allowed); err != nil {
		return err
	}
	if !lifecycleJSONSurrogates(raw) {
		return ErrValidation
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	return nil
}

// The same durable on-disk flock used by native lifecycle work is held across
// backup command completion. For normal workspaces it is anchored to that
// workspace's 0700 directory. Native successor uses its existing exact owner.
func lockRecoveryWorkspace(ws Workspace) (*nativeWorkspaceLease, error) {
	if nativeWorkspaceSelected(ws) {
		return lockNativeWorkspace(ws)
	}
	d, err := os.Open(ws.Directory)
	if err != nil {
		return nil, err
	}
	l, err := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return &nativeWorkspaceLease{dir: d, lock: l}, nil
}

func boundedRecoveryJSON(w http.ResponseWriter, r *http.Request, out any, allowed string) bool {
	if r.ContentLength > backupRequestBodyLimit || r.Body == nil {
		portalError(w, http.StatusBadRequest, errors.New("invalid bounded recovery request"))
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, backupRequestBodyLimit+1))
	if err != nil || len(raw) > int(backupRequestBodyLimit) ||
		applicationJSONFields(raw, allowed) != nil || !lifecycleJSONSurrogates(raw) {
		portalError(w, http.StatusBadRequest, errors.New("invalid recovery request"))
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		portalError(w, http.StatusBadRequest, errors.New("invalid recovery request fields"))
		return false
	}
	return true
}

type startBackupRequest struct {
	DestinationID string `json:"destination_id"`
	Mode          string `json:"mode"`
}

func (p *Portal) recoveryDestinations(w http.ResponseWriter, r *http.Request) {
	tenant, ok := portalTenant(r)
	if !ok {
		portalError(w, http.StatusForbidden, errors.New("authenticated tenant required"))
		return
	}
	if p.recovery == nil {
		portalJSON(w, http.StatusOK, map[string]any{"destinations": []any{}, "configured": false})
		return
	}
	dests := make([]map[string]string, 0, len(p.recovery.config.NFSTargets))
	for _, t := range p.recovery.config.NFSTargets {
		if t.Tenant != tenant {
			continue
		}
		dests = append(dests, map[string]string{"id": t.ID, "display_name": t.DisplayName, "storage_type": "NFS", "backup_coverage": "ETCD_ONLY"})
	}
	portalJSON(w, http.StatusOK, map[string]any{"destinations": dests, "configured": true})
}

func (p *Portal) getBackup(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	job, err := readBackupJob(ws)
	if errors.Is(err, os.ErrNotExist) {
		portalJSON(w, http.StatusOK, map[string]any{"job": nil, "available": p.recovery != nil})
		return
	}
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("backup journal requires reconciliation"))
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"job": job, "available": p.recovery != nil})
}

func (p *Portal) startBackup(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh authorized step-up required"))
		return
	}
	if p.recovery == nil {
		portalError(w, http.StatusServiceUnavailable, errors.New("NFS backup policy not configured"))
		return
	}
	var req startBackupRequest
	if !boundedRecoveryJSON(w, r, &req, "destination_id mode") {
		return
	}
	if req.Mode != "ETCD_ONLY" || !recoveryIDPattern.MatchString(req.DestinationID) {
		portalError(w, http.StatusBadRequest, errors.New("backup mode requires a configured ETCD_ONLY destination"))
		return
	}
	nonce := r.Header.Get("Idempotency-Key")
	if !backupIdempotencyPattern.MatchString(nonce) {
		portalError(w, http.StatusBadRequest, errors.New("valid Idempotency-Key required"))
		return
	}
	manager := p.recovery
	dest, ok := manager.destination(ws.Tenant, req.DestinationID)
	if !ok {
		portalError(w, http.StatusBadRequest, errors.New("destination is not preapproved"))
		return
	}
	if err = manager.validDestination(dest); err != nil {
		portalError(w, http.StatusConflict, errors.New("registered NFS storage or encrypted repository unavailable"))
		return
	}
	key := registryKey(ws.Tenant, ws.ClusterID)
	p.mu.Lock()
	defer p.mu.Unlock()
	lease, err := lockRecoveryWorkspace(ws)
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("workspace operation is locked or unavailable"))
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = lease.Close()
		}
	}()
	prior, err := readBackupJob(ws)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		portalError(w, http.StatusConflict, errors.New("prior backup journal requires reconciliation"))
		return
	}
	if err == nil {
		if prior.IdempotencyKey == nonce {
			if prior.DestinationID != req.DestinationID {
				portalError(w, http.StatusConflict, errors.New("idempotency key belongs to another request"))
				return
			}
			portalJSON(w, http.StatusAccepted, map[string]any{"job": prior})
			return
		}
		if prior.Status != "SUCCEEDED" {
			portalError(w, http.StatusConflict, errors.New("prior backup outcome is not reconciled; do not replay"))
			return
		}
	}
	if p.running[key] {
		portalError(w, http.StatusConflict, errors.New("cluster lifecycle operation already active"))
		return
	}
	if pending, e := reconciliationState(ws); e != nil || pending {
		portalError(w, http.StatusConflict, errors.New("cluster lifecycle state is pending or unavailable"))
		return
	}
	if !manager.client.KubeconfigExists(ws) {
		portalError(w, http.StatusConflict, errors.New("existing authenticated KubeOne cluster required"))
		return
	}
	// Validate the actual control-plane quorum without claiming PVC protection.
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	status, e := manager.client.Status(ctx, ws)
	cancel()
	if e != nil || !status.APIReady || ws.ExpectedCPNodes < 3 ||
		status.ReadyControlPlanes != ws.ExpectedCPNodes || status.KubeSystemNonReady != 0 {
		portalError(w, http.StatusConflict, errors.New("KubeOne control-plane quorum/health not proven"))
		return
	}
	id, e := newLifecycleJobID()
	if e != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not create backup identity"))
		return
	}
	now := time.Now().UTC()
	job := ClusterBackupJob{
		ID: id, ClusterID: ws.ClusterID, DestinationID: req.DestinationID,
		IdempotencyKey: nonce, Status: "RUNNING", Coverage: "ETCD_ONLY", RequestedAt: now, UpdatedAt: now,
		EvidenceLabel: "UNKNOWN", Message: "encrypted etcd backup and NFS restore verification running; PKI/PVC not covered",
	}
	if e = writeBoundedJob(ws, backupJournalPath(ws), ".layersentry-etcd-backup-*.tmp", job); e != nil {
		portalError(w, http.StatusInternalServerError, errors.New("backup intent could not be durably written"))
		return
	}
	p.running[key] = true
	transferred = true
	go p.executeEtcdBackup(ws, key, job, lease)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (p *Portal) executeEtcdBackup(ws Workspace, key string, job ClusterBackupJob, lease *nativeWorkspaceLease) {
	defer lease.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	id, checksum, err := p.recovery.BackupEtcdToNFS(ctx, ws, job.DestinationID, job.ID)
	job.UpdatedAt = time.Now().UTC()
	if err != nil {
		job.Status = "UNKNOWN"
		job.Message = "KubeOne/Restic backup outcome unknown; inspect exact source/repository, never blind retry"
		job.EvidenceLabel = "UNKNOWN"
	} else {
		job.Status = "SUCCEEDED"
		job.ResticSnapshotID = id
		job.EtcdSHA256 = checksum
		job.EvidenceLabel = "ETCD_RESTIC_RESTORE_VERIFIED"
		job.Message = "encrypted NFS etcd snapshot restored and SHA256 verified; PKI and PVC data NOT included"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := writeBoundedJob(ws, backupJournalPath(ws), ".layersentry-etcd-backup-*.tmp", job); err != nil {
		// Leave the original RUNNING intent on disk if journal publication fails.
		// No automatic replay, even if Restic already accepted the snapshot.
	}
	delete(p.running, key)
}

// NFS is the transport for encrypted etcd backup, not proof of an independent
// DR site, PKI custody, or stateful application-volume restoration.
type DRProtectionPolicy struct {
	Enabled         bool      `json:"enabled"`
	ClusterID       string    `json:"cluster_id"`
	TargetClusterID string    `json:"target_cluster_id"`
	TargetEndpoint  string    `json:"target_endpoint"`
	DestinationID   string    `json:"destination_id"`
	TargetIdentity  string    `json:"target_identity_sha256"`
	State           string    `json:"state"`
	Reason          string    `json:"reason"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type drRequest struct {
	Enabled         bool   `json:"enabled"`
	TargetClusterID string `json:"target_cluster_id"`
	TargetEndpoint  string `json:"target_endpoint"`
	DestinationID   string `json:"destination_id"`
}

func drPolicyPath(ws Workspace) string {
	return filepath.Join(ws.Directory, ".layersentry-kubeone-dr-policy.json")
}

func readDRPolicy(ws Workspace) (DRProtectionPolicy, error) {
	var p DRProtectionPolicy
	err := readRecoveryRecord(drPolicyPath(ws), &p, "enabled cluster_id target_cluster_id target_endpoint destination_id target_identity_sha256 state reason updated_at")
	if err != nil {
		return p, err
	}
	if p.ClusterID != ws.ClusterID || p.UpdatedAt.IsZero() ||
		(p.Enabled && (!recoveryIDPattern.MatchString(p.TargetClusterID) || len(p.TargetIdentity) != 64 || !validRecoveryEndpoint(p.TargetEndpoint))) {
		return DRProtectionPolicy{}, ErrValidation
	}
	if !p.Enabled && p.State != "DISABLED" || p.Enabled && p.State != "BLOCKED" {
		return DRProtectionPolicy{}, ErrValidation
	}
	return p, nil
}

func identityDigest(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 1<<20 {
		return "", ErrValidation
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return "", ErrValidation
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, 1<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *Portal) getDRPolicy(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	policy, err := readDRPolicy(ws)
	if errors.Is(err, os.ErrNotExist) {
		portalJSON(w, http.StatusOK, map[string]any{"policy": nil, "configured": p.recovery != nil})
		return
	}
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("DR policy requires reconciliation"))
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"policy": policy, "configured": p.recovery != nil})
}

func (p *Portal) updateDRPolicy(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh authorized step-up required"))
		return
	}
	if p.recovery == nil {
		portalError(w, http.StatusServiceUnavailable, errors.New("KubeOne DR owner not configured"))
		return
	}
	var req drRequest
	if !boundedRecoveryJSON(w, r, &req, "enabled target_cluster_id target_endpoint destination_id") {
		return
	}
	policy := DRProtectionPolicy{Enabled: req.Enabled, ClusterID: ws.ClusterID, UpdatedAt: time.Now().UTC()}
	if req.Enabled {
		m := p.recovery
		target, ok := m.target(ws.Tenant, ws.ClusterID, req.TargetClusterID)
		if !ok || req.TargetEndpoint != target.APIEndpoint || !validRecoveryEndpoint(req.TargetEndpoint) {
			portalError(w, http.StatusBadRequest, errors.New("DR target must match a separately registered cluster and endpoint"))
			return
		}
		if _, ok = m.destination(ws.Tenant, req.DestinationID); !ok {
			portalError(w, http.StatusBadRequest, errors.New("approved DR backup destination required"))
			return
		}
		tws, err := p.Client.Workspace(ws.Tenant, req.TargetClusterID)
		if err != nil || tws.ClusterID == ws.ClusterID {
			portalError(w, http.StatusConflict, errors.New("independent DR cluster is not registered or unavailable"))
			return
		}
		fingerprint, err := identityDigest(tws.Kubeconfig)
		if err != nil {
			portalError(w, http.StatusConflict, errors.New("independent DR cluster identity not proven"))
			return
		}
		policy.TargetClusterID = req.TargetClusterID
		policy.TargetEndpoint = req.TargetEndpoint
		policy.TargetIdentity = fingerprint
		policy.DestinationID = req.DestinationID
		policy.State = "BLOCKED"
		policy.Reason = "Control-plane DR planning registered; application/PVC backup, PKI, site fencing and DR recovery not qualified"
	} else {
		if req.TargetClusterID != "" || req.TargetEndpoint != "" || req.DestinationID != "" {
			portalError(w, http.StatusBadRequest, errors.New("disabled DR request must not change target identity"))
			return
		}
		policy.State = "DISABLED"
		policy.Reason = "protection disabled; existing backup data retained"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	lease, err := lockRecoveryWorkspace(ws)
	if err != nil {
		portalError(w, http.StatusConflict, errors.New("workspace operation unavailable"))
		return
	}
	defer lease.Close()
	if p.running[registryKey(ws.Tenant, ws.ClusterID)] {
		portalError(w, http.StatusConflict, errors.New("cluster operation already active"))
		return
	}
	if pending, err := reconciliationState(ws); err != nil || pending {
		portalError(w, http.StatusConflict, errors.New("prior lifecycle outcome requires reconciliation"))
		return
	}
	if err := writeBoundedJob(ws, drPolicyPath(ws), ".layersentry-kubeone-dr-*.tmp", policy); err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not persist KubeOne DR policy"))
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"policy": policy})
}

type drValidation struct {
	SourceClusterID            string   `json:"source_cluster_id"`
	TargetClusterID            string   `json:"target_cluster_id"`
	State                      string   `json:"state"`
	Reasons                    []string `json:"reasons"`
	ControlPlaneBackupVerified bool     `json:"control_plane_backup_verified"`
	ApplicationPVCProtected    bool     `json:"application_pvc_protected"`
	ReadyForFailover           bool     `json:"ready_for_failover"`
}

func (p *Portal) validateDRPolicy(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh authorized step-up required"))
		return
	}
	if !boundedRecoveryJSON(w, r, new(struct{}), "") {
		return
	}
	plan, err := readDRPolicy(ws)
	if err != nil || !plan.Enabled || p.recovery == nil {
		portalError(w, http.StatusConflict, errors.New("enabled registered DR policy not found"))
		return
	}
	target, ok := p.recovery.target(ws.Tenant, ws.ClusterID, plan.TargetClusterID)
	tws, err := p.Client.Workspace(ws.Tenant, plan.TargetClusterID)
	if !ok || err != nil || target.APIEndpoint != plan.TargetEndpoint {
		portalError(w, http.StatusConflict, errors.New("registered DR destination changed or unavailable"))
		return
	}
	fingerprint, err := identityDigest(tws.Kubeconfig)
	if err != nil || fingerprint != plan.TargetIdentity {
		portalError(w, http.StatusConflict, errors.New("DR cluster identity drift; explicit owner review required"))
		return
	}
	result := drValidation{SourceClusterID: ws.ClusterID, TargetClusterID: tws.ClusterID, State: "BLOCKED", Reasons: []string{}}
	for _, s := range []Workspace{ws, tws} {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		health, e := p.Client.Status(ctx, s)
		cancel()
		if e != nil || !health.APIReady || health.ReadyControlPlanes < 3 ||
			health.ReadyControlPlanes != s.ExpectedCPNodes || health.KubeSystemNonReady != 0 {
			result.Reasons = append(result.Reasons, "independent KubeOne control-plane health/quorum not verified")
		}
	}
	job, e := readBackupJob(ws)
	if e == nil && job.Status == "SUCCEEDED" && job.DestinationID == plan.DestinationID && job.Coverage == "ETCD_ONLY" {
		result.ControlPlaneBackupVerified = true
	} else {
		result.Reasons = append(result.Reasons, "encrypted control-plane snapshot on approved NFS destination missing")
	}
	result.Reasons = append(result.Reasons, "KubeOne etcd snapshot does not include Kubernetes PKI or PVC/application bytes; independent restore and fencing owner not qualified")
	result.ApplicationPVCProtected = false
	result.ReadyForFailover = false
	portalJSON(w, http.StatusOK, map[string]any{"validation": result})
}

func (p *Portal) rejectUnqualifiedFailover(w http.ResponseWriter, r *http.Request) {
	ws, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, ws) {
		portalError(w, http.StatusForbidden, errors.New("fresh authorized step-up required"))
		return
	}
	portalError(w, http.StatusConflict, errors.New("KubeOne disaster recovery failover is blocked until PKI, application/PVC restore, independent site and single-writer fencing are qualified"))
}
