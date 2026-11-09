package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const maxEtcdSnapshotSize int64 = 8 << 30

type ClusterBackupJob struct {
	ID               string    `json:"id"`
	ClusterID        string    `json:"cluster_id"`
	DestinationID    string    `json:"destination_id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	Status           string    `json:"status"`   // RUNNING, SUCCEEDED, UNKNOWN: never infer "not run" after uncertain native effects
	Coverage         string    `json:"coverage"` // ETCD_ONLY; not PKI or PVC bytes
	ResticSnapshotID string    `json:"restic_snapshot_id,omitempty"`
	EtcdSHA256       string    `json:"etcd_sha256,omitempty"`
	RequestedAt      time.Time `json:"requested_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	EvidenceLabel    string    `json:"evidence_label"`
	Message          string    `json:"message"`
}

type RecoveryManager struct {
	client                 *Client
	config                 RecoveryConfig
	mountCheck             func(NFSBackupTarget) error // fixed production function; test injection only
	storageBindingVerifier DRStorageCredentialVerifier // explicitly wired provider/custody adapter; nil blocks DR
}

func NewRecoveryManager(c *Client, config RecoveryConfig) (*RecoveryManager, error) {
	if c == nil || c.runner == nil {
		return nil, fmt.Errorf("%w: KubeOne client is unavailable", ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &RecoveryManager{client: c, config: config, mountCheck: verifyNFSMount}, nil
}

func (m *RecoveryManager) destination(tenant, id string) (NFSBackupTarget, bool) {
	for _, t := range m.config.NFSTargets {
		if t.Tenant == tenant && t.ID == id {
			return t, true
		}
	}
	return NFSBackupTarget{}, false
}

func (m *RecoveryManager) target(tenant, source, dest string) (DRClusterTarget, bool) {
	for _, t := range m.config.DRTargets {
		if t.Tenant == tenant && t.SourceClusterID == source && t.TargetClusterID == dest {
			return t, true
		}
	}
	return DRClusterTarget{}, false
}

func (m *RecoveryManager) validDestination(t NFSBackupTarget) error {
	if err := m.mountCheck(t); err != nil {
		return err
	}
	return protectedRecoveryFile(t.PasswordFile)
}

func backupJournalPath(ws Workspace) string {
	return filepath.Join(ws.Directory, ".layersentry-nfs-etcd-backup.json")
}

func readBackupJob(ws Workspace) (ClusterBackupJob, error) {
	var job ClusterBackupJob
	err := readRecoveryRecord(backupJournalPath(ws), &job,
		"id cluster_id destination_id idempotency_key status coverage restic_snapshot_id etcd_sha256 requested_at updated_at evidence_label message")
	if err != nil {
		return job, err
	}
	if len(job.ID) != 32 || job.ClusterID != ws.ClusterID ||
		!recoveryIDPattern.MatchString(job.DestinationID) ||
		job.IdempotencyKey == "" || job.Coverage != "ETCD_ONLY" ||
		job.RequestedAt.IsZero() || job.UpdatedAt.IsZero() ||
		job.RequestedAt.After(job.UpdatedAt) {
		return ClusterBackupJob{}, fmt.Errorf("%w: backup journal identity invalid", ErrValidation)
	}
	switch job.Status {
	case "RUNNING", "UNKNOWN":
		if job.EvidenceLabel != "UNKNOWN" {
			return ClusterBackupJob{}, ErrValidation
		}
	case "SUCCEEDED":
		if len(job.ResticSnapshotID) != 64 || len(job.EtcdSHA256) != 64 || job.EvidenceLabel != "ETCD_RESTIC_RESTORE_VERIFIED" {
			return ClusterBackupJob{}, ErrValidation
		}
	default:
		return ClusterBackupJob{}, ErrValidation
	}
	return job, nil
}

// The hash is a storage key, NOT a permission credential or a customer token.
func recoveryStorageKey(s string) string {
	digest := sha256.Sum256([]byte(s))
	return hex.EncodeToString(digest[:16])
}

func ensurePrivateRepository(t NFSBackupTarget, tenant, clusterID string) (string, error) {
	if err := verifyStorageIDs(tenant, clusterID); err != nil {
		return "", err
	}
	// No user-supplied path reaches this expression.
	path := filepath.Join(t.MountPath, "layersentry-kubeone", recoveryStorageKey(tenant), recoveryStorageKey(clusterID))
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", fmt.Errorf("%w: cannot prepare encrypted backup repository", ErrValidation)
	}
	// Refuse a user-controlled symlink (including symlink ancestor) or a
	// group/world-readable repository; never write secrets to such a path.
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return "", fmt.Errorf("%w: unsafe repository path", ErrValidation)
	}
	for current := path; current != t.MountPath; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("%w: repository directory permissions are unsafe", ErrValidation)
		}
	}
	return path, nil
}

func verifyStorageIDs(tenant, clusterID string) error {
	if len(tenant) > 128 || tenant == "" || strings.ContainsAny(tenant, "\x00\r\n/") ||
		!recoveryIDPattern.MatchString(clusterID) {
		return fmt.Errorf("%w: invalid tenant or cluster identity", ErrValidation)
	}
	return nil
}

// snapshotDigest reads a complete regular, single-link 0600 root-private file,
// never a prefix or a symlink. Payload can include Kubernetes Secret objects.
func snapshotDigest(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 512 || st.Size() > maxEtcdSnapshotSize ||
		st.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%w: etcd backup custody unavailable", ErrValidation)
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || native.Nlink != 1 || native.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("%w: etcd snapshot not owned by service", ErrValidation)
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
	n, err := io.Copy(h, io.LimitReader(f, maxEtcdSnapshotSize+1))
	if err != nil || n != st.Size() {
		return "", fmt.Errorf("%w: snapshot changed during checksum", ErrValidation)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m *RecoveryManager) runRestic(ctx context.Context, ws Workspace, t NFSBackupTarget, repo string, args ...string) (CommandResult, error) {
	if err := m.validDestination(t); err != nil {
		return CommandResult{}, err
	}
	a := append([]string{"--repo", repo, "--password-file", t.PasswordFile}, args...)
	result, err := m.client.runner.Run(ctx, ws.Directory, m.config.ResticBinary, a, m.client.cfg.Environment)
	if err != nil {
		return CommandResult{}, errors.New("encrypted backup operation unavailable; original outcome requires reconciliation")
	}
	if result.StdoutTruncated {
		return CommandResult{}, ErrValidation
	}
	return result, nil
}

func (m *RecoveryManager) snapshotID(result CommandResult) (string, error) {
	// "restic backup --json" emits progress objects and a final summary line.
	// The expected immutable snapshot ID is only accepted from that summary.
	var id string
	for _, line := range strings.Split(result.Stdout, "\n") {
		if len(line) == 0 {
			continue
		}
		var value struct {
			MessageType string `json:"message_type"`
			SnapshotID  string `json:"snapshot_id"`
		}
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			return "", ErrValidation
		}
		if value.MessageType == "summary" {
			if id != "" || len(value.SnapshotID) != 64 {
				return "", ErrValidation
			}
			if _, err := hex.DecodeString(value.SnapshotID); err != nil {
				return "", ErrValidation
			}
			id = value.SnapshotID
		}
	}
	if id == "" {
		return "", ErrValidation
	}
	return id, nil
}

func restoredSnapshotDigest(root string) (string, error) {
	var got string
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() != "snapshot.db" || entry.Type()&os.ModeSymlink != 0 || count != 0 {
			return fmt.Errorf("%w: unexpected Restic restore item", ErrValidation)
		}
		value, err := snapshotDigest(path)
		if err != nil {
			return err
		}
		got = value
		count++
		return nil
	})
	if err != nil || count != 1 {
		return "", fmt.Errorf("%w: encrypted snapshot restoration incomplete", ErrValidation)
	}
	return got, nil
}

// BackupEtcdToNFS runs the genuine version-pinned KubeOne etcd snapshot then
// Restic-encrypts it into an exact NFS mount and independently RESTORES it for
// byte-for-byte verification. This never purports to back up PKI or PVCs.
func (m *RecoveryManager) BackupEtcdToNFS(ctx context.Context, ws Workspace, id, jobID string) (string, string, error) {
	t, ok := m.destination(ws.Tenant, id)
	if !ok {
		return "", "", ErrValidation
	}
	if err := m.validDestination(t); err != nil {
		return "", "", err
	}
	if !m.client.KubeconfigExists(ws) {
		return "", "", ErrValidation
	}
	stage, err := os.MkdirTemp(m.config.StagingRoot, ".layersentry-etcd-backup-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(stage)
	if err = os.Chmod(stage, 0700); err != nil {
		return "", "", err
	}
	file := filepath.Join(stage, "snapshot.db")
	args := []string{"etcd", "snapshot", file, "-m", ws.Manifest}
	if ws.TFJSON != "" {
		args = append(args, "-t", ws.TFJSON)
	}
	if ws.Credentials != "" {
		args = append(args, "-c", ws.Credentials)
	}
	res, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubeOneBinary, args, m.client.cfg.Environment)
	if err != nil || res.StdoutTruncated {
		return "", "", errors.New("native KubeOne etcd snapshot outcome unknown; reconciliation required")
	}
	// KubeOne controls how the snapshot file is created. Parent directory
	// is private before invocation; narrow final file permissions afterwards.
	if st, statErr := os.Lstat(file); statErr != nil || !st.Mode().IsRegular() {
		return "", "", ErrValidation
	}
	if err = os.Chmod(file, 0600); err != nil {
		return "", "", ErrValidation
	}
	original, err := snapshotDigest(file)
	if err != nil {
		return "", "", err
	}
	if err = m.validDestination(t); err != nil {
		return "", "", err
	}
	repo, err := ensurePrivateRepository(t, ws.Tenant, ws.ClusterID)
	if err != nil {
		return "", "", err
	}
	if info, statErr := os.Lstat(filepath.Join(repo, "config")); errors.Is(statErr, os.ErrNotExist) {
		if _, err = m.runRestic(ctx, ws, t, repo, "init"); err != nil {
			return "", "", err
		}
	} else if statErr != nil || !info.Mode().IsRegular() {
		return "", "", ErrValidation
	}
	// Restic resolves the workspace snapshot by the single whitelisted filename.
	// Passing a local absolute file path never permits user-specified command text.
	backup, err := m.runRestic(ctx, ws, t, repo, "backup", "--json", "--tag", "layersentry-etcd:"+recoveryStorageKey(ws.ClusterID), "--tag", "job:"+jobID, file)
	if err != nil {
		return "", "", err
	}
	snapshotID, err := m.snapshotID(backup)
	if err != nil {
		return "", "", err
	}
	verifyDir := filepath.Join(stage, "restored")
	if err = os.Mkdir(verifyDir, 0700); err != nil {
		return "", "", err
	}
	if _, err = m.runRestic(ctx, ws, t, repo, "restore", snapshotID, "--target", verifyDir); err != nil {
		return "", "", err
	}
	restored, err := restoredSnapshotDigest(verifyDir)
	if err != nil || restored != original {
		return "", "", fmt.Errorf("%w: encrypted NFS restore checksum differs", ErrValidation)
	}
	if err = m.validDestination(t); err != nil {
		return "", "", err
	}
	return snapshotID, original, nil
}
