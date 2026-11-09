package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const recoveryConfigLimit = 64 << 10

var recoveryIDPattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,62}$")

// NFSBackupTarget is a server-owned, pre-mounted storage identity. No HTTP
// request may provide a path, NFS export, password file, or credentials.
type NFSBackupTarget struct {
	Tenant       string `json:"tenant"`
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	MountPath    string `json:"mount_path"`
	MountSource  string `json:"mount_source"`
	PasswordFile string `json:"password_file"`
}

// DRClusterTarget is an exact same-tenant, distinct-identity KubeOne site.
// The endpoint is an allowlisted reference, never a browser-selected dial URL.
type DRClusterTarget struct {
	Tenant          string `json:"tenant"`
	SourceClusterID string `json:"source_cluster_id"`
	TargetClusterID string `json:"target_cluster_id"`
	APIEndpoint     string `json:"api_endpoint"`
}

type DRWorkloadProfile struct {
	Namespace            string `json:"namespace"`
	Kind                 string `json:"kind"` // STATELESS or STATEFUL
	BackupName           string `json:"backup_name"`
	FailbackBackupName   string `json:"failback_backup_name"`
	StorageLocation      string `json:"storage_location"`
	ManagedCredentialRef string `json:"managed_credential_ref"`
	PVCName              string `json:"pvc_name,omitempty"`
	VolumeRecoveryKind   string `json:"volume_recovery_kind,omitempty"`
}

// DRExecutionProfile.ServiceRoute is the public application route moved by
// the independent network owner (DNS/VIP/LB). It is never a Kubernetes API
// endpoint: the signed traffic-cutover proof binds it to the active writer.
type DRExecutionProfile struct {
	Tenant                        string              `json:"tenant"`
	SourceClusterID               string              `json:"source_cluster_id"`
	SourceEndpoint                string              `json:"source_endpoint"`
	TargetClusterID               string              `json:"target_cluster_id"`
	ServiceRoute                  string              `json:"service_route"`
	FencePublicKeyFile            string              `json:"fence_public_key_file"`
	FenceEvidenceFile             string              `json:"fence_evidence_file"`
	RecoveryVerifierPublicKeyFile string              `json:"recovery_verifier_public_key_file"`
	RecoveryVerificationFile      string              `json:"recovery_verification_file"`
	Workloads                     []DRWorkloadProfile `json:"workloads"`
}

// DRAutomationPolicy is server-configured and disabled by default.
type DRAutomationPolicy struct {
	Tenant                string `json:"tenant"`
	SourceClusterID       string `json:"source_cluster_id"`
	TargetClusterID       string `json:"target_cluster_id"`
	ControllerClusterID   string `json:"controller_cluster_id"`
	Enabled               bool   `json:"enabled"`
	AutoFailover          bool   `json:"auto_failover"`
	AutoFailback          bool   `json:"auto_failback"`
	PollSeconds           int    `json:"poll_seconds"`
	SourceFailureChecks   int    `json:"source_failure_checks"`
	TargetReadyChecks     int    `json:"target_ready_checks"`
	FailbackHealthyChecks int    `json:"failback_healthy_checks"`
	FailbackHoldSeconds   int    `json:"failback_hold_seconds"`
	MaxBackupAgeSeconds   int    `json:"max_backup_age_seconds"`
	MaxRPOSeconds         int    `json:"max_rpo_seconds"`
}
type RecoveryConfig struct {
	DRExecutions []DRExecutionProfile `json:"dr_executions,omitempty"`
	DRAutomation []DRAutomationPolicy `json:"dr_automation,omitempty"`
	StagingRoot  string               `json:"staging_root"` // private LOCAL non-NFS snapshot staging
	ResticBinary string               `json:"restic_binary"`
	NFSTargets   []NFSBackupTarget    `json:"nfs_targets"`
	DRTargets    []DRClusterTarget    `json:"dr_targets"`
}

func protectedRecoveryFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: protected path must be absolute and canonical", ErrValidation)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() <= 0 {
		return fmt.Errorf("%w: protected recovery file has unsafe mode", ErrValidation)
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return fmt.Errorf("%w: protected recovery file has unsafe owner or link count", ErrValidation)
	}
	return nil
}

func LoadRecoveryConfig(path string) (RecoveryConfig, error) {
	if err := protectedRecoveryFile(path); err != nil {
		return RecoveryConfig{}, err
	}
	if info, err := os.Lstat(path); err != nil || info.Size() > recoveryConfigLimit {
		return RecoveryConfig{}, ErrValidation
	}
	f, err := os.Open(path)
	if err != nil {
		return RecoveryConfig{}, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, recoveryConfigLimit+1))
	d.DisallowUnknownFields()
	var cfg RecoveryConfig
	if err := d.Decode(&cfg); err != nil {
		return RecoveryConfig{}, err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return RecoveryConfig{}, fmt.Errorf("%w: configuration has extra data", ErrValidation)
	}
	if err := cfg.Validate(); err != nil {
		return RecoveryConfig{}, err
	}
	return cfg, nil
}

func (cfg RecoveryConfig) Validate() error {
	if len(cfg.NFSTargets) == 0 || len(cfg.NFSTargets) > 32 ||
		len(cfg.DRTargets) > 64 || len(cfg.DRExecutions) > 64 || len(cfg.DRAutomation) > 64 || !filepath.IsAbs(cfg.ResticBinary) ||
		filepath.Clean(cfg.ResticBinary) != cfg.ResticBinary ||
		!filepath.IsAbs(cfg.StagingRoot) || filepath.Clean(cfg.StagingRoot) != cfg.StagingRoot {
		return fmt.Errorf("%w: invalid recovery provider settings", ErrValidation)
	}
	if st, err := os.Stat(cfg.ResticBinary); err != nil || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
		return fmt.Errorf("%w: configured Restic binary unavailable", ErrValidation)
	}
	// KubeOne etcd snapshots contain plaintext Kubernetes Secret objects.
	// Stage only on a designated private local filesystem, never on NFS.
	stage, err := os.Lstat(cfg.StagingRoot)
	if err != nil || !stage.IsDir() || stage.Mode().Perm() != 0700 {
		return fmt.Errorf("%w: dedicated private plaintext staging root required", ErrValidation)
	}
	native, ok := stage.Sys().(*syscall.Stat_t)
	var fs unix.Statfs_t
	if !ok || native.Uid != uint32(os.Geteuid()) ||
		unix.Statfs(cfg.StagingRoot, &fs) != nil || uint64(fs.Type) == uint64(unix.NFS_SUPER_MAGIC) {
		return fmt.Errorf("%w: unsafe or NFS plaintext staging root", ErrValidation)
	}
	if resolved, err := filepath.EvalSymlinks(cfg.StagingRoot); err != nil || resolved != cfg.StagingRoot {
		return fmt.Errorf("%w: plaintext staging root contains a symlink", ErrValidation)
	}
	ids := map[string]bool{}
	mounts := map[string]bool{}
	for _, t := range cfg.NFSTargets {
		if t.Tenant == "" || len(t.Tenant) > 128 || strings.ContainsAny(t.Tenant, "\x00\r\n/") ||
			!recoveryIDPattern.MatchString(t.ID) || ids[registryKey(t.Tenant, t.ID)] ||
			strings.TrimSpace(t.DisplayName) == "" || len(t.DisplayName) > 96 ||
			strings.ContainsAny(t.DisplayName, "\r\n\x00") ||
			!filepath.IsAbs(t.MountPath) || filepath.Clean(t.MountPath) != t.MountPath ||
			strings.ContainsAny(t.MountPath, "\x00\r\n\t ") ||
			mounts[t.MountPath] || t.MountPath == "/" ||
			t.MountSource == "" || len(t.MountSource) > 256 ||
			strings.ContainsAny(t.MountSource, "\x00\r\n\t ") ||
			!strings.Contains(t.MountSource, ":") {
			return fmt.Errorf("%w: invalid or duplicate NFS destination", ErrValidation)
		}
		if err := protectedRecoveryFile(t.PasswordFile); err != nil {
			return fmt.Errorf("%w: NFS repository credentials are unavailable", ErrValidation)
		}
		if secret, err := os.Lstat(t.PasswordFile); err != nil || secret.Size() < 24 || secret.Size() > 4096 {
			return fmt.Errorf("%w: encrypted backup password must use a protected strong credential", ErrValidation)
		}
		ids[registryKey(t.Tenant, t.ID)], mounts[t.MountPath] = true, true
	}
	targets := map[string]bool{}
	for _, t := range cfg.DRTargets {
		if t.Tenant == "" || !recoveryIDPattern.MatchString(t.SourceClusterID) ||
			!recoveryIDPattern.MatchString(t.TargetClusterID) ||
			t.SourceClusterID == t.TargetClusterID || !validRecoveryEndpoint(t.APIEndpoint) {
			return fmt.Errorf("%w: invalid DR target registration", ErrValidation)
		}
		key := registryKey(t.Tenant, t.SourceClusterID) + ":" + t.TargetClusterID
		if targets[key] {
			return fmt.Errorf("%w: duplicate DR registration", ErrValidation)
		}
		targets[key] = true
	}
	// An execution profile is a server-registered qualified source/target
	// pair; it does not create fencing credentials or grant itself trust.
	pairs := map[string]bool{}
	for _, e := range cfg.DRExecutions {
		if !recoveryIDPattern.MatchString(e.SourceClusterID) ||
			!recoveryIDPattern.MatchString(e.TargetClusterID) ||
			!validRecoveryEndpoint(e.SourceEndpoint) || e.Tenant == "" ||
			e.SourceClusterID == e.TargetClusterID || len(e.Workloads) != 2 ||
			!filepath.IsAbs(e.FenceEvidenceFile) || filepath.Clean(e.FenceEvidenceFile) != e.FenceEvidenceFile {
			return fmt.Errorf("%w: DR execution profile invalid", ErrValidation)
		}
		found, targetAPI := false, ""
		for _, d := range cfg.DRTargets {
			if d.Tenant == e.Tenant && d.SourceClusterID == e.SourceClusterID && d.TargetClusterID == e.TargetClusterID {
				found, targetAPI = true, d.APIEndpoint
				break
			}
		}
		key := registryKey(e.Tenant, e.SourceClusterID) + ":" + e.TargetClusterID
		if !found || pairs[key] {
			return fmt.Errorf("%w: unregistered or duplicated DR execution", ErrValidation)
		}
		if !validServiceRoute(e.ServiceRoute, e.SourceEndpoint, targetAPI) {
			return fmt.Errorf("%w: DR workload service route must be a distinct https route, not a Kubernetes API endpoint", ErrValidation)
		}
		pairs[key] = true
		if err := protectedRecoveryFile(e.FencePublicKeyFile); err != nil {
			return fmt.Errorf("%w: external fence verifier unavailable", ErrValidation)
		}
		if err := protectedRecoveryFile(e.RecoveryVerifierPublicKeyFile); err != nil {
			return fmt.Errorf("%w: independent DR application/network verifier unavailable", ErrValidation)
		}
		if !filepath.IsAbs(e.RecoveryVerificationFile) || filepath.Clean(e.RecoveryVerificationFile) != e.RecoveryVerificationFile {
			return fmt.Errorf("%w: recovery completion evidence reference invalid", ErrValidation)
		}
		keyData, err := os.ReadFile(e.FencePublicKeyFile)
		if err != nil || len(strings.TrimSpace(string(keyData))) != 64 {
			return fmt.Errorf("%w: external fence verifier key identity invalid", ErrValidation)
		}
		appKey, err := os.ReadFile(e.RecoveryVerifierPublicKeyFile)
		if err != nil || len(strings.TrimSpace(string(appKey))) != 64 || strings.TrimSpace(string(appKey)) == strings.TrimSpace(string(keyData)) {
			return fmt.Errorf("%w: independent application verifier key identity invalid or not separate", ErrValidation)
		}
		for i, w := range e.Workloads {
			if !kubernetesNamespacePattern.MatchString(w.Namespace) ||
				!recoveryIDPattern.MatchString(w.BackupName) || !recoveryIDPattern.MatchString(w.FailbackBackupName) || w.BackupName == w.FailbackBackupName || !recoveryIDPattern.MatchString(w.StorageLocation) || !recoveryIDPattern.MatchString(w.ManagedCredentialRef) ||
				(i == 0 && w.Kind != "STATELESS") || (i == 1 && w.Kind != "STATEFUL") ||
				(i == 0 && (w.PVCName != "" || w.VolumeRecoveryKind != "")) ||
				(i == 1 && (!kubernetesNamespacePattern.MatchString(w.PVCName) ||
					(w.VolumeRecoveryKind != "FSB_KOPIA" && w.VolumeRecoveryKind != "CSI_DATAMOVER"))) {
				return fmt.Errorf("%w: requires one exact stateless and stateful workload", ErrValidation)
			}
		}
		if e.Workloads[0].ManagedCredentialRef != e.Workloads[1].ManagedCredentialRef {
			return fmt.Errorf("%w: DR workloads must use one managed storage credential reference", ErrValidation)
		}
		if e.Workloads[0].Namespace == e.Workloads[1].Namespace {
			return fmt.Errorf("%w: distinct stateless and stateful namespaces required", ErrValidation)
		}
	}
	if err := validateDRAutomation(cfg); err != nil {
		return err
	}
	return nil
}

func validRecoveryEndpoint(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		u.Hostname() == "" || u.Port() != "6443" ||
		strings.ContainsAny(value, "\r\n\x00\\@") {
		return false
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
	}
	return len(host) <= 253 && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".") &&
		!strings.Contains(host, "..") && !strings.ContainsAny(host, " /:[]")
}

// validServiceRoute accepts an https workload origin (default or explicit
// non-API port) on a host that is neither KubeOne API endpoint of the pair.
func validServiceRoute(route string, apiEndpoints ...string) bool {
	u, err := url.Parse(route)
	if err != nil || u.Scheme != "https" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		u.Port() == "6443" || strings.ContainsAny(route, "\r\n\x00\\@") {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	api := *u
	api.Host = net.JoinHostPort(u.Hostname(), "6443")
	if !validRecoveryEndpoint(api.String()) {
		return false
	}
	for _, e := range apiEndpoints {
		a, err := url.Parse(e)
		if err != nil || strings.EqualFold(a.Hostname(), u.Hostname()) {
			return false
		}
	}
	return true
}

// On a production host this validates the exact NFS mount identity rather than
// accepting an ordinary local directory (or an automount which did not mount).
func verifyNFSMount(t NFSBackupTarget) error {
	info, err := os.Lstat(t.MountPath)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: backup destination is not a directory", ErrValidation)
	}
	if resolved, err := filepath.EvalSymlinks(t.MountPath); err != nil || resolved != t.MountPath {
		return fmt.Errorf("%w: NFS destination includes a symlink", ErrValidation)
	}
	var fs unix.Statfs_t
	if unix.Statfs(t.MountPath, &fs) != nil || uint64(fs.Type) != uint64(unix.NFS_SUPER_MAGIC) {
		return fmt.Errorf("%w: destination is not an active NFS filesystem", ErrValidation)
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(raw) > 4<<20 {
		return fmt.Errorf("%w: NFS mount identity unavailable", ErrValidation)
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		split := strings.SplitN(string(line), " - ", 2)
		if len(split) != 2 {
			continue
		}
		first, second := strings.Fields(split[0]), strings.Fields(split[1])
		if len(first) < 6 || len(second) < 2 || first[4] != t.MountPath {
			continue
		}
		if (second[0] == "nfs" || second[0] == "nfs4") &&
			second[1] == t.MountSource && strings.Split(first[5], ",")[0] == "rw" {
			return nil
		}
		return fmt.Errorf("%w: NFS mount has a different source or mode", ErrValidation)
	}
	return fmt.Errorf("%w: exact NFS mount not found", ErrValidation)
}
