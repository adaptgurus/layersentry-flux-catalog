package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Velero restores Kubernetes application objects and PVC bytes via its
// qualified CSI data mover or Kopia filesystem backup. KubeOne itself does
// NOT ship PVC bytes between independent DR clusters; it owns cluster/etcd
// lifecycle only. This path uses typed Kubernetes API objects, never shell.
type nativeVeleroBackup struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		IncludedNamespaces []string `json:"includedNamespaces"`
		StorageLocation    string   `json:"storageLocation"`
	} `json:"spec"`
	Status struct {
		Phase               string    `json:"phase"`
		Errors              int       `json:"errors"`
		Warnings            int       `json:"warnings"`
		StartTimestamp      time.Time `json:"startTimestamp"`
		CompletionTimestamp time.Time `json:"completionTimestamp"`
	} `json:"status"`
}

func (m *RecoveryManager) readVeleroBackup(ctx context.Context, ws Workspace, p DRWorkloadProfile, expectedUID string) (nativeVeleroBackup, error) {
	var b nativeVeleroBackup
	if !m.client.KubeconfigExists(ws) {
		return b, ErrValidation
	}
	args := []string{"--kubeconfig", ws.Kubeconfig, "-n", "velero", "get", "backups.velero.io", p.BackupName, "-o", "json"}
	res, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary, args, m.client.cfg.Environment)
	if err != nil || res.StdoutTruncated || len(res.Stdout) > 1<<20 || len(res.Stdout) == 0 {
		return b, ErrValidation
	}
	if err := json.Unmarshal([]byte(res.Stdout), &b); err != nil {
		return b, ErrValidation
	}
	if b.APIVersion != "velero.io/v1" || b.Kind != "Backup" ||
		b.Metadata.Name != p.BackupName || b.Metadata.Namespace != "velero" ||
		len(b.Metadata.UID) < 16 || len(b.Metadata.UID) > 64 ||
		b.Spec.StorageLocation != p.StorageLocation ||
		len(b.Spec.IncludedNamespaces) != 1 || b.Spec.IncludedNamespaces[0] != p.Namespace ||
		b.Status.Phase != "Completed" || b.Status.Errors != 0 || b.Status.Warnings != 0 ||
		b.Status.CompletionTimestamp.IsZero() || (expectedUID != "" && b.Metadata.UID != expectedUID) {
		return nativeVeleroBackup{}, fmt.Errorf("%w: exact qualified Velero backup unavailable", ErrValidation)
	}
	return b, nil
}

type nativeVeleroRestore struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		BackupName         string   `json:"backupName"`
		IncludedNamespaces []string `json:"includedNamespaces"`
		ExcludedResources  []string `json:"excludedResources"`
		RestorePVs         *bool    `json:"restorePVs"`
		ResourceModifier   struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"resourceModifier"`
	} `json:"spec"`
	Status struct {
		Phase               string    `json:"phase"`
		Errors              int       `json:"errors"`
		Warnings            int       `json:"warnings"`
		CompletionTimestamp time.Time `json:"completionTimestamp"`
	} `json:"status"`
}

func drRestoreName(nonce string, p DRWorkloadProfile) string {
	hash := sha256.Sum256([]byte(nonce + ":" + p.Namespace + ":" + p.BackupName))
	return "lsdr-" + hex.EncodeToString(hash[:12])
}

func (m *RecoveryManager) observeVeleroRestore(ctx context.Context, ws Workspace, name string) (nativeVeleroRestore, error) {
	var value nativeVeleroRestore
	result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "-n", "velero", "get", "restores.velero.io", name, "-o", "json"}, m.client.cfg.Environment)
	if err != nil || result.StdoutTruncated || len(result.Stdout) > 1<<20 || len(result.Stdout) == 0 {
		return value, ErrValidation
	}
	if err := json.Unmarshal([]byte(result.Stdout), &value); err != nil {
		return value, ErrValidation
	}
	if value.APIVersion != "velero.io/v1" || value.Kind != "Restore" ||
		value.Metadata.Name != name || value.Metadata.Namespace != "velero" ||
		len(value.Metadata.UID) < 16 || len(value.Metadata.UID) > 64 {
		return nativeVeleroRestore{}, ErrValidation
	}
	return value, nil
}

// A Kopia file-system restore MUST use a freshly provisioned target PV.
// Never silently adopt the original site's NFS/CSI PV/volumeHandle.
func drKopiaModifierName(name string, p DRWorkloadProfile) string {
	h := sha256.Sum256([]byte(name + ":" + p.Namespace + ":" + p.PVCName))
	return "lsdr-pvc-" + hex.EncodeToString(h[:12])
}

func drKopiaRestoreSpecValid(p DRWorkloadProfile, name string, v nativeVeleroRestore) bool {
	if p.Kind != "STATEFUL" || p.VolumeRecoveryKind != "FSB_KOPIA" {
		return true
	}
	if v.Spec.RestorePVs == nil || *v.Spec.RestorePVs ||
		v.Spec.ResourceModifier.APIGroup != "" ||
		v.Spec.ResourceModifier.Kind != "configmap" ||
		v.Spec.ResourceModifier.Name != drKopiaModifierName(name, p) {
		return false
	}
	for _, r := range v.Spec.ExcludedResources {
		if r == "persistentvolumes" {
			return true
		}
	}
	return false
}

func (m *RecoveryManager) createDRKopiaPVCModifier(ctx context.Context, ws Workspace,
	p DRWorkloadProfile, restoreName string) (string, error) {
	if !kubernetesNamespacePattern.MatchString(p.Namespace) ||
		!kubernetesNamespacePattern.MatchString(p.PVCName) ||
		!recoveryIDPattern.MatchString(restoreName) ||
		p.Kind != "STATEFUL" || p.VolumeRecoveryKind != "FSB_KOPIA" {
		return "", ErrValidation
	}
	name := drKopiaModifierName(restoreName, p)
	// Both identifiers are DNS-label validated: no YAML/regex injection.
	patch := fmt.Sprintf(`version: v1
resourceModifierRules:
  - conditions:
      groupResource: persistentvolumeclaims
      namespaces:
        - %s
      resourceNameRegex: "^%s$"
    patches:
      - operation: remove
        path: /spec/volumeName
`, p.Namespace, p.PVCName)
	doc := map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "immutable": true,
		"metadata": map[string]any{
			"name": name, "namespace": "velero",
			"labels": map[string]string{"layersentry.io/kubeone-dr-restore": "true"},
		},
		"data": map[string]string{"resource-modifier.yaml": patch},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(ws.Directory, ".layersentry-dr-pvc-modifier-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	file := filepath.Join(dir, "modifier.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		return "", err
	}
	result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "create", "-f", file}, m.client.cfg.Environment)
	if err != nil || result.StdoutTruncated {
		return "", errors.New("Kopia modifier creation UNKNOWN; do not retry automatically")
	}
	return name, nil
}

// Refuse to restore over existing application pods/PVCs. Velero's default
// behavior can silently skip existing data; this boundary must never promote
// an old writer's retained volumes as newly recovered application bytes.
func (m *RecoveryManager) targetNamespaceEmpty(ctx context.Context, ws Workspace, p DRWorkloadProfile) error {
	for _, resource := range []string{"pods", "persistentvolumeclaims", "deployments.apps", "statefulsets.apps", "services", "configmaps", "secrets"} {
		result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
			[]string{"--kubeconfig", ws.Kubeconfig, "-n", p.Namespace, "get", resource, "-o", "json"}, m.client.cfg.Environment)
		if err != nil || result.StdoutTruncated || len(result.Stdout) > 1<<20 {
			return ErrValidation
		}
		var value struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal([]byte(result.Stdout), &value); err != nil || value.Items == nil {
			return ErrValidation
		}
		// K8s root-ca publisher automatically creates kube-root-ca.crt per
		// namespace. Its native cluster CA is not transferable application
		// data; do not consider any other ConfigMap an empty target.
		if resource == "configmaps" && len(value.Items) == 1 {
			var cm struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(value.Items[0], &cm) == nil &&
				cm.Metadata.Name == "kube-root-ca.crt" && cm.Metadata.Namespace == p.Namespace &&
				len(cm.Data) == 1 && len(cm.Data["ca.crt"]) > 0 && len(cm.Data["ca.crt"]) <= 32<<10 {
				continue
			}
		}
		if len(value.Items) != 0 {
			return ErrValidation
		}
	}
	return nil
}

func (m *RecoveryManager) createVeleroRestore(ctx context.Context, ws Workspace, p DRWorkloadProfile, name string) (string, error) {
	if !m.client.KubeconfigExists(ws) || !recoveryIDPattern.MatchString(name) {
		return "", ErrValidation
	}
	if err := m.targetNamespaceEmpty(ctx, ws, p); err != nil {
		return "", fmt.Errorf("%w: target namespace cannot be proved clean", ErrValidation)
	}
	// The content is fixed typed Velero v1 Restore schema. The namespace and
	// backup name came from the pinned server-side DR execution profile.
	fsbKopia := p.Kind == "STATEFUL" && p.VolumeRecoveryKind == "FSB_KOPIA"
	spec := map[string]any{
		"backupName":             p.BackupName,
		"includedNamespaces":     []string{p.Namespace},
		"existingResourcePolicy": "none",
		"restorePVs":             p.Kind == "STATEFUL" && !fsbKopia,
	}
	if fsbKopia {
		// Preserve one exact independently allocated target PVC. The source
		// site's native PV identifier MUST NOT be adopted at DR or failback.
		modifier, err := m.createDRKopiaPVCModifier(ctx, ws, p, name)
		if err != nil {
			return "", err
		}
		spec["excludedResources"] = []string{"persistentvolumes"}
		spec["resourceModifier"] = map[string]any{
			"apiGroup": "", "kind": "configmap", "name": modifier,
		}
	}
	doc := map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "Restore",
		"metadata":   map[string]string{"name": name, "namespace": "velero"},
		"spec":       spec,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(ws.Directory, ".layersentry-dr-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	file := filepath.Join(dir, "restore.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		return "", err
	}
	result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "create", "-f", file}, m.client.cfg.Environment)
	if err != nil || result.StdoutTruncated {
		return "", errors.New("Velero restore create outcome UNKNOWN; do not retry automatically")
	}
	observed, err := m.observeVeleroRestore(ctx, ws, name)
	if err != nil {
		return "", errors.New("Velero restore accepted but resource identity is unreadable; do not retry")
	}
	if observed.Spec.BackupName != p.BackupName ||
		len(observed.Spec.IncludedNamespaces) != 1 || observed.Spec.IncludedNamespaces[0] != p.Namespace ||
		!drKopiaRestoreSpecValid(p, name, observed) {
		return "", ErrValidation
	}
	return observed.Metadata.UID, nil
}

func (m *RecoveryManager) verifyVeleroRestore(ctx context.Context, ws Workspace, p DRWorkloadProfile, name, uid string) error {
	end := time.Now().Add(25 * time.Minute)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		v, err := m.observeVeleroRestore(ctx, ws, name)
		if err != nil || v.Metadata.UID != uid || v.Spec.BackupName != p.BackupName ||
			len(v.Spec.IncludedNamespaces) != 1 || v.Spec.IncludedNamespaces[0] != p.Namespace ||
			!drKopiaRestoreSpecValid(p, name, v) {
			return fmt.Errorf("%w: Velero restore identity changed or disappeared", ErrValidation)
		}
		if v.Status.Phase == "Completed" {
			if v.Status.Errors != 0 || v.Status.Warnings != 0 || v.Status.CompletionTimestamp.IsZero() {
				return ErrValidation
			}
			if p.Kind == "STATEFUL" {
				return m.verifyVolumeRestoreEvidence(ctx, ws, p, name, uid)
			}
			return nil
		}
		switch v.Status.Phase {
		case "New", "InProgress", "WaitingForPluginOperations", "Finalizing":
		default:
			return fmt.Errorf("%w: incomplete or failed Velero restore status", ErrValidation)
		}
		if time.Now().After(end) {
			return context.DeadlineExceeded
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Verify a native Velero PodVolumeRestore (Kopia FSB) or CSI DataDownload
// actually reached Completed. A Velero Restore CR alone proves no PVC bytes.
// Every volume operation must belong to THIS Restore object (restore UID, not
// only its reusable deterministic name), and one of them must have written
// into the configured application PVC that is live now.
func (m *RecoveryManager) verifyVolumeRestoreEvidence(ctx context.Context, ws Workspace, p DRWorkloadProfile, name, restoreUID string) error {
	kind := ""
	switch p.VolumeRecoveryKind {
	case "FSB_KOPIA":
		kind = "podvolumerestores.velero.io"
	case "CSI_DATAMOVER":
		kind = "datadownloads.velero.io"
	default:
		return ErrValidation
	}
	if len(restoreUID) < 16 {
		return ErrValidation
	}
	pvcUID, err := m.recoveredPVCUID(ctx, ws, p)
	if err != nil {
		return err
	}
	result, err := m.client.runner.Run(ctx, ws.Directory, m.client.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "-n", "velero", "get", kind, "-l", "velero.io/restore-name=" + name, "-o", "json"}, m.client.cfg.Environment)
	if err != nil || result.StdoutTruncated || len(result.Stdout) > 1<<20 {
		return ErrValidation
	}
	var value struct {
		Items []struct {
			Metadata struct{ Labels map[string]string }
			Spec     struct {
				TargetVolume struct {
					PVC       string `json:"pvc"`
					Namespace string `json:"namespace"`
				} `json:"targetVolume"`
			}
			Status struct{ Phase string }
		}
	}
	if err := json.Unmarshal([]byte(result.Stdout), &value); err != nil || len(value.Items) == 0 || len(value.Items) > 100 {
		return ErrValidation
	}
	wroteApplicationPVC := false
	for _, item := range value.Items {
		if item.Metadata.Labels["velero.io/restore-name"] != name ||
			item.Metadata.Labels["velero.io/restore-uid"] != restoreUID || item.Status.Phase != "Completed" {
			return ErrValidation
		}
		switch p.VolumeRecoveryKind {
		case "FSB_KOPIA":
			// Velero labels each PodVolumeRestore with the restored PVC's UID.
			wroteApplicationPVC = wroteApplicationPVC || item.Metadata.Labels["velero.io/pvc-uid"] == pvcUID
		case "CSI_DATAMOVER":
			// A DataDownload names its target PVC; the restored claim UID is
			// then re-read live above and at promotion.
			wroteApplicationPVC = wroteApplicationPVC ||
				(item.Spec.TargetVolume.PVC == p.PVCName && item.Spec.TargetVolume.Namespace == p.Namespace)
		}
	}
	if !wroteApplicationPVC {
		return fmt.Errorf("%w: no completed volume restore wrote the configured application PVC", ErrValidation)
	}
	return nil
}
