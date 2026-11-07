package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Kubernetes coordination.k8s.io Lease is a distributed *controller*
// election primitive, NOT a source-writer physical/storage fence or witness.
// A dedicated DR-side, independently scoped ServiceAccount must have
// get/patch on one pre-provisioned Lease. Runtime never creates one.
const drKubernetesLeaderNamespace = "kube-system"

// Kubernetes metav1.MicroTime JSON decoding requires a fractional-six-digit
// timestamp; RFC3339Nano strips trailing zeroes and sometimes has NO dot.
const drKubernetesLeaseTimestampLayout = "2006-01-02T15:04:05.000000Z07:00"

type drKubernetesLeaseRecord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string    `json:"holderIdentity"`
		RenewTime            time.Time `json:"renewTime"`
		LeaseDurationSeconds int       `json:"leaseDurationSeconds"`
	} `json:"spec"`
}

type drKubernetesControllerLease struct {
	client              *Client
	target              Workspace
	pair                DRAutomationPolicy
	name, identity, uid string
	duration            time.Duration
}

func drKubernetesLeaderName(a DRAutomationPolicy) string {
	sum := sha256.Sum256([]byte(a.Tenant + "|" + a.SourceClusterID + "|" + a.TargetClusterID))
	return "layersentry-dr-" + hex.EncodeToString(sum[:12])
}
func drKubernetesTenantHash(tenant string) string {
	sum := sha256.Sum256([]byte("layersentry-kubeone-dr-tenant/v1|" + tenant))
	return hex.EncodeToString(sum[:12])
}

func (l *drKubernetesControllerLease) read(ctx context.Context) (drKubernetesLeaseRecord, error) {
	var record drKubernetesLeaseRecord
	if l == nil || l.client == nil || l.client.runner == nil {
		return record, ErrValidation
	}
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	args := []string{"--kubeconfig", l.target.Kubeconfig,
		"-n", drKubernetesLeaderNamespace, "get", "leases.coordination.k8s.io", l.name, "-o", "json"}
	result, err := l.client.runner.Run(c, l.target.Directory, l.client.cfg.KubectlBinary, args, l.client.cfg.Environment)
	if err != nil || result.StdoutTruncated || len(result.Stdout) > 1<<18 {
		return record, ErrValidation
	}
	if err := json.Unmarshal([]byte(result.Stdout), &record); err != nil {
		return record, ErrValidation
	}
	ann := record.Metadata.Annotations
	if record.APIVersion != "coordination.k8s.io/v1" || record.Kind != "Lease" ||
		record.Metadata.Name != l.name || record.Metadata.Namespace != drKubernetesLeaderNamespace ||
		len(record.Metadata.UID) < 16 || len(record.Metadata.UID) > 128 ||
		len(record.Metadata.ResourceVersion) < 1 || len(record.Metadata.ResourceVersion) > 128 ||
		ann["layersentry.io/dr-source"] != l.pair.SourceClusterID ||
		ann["layersentry.io/dr-target"] != l.pair.TargetClusterID ||
		ann["layersentry.io/dr-tenant-hash"] != drKubernetesTenantHash(l.pair.Tenant) ||
		ann["layersentry.io/dr-leader-contract"] != "v1" ||
		record.Spec.LeaseDurationSeconds < l.pair.PollSeconds*3+90 ||
		record.Spec.LeaseDurationSeconds > 3600 ||
		len(record.Spec.HolderIdentity) > 128 {
		return drKubernetesLeaseRecord{}, ErrValidation
	}
	if l.uid != "" && l.uid != record.Metadata.UID {
		return drKubernetesLeaseRecord{}, ErrValidation
	}
	if l.duration != 0 && time.Duration(record.Spec.LeaseDurationSeconds)*time.Second != l.duration {
		return drKubernetesLeaseRecord{}, ErrValidation
	}
	return record, nil
}

func (l *drKubernetesControllerLease) patch(ctx context.Context,
	previous drKubernetesLeaseRecord, now time.Time) error {
	ops := []map[string]any{
		{"op": "test", "path": "/metadata/resourceVersion", "value": previous.Metadata.ResourceVersion},
		{"op": "test", "path": "/metadata/uid", "value": previous.Metadata.UID},
		{"op": "test", "path": "/spec/holderIdentity", "value": previous.Spec.HolderIdentity},
		{"op": "add", "path": "/spec/holderIdentity", "value": l.identity},
		{"op": "add", "path": "/spec/renewTime", "value": now.UTC().Format(drKubernetesLeaseTimestampLayout)},
	}
	raw, err := json.Marshal(ops)
	if err != nil {
		return ErrValidation
	}
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	args := []string{"--kubeconfig", l.target.Kubeconfig, "-n", drKubernetesLeaderNamespace,
		"patch", "leases.coordination.k8s.io", l.name, "--type=json", "-p", string(raw)}
	result, err := l.client.runner.Run(c, l.target.Directory, l.client.cfg.KubectlBinary, args, l.client.cfg.Environment)
	if err != nil || result.StdoutTruncated {
		return ErrValidation
	}
	return nil // never infer ownership from the patch response
}

func (l *drKubernetesControllerLease) Check(ctx context.Context) error {
	record, err := l.read(ctx)
	if err != nil || record.Spec.HolderIdentity != l.identity {
		return ErrValidation
	}
	now := time.Now().UTC()
	if record.Spec.RenewTime.IsZero() ||
		record.Spec.RenewTime.After(now.Add(15*time.Second)) ||
		record.Spec.RenewTime.Add(l.duration).Sub(now) < 30*time.Second {
		return ErrValidation
	}
	return nil
}

func (l *drKubernetesControllerLease) Renew(ctx context.Context) error {
	record, err := l.read(ctx)
	if err != nil || record.Spec.HolderIdentity != l.identity {
		return ErrValidation
	}
	now := time.Now().UTC()
	if record.Spec.RenewTime.IsZero() || record.Spec.RenewTime.After(now.Add(15*time.Second)) ||
		record.Spec.RenewTime.Add(l.duration).Sub(now) < 30*time.Second {
		return ErrValidation
	}
	if err := l.patch(ctx, record, now); err != nil {
		return err
	}
	return l.Check(ctx)
}

func acquireDRKubernetesControllerLease(ctx context.Context, client *Client,
	source, target Workspace, a DRAutomationPolicy) (*drKubernetesControllerLease, error) {
	if client == nil || source.Tenant != a.Tenant || source.ClusterID != a.SourceClusterID ||
		target.Tenant != a.Tenant || target.ClusterID != a.TargetClusterID ||
		target.ExpectedCPNodes < 3 || a.PollSeconds < 15 {
		return nil, ErrValidation
	}
	id, err := newLifecycleJobID()
	if err != nil {
		return nil, err
	}
	l := &drKubernetesControllerLease{client: client, target: target, pair: a,
		name: drKubernetesLeaderName(a), identity: "lsdr-" + id}
	record, err := l.read(ctx)
	if err != nil {
		return nil, err
	}
	l.uid = record.Metadata.UID
	l.duration = time.Duration(record.Spec.LeaseDurationSeconds) * time.Second
	now := time.Now().UTC()
	// Without a clear expiry and clock-grace margin, a different
	// controller cannot seize a still-held native Kubernetes Lease.
	if record.Spec.HolderIdentity != "" {
		if record.Spec.RenewTime.IsZero() ||
			record.Spec.RenewTime.After(now.Add(15*time.Second)) ||
			now.Before(record.Spec.RenewTime.Add(l.duration).Add(30*time.Second)) {
			return nil, errors.New("DR Kubernetes leader is held or its expiry is ambiguous")
		}
	}
	if err := l.patch(ctx, record, now); err != nil {
		return nil, err
	}
	if err := l.Check(ctx); err != nil {
		return nil, err
	}
	return l, nil
}
func (l *drKubernetesControllerLease) String() string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", drKubernetesLeaderNamespace, l.name)
}
