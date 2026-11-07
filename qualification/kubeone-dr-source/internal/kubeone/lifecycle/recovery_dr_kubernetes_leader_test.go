package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type drFakeKubernetesLeaderRunner struct {
	mu                  sync.Mutex
	record              drKubernetesLeaseRecord
	failRead, failPatch bool
	reads, patches      int
}

func newDRFakeKubernetesLeaderRunner(a DRAutomationPolicy) *drFakeKubernetesLeaderRunner {
	r := &drFakeKubernetesLeaderRunner{}
	r.record.APIVersion = "coordination.k8s.io/v1"
	r.record.Kind = "Lease"
	r.record.Metadata.Name = drKubernetesLeaderName(a)
	r.record.Metadata.Namespace = drKubernetesLeaderNamespace
	r.record.Metadata.UID = strings.Repeat("c", 36)
	r.record.Metadata.ResourceVersion = "1"
	r.record.Metadata.Annotations = map[string]string{
		"layersentry.io/dr-source":          a.SourceClusterID,
		"layersentry.io/dr-target":          a.TargetClusterID,
		"layersentry.io/dr-tenant-hash":     drKubernetesTenantHash(a.Tenant),
		"layersentry.io/dr-leader-contract": "v1",
	}
	r.record.Spec.LeaseDurationSeconds = 180
	r.record.Spec.HolderIdentity = ""
	return r
}
func (r *drFakeKubernetesLeaderRunner) Run(_ context.Context, _ string, _ string, args, _ []string) (CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "leases.coordination.k8s.io") {
		return CommandResult{}, ErrValidation
	}
	if strings.Contains(joined, " get leases.coordination.k8s.io ") {
		r.reads++
		if r.failRead {
			return CommandResult{}, errors.New("DR API unavailable")
		}
		raw, _ := json.Marshal(r.record)
		return CommandResult{Stdout: string(raw)}, nil
	}
	if strings.Contains(joined, " patch leases.coordination.k8s.io ") {
		if r.failPatch {
			return CommandResult{}, errors.New("Kubernetes RBAC denied patch")
		}
		payload := ""
		for i, a := range args {
			if a == "-p" && i+1 < len(args) {
				payload = args[i+1]
			}
		}
		var ops []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal([]byte(payload), &ops); err != nil {
			return CommandResult{}, err
		}
		if len(ops) != 5 {
			return CommandResult{}, errors.New("unqualified JSON patch shape")
		}
		wanted := []struct{ op, path, value string }{
			{"test", "/metadata/resourceVersion", r.record.Metadata.ResourceVersion},
			{"test", "/metadata/uid", r.record.Metadata.UID},
			{"test", "/spec/holderIdentity", r.record.Spec.HolderIdentity},
			{"add", "/spec/holderIdentity", ""},
			{"add", "/spec/renewTime", ""},
		}
		var holder string
		var renew time.Time
		for i, o := range ops {
			if o.Op != wanted[i].op || o.Path != wanted[i].path {
				return CommandResult{}, errors.New("wrong CAS operation")
			}
			var s string
			if err := json.Unmarshal(o.Value, &s); err != nil {
				return CommandResult{}, err
			}
			if i < 3 && s != wanted[i].value {
				return CommandResult{}, errors.New("resourceVersion/UID/holder CAS conflict")
			}
			if i == 3 {
				holder = s
			}
			if i == 4 {
				var err error
				renew, err = time.Parse(drKubernetesLeaseTimestampLayout, s)
				if err != nil {
					return CommandResult{}, err
				}
			}
		}
		if !strings.HasPrefix(holder, "lsdr-") {
			return CommandResult{}, errors.New("invalid elected identity")
		}
		r.record.Spec.HolderIdentity = holder
		r.record.Spec.RenewTime = renew
		n, err := strconv.Atoi(r.record.Metadata.ResourceVersion)
		if err != nil {
			return CommandResult{}, err
		}
		r.record.Metadata.ResourceVersion = fmt.Sprint(n + 1)
		r.patches++
		return CommandResult{Stdout: "lease patched"}, nil
	}
	return CommandResult{}, ErrValidation
}

func leaderTestIdentity(a DRAutomationPolicy) (Workspace, Workspace) {
	return Workspace{Tenant: a.Tenant, ClusterID: a.SourceClusterID, Directory: "/tmp", Kubeconfig: "/tmp/source-kubeconfig", ExpectedCPNodes: 3},
		Workspace{Tenant: a.Tenant, ClusterID: a.TargetClusterID, Directory: "/tmp", Kubeconfig: "/tmp/dr-kubeconfig", ExpectedCPNodes: 3}
}
func leaderTestPolicy() DRAutomationPolicy {
	return DRAutomationPolicy{Tenant: "tenant-a", SourceClusterID: "cluster-a",
		TargetClusterID: "cluster-dr", ControllerClusterID: "cluster-dr", PollSeconds: 15}
}

func TestDRNativeKubernetesLeaseElectionRefusesDuplicateAndRevocation(t *testing.T) {
	a := leaderTestPolicy()
	source, target := leaderTestIdentity(a)
	fake := newDRFakeKubernetesLeaderRunner(a)
	client := &Client{runner: fake, cfg: ClientConfig{KubectlBinary: "kubectl"}}
	first, err := acquireDRKubernetesControllerLease(context.Background(), client, source, target, a)
	if err != nil {
		t.Fatal("qualified pre-provisioned lease cannot be acquired", err)
	}
	if err := first.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireDRKubernetesControllerLease(context.Background(), client, source, target, a); err == nil {
		t.Fatal("two controllers acquired the same live DR lease")
	}
	if err := first.Renew(context.Background()); err != nil {
		t.Fatal("actual owner cannot CAS renew", err)
	}
	fake.mu.Lock()
	fake.record.Spec.HolderIdentity = "external-other-holder"
	fake.mu.Unlock()
	if err := first.Check(context.Background()); err == nil {
		t.Fatal("displaced leader still claimed authority")
	}
	if err := first.Renew(context.Background()); err == nil {
		t.Fatal("displaced leader renewed foreign lease")
	}
}

func TestDRNativeKubernetesLeaseRejectsMissingOrUntrustedAdoption(t *testing.T) {
	a := leaderTestPolicy()
	src, dr := leaderTestIdentity(a)
	for _, tc := range []struct {
		name   string
		mutate func(*drFakeKubernetesLeaderRunner)
	}{
		{"missing", func(f *drFakeKubernetesLeaderRunner) { f.failRead = true }},
		{"wrong_tenant", func(f *drFakeKubernetesLeaderRunner) {
			f.record.Metadata.Annotations["layersentry.io/dr-tenant-hash"] = "foreign"
		}},
		{"wrong_source", func(f *drFakeKubernetesLeaderRunner) {
			f.record.Metadata.Annotations["layersentry.io/dr-source"] = "another-dc"
		}},
		{"wrong_name", func(f *drFakeKubernetesLeaderRunner) { f.record.Metadata.Name = "foreign-lease" }},
		{"unsafe_duration", func(f *drFakeKubernetesLeaderRunner) { f.record.Spec.LeaseDurationSeconds = 30 }},
		{"rbac_denied", func(f *drFakeKubernetesLeaderRunner) { f.failPatch = true }},
		{"active_other_holder", func(f *drFakeKubernetesLeaderRunner) {
			f.record.Spec.HolderIdentity = "existing-owner"
			f.record.Spec.RenewTime = time.Now().UTC()
		}},
		{"future_clock", func(f *drFakeKubernetesLeaderRunner) {
			f.record.Spec.HolderIdentity = "existing-owner"
			f.record.Spec.RenewTime = time.Now().UTC().Add(time.Hour)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newDRFakeKubernetesLeaderRunner(a)
			tc.mutate(fake)
			client := &Client{runner: fake, cfg: ClientConfig{KubectlBinary: "kubectl"}}
			if _, err := acquireDRKubernetesControllerLease(context.Background(), client, src, dr, a); err == nil {
				t.Fatal("missing/mismatched/untrusted distributed leader admitted")
			}
		})
	}
}
func TestDRNativeKubernetesLeaseAllowsExpiredCASOnly(t *testing.T) {
	a := leaderTestPolicy()
	src, dr := leaderTestIdentity(a)
	fake := newDRFakeKubernetesLeaderRunner(a)
	fake.record.Spec.HolderIdentity = "abandoned-stale-owner"
	fake.record.Spec.RenewTime = time.Now().UTC().Add(-15 * time.Minute)
	client := &Client{runner: fake, cfg: ClientConfig{KubectlBinary: "kubectl"}}
	owned, err := acquireDRKubernetesControllerLease(context.Background(), client, src, dr, a)
	if err != nil {
		t.Fatal("stale leader under valid pre-provisioned lease not replaceable by CAS", err)
	}
	if err := owned.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDRNativeKubernetesLeaseRuntimeBlocksUnprovisionedController(t *testing.T) {
	x := setupDRExecutionFixture(t)
	_ = registeredAutoDRPolicy(t, x)
	x.runner.mu.Lock()
	x.runner.drKubeLeader = nil
	x.runner.mu.Unlock()
	if err := x.portal.RunDRAutomation(context.Background(), "cluster-dr"); err == nil {
		t.Fatal("enabled automatic DR ran without independently provisioned distributed Kubernetes Lease")
	}
	x.portal.mu.Lock()
	active := x.portal.autoDRRunning
	x.portal.mu.Unlock()
	if active {
		t.Fatal("unqualified controller retained active state after Lease admission failure")
	}
}

func TestDRNativeKubernetesLeaseUsesMicroTimeWireFormat(t *testing.T) {
	when := time.Date(2026, 11, 7, 16, 17, 3, 0, time.UTC)
	encoded := when.Format(drKubernetesLeaseTimestampLayout)
	if encoded != "2026-11-07T16:17:03.000000Z" {
		t.Fatalf("Kubernetes MicroTime JSON cannot parse timestamp %q", encoded)
	}
	observed, err := time.Parse(drKubernetesLeaseTimestampLayout, encoded)
	if err != nil || !observed.Equal(when) {
		t.Fatal("microsecond Lease time failed round trip", err, observed)
	}
	when = when.Add(123456789 * time.Nanosecond)
	encoded = when.Format(drKubernetesLeaseTimestampLayout)
	if encoded != "2026-11-07T16:17:03.123456Z" {
		t.Fatalf("Kubernetes Lease renewal time has wrong microsecond precision: %q", encoded)
	}
}
