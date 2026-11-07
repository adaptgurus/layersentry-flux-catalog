package kubeone

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Synthetic runner replies only; no native/customer workspace or cluster API.
func identityStatusClient(t *testing.T, names []string) (*Client, Workspace, *fakeRunner) {
	t.Helper()
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(ws.Tenant, ws.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": name, "labels": map[string]string{"node-role.kubernetes.io/control-plane": ""}},
			"status":   map[string]any{"conditions": []map[string]string{{"type": "Ready", "status": "True"}}},
		})
	}
	raw, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	base := "--kubeconfig " + resolved.Kubeconfig + " "
	runner := &fakeRunner{status: map[string]CommandResult{
		base + "get --raw=/readyz":               {Stdout: "ok"},
		base + "get nodes -o json":               {Stdout: string(raw)},
		base + "get pods -n kube-system -o json": {Stdout: `{"items":[]}`},
	}}
	client, err := NewClient(registry, runner, ClientConfig{KubeOneBinary: executable(t, root, "kubeone"), KubectlBinary: executable(t, root, "kubectl"), PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return client, resolved, runner
}

func TestStatusRequiresDistinctNodeIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"duplicate", []string{"cp1", "cp1", "cp1"}},
		{"empty", []string{"cp1", "", "cp3"}},
		{"blank", []string{"cp1", " \t", "cp3"}},
		{"noncanonical", []string{"cp1", " cp2 ", "cp3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, ws, runner := identityStatusClient(t, tc.names)
			status, err := client.Status(t.Context(), ws)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("invalid node identity accepted: status=%+v err=%v", status, err)
			}
			if status.ReadyNodes != 0 || status.ReadyControlPlanes != 0 || len(status.Nodes) != 0 {
				t.Fatalf("partial invalid inventory counted as readiness: %+v", status)
			}
			if len(runner.calls) != 2 {
				t.Fatalf("invalid node inventory did not stop before pod read: calls=%d", len(runner.calls))
			}
		})
	}
}

func TestWaitHealthyDoesNotCountRepeatedNodeIdentity(t *testing.T) {
	client, ws, _ := identityStatusClient(t, []string{"cp1", "cp1", "cp1"})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	status, err := client.WaitHealthy(ctx, ws, 3, 3)
	if !errors.Is(err, context.DeadlineExceeded) || status.ReadyControlPlanes != 0 {
		t.Fatalf("one repeated node satisfied three-control-plane health: status=%+v err=%v", status, err)
	}
}

func TestWaitHealthyCountsDistinctNodeIdentity(t *testing.T) {
	client, ws, runner := identityStatusClient(t, []string{"cp1", "cp2", "cp3"})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	status, err := client.WaitHealthy(ctx, ws, 3, 3)
	if err != nil || status.ReadyNodes != 3 || status.ReadyControlPlanes != 3 || len(runner.calls) != 3 {
		t.Fatalf("valid distinct nodes failed health: status=%+v err=%v calls=%d", status, err, len(runner.calls))
	}
}
