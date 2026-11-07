package lifecycle

import (
	"context"
	"testing"
	"time"
)

func TestStatusRequiresExactReadyzSuccess(t *testing.T) {
	for _, reply := range []string{"ok", "ok\n", " \tok\r\n", "not ok", "[+]ping ok\n[-]etcd failed\nreadyz check failed", "OK", "token invalid", "", "ok\x00"} {
		t.Run(reply, func(t *testing.T) {
			root, ws := tempWorkspace(t)
			registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := registry.Resolve(ws.Tenant, ws.ClusterID)
			if err != nil {
				t.Fatal(err)
			}
			base := "--kubeconfig " + resolved.Kubeconfig + " "
			runner := &fakeRunner{status: map[string]CommandResult{
				base + "get --raw=/readyz":               {Stdout: reply},
				base + "get nodes -o json":               {Stdout: `{"items":[]}`},
				base + "get pods -n kube-system -o json": {Stdout: `{"items":[]}`},
			}}
			client, err := NewClient(registry, runner, ClientConfig{KubeOneBinary: executable(t, root, "kubeone"), KubectlBinary: executable(t, root, "kubectl"), PollInterval: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			want := reply == "ok" || reply == "ok\n" || reply == " \tok\r\n"
			status, err := client.Status(context.Background(), resolved)
			if status.APIReady != want || (err == nil) != want {
				t.Fatalf("APIReady=%t err=%v want=%t", status.APIReady, err, want)
			}
			if !want && len(runner.calls) != 1 {
				t.Fatal("unhealthy readiness did not stop before further reads")
			}
		})
	}
}
