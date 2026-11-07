package lifecycle

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type namespaceRunner struct {
	t            *testing.T
	createCalled bool
}

func (r *namespaceRunner) Run(_ context.Context, _ string, _ string, args, _ []string) (CommandResult, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, " create -f ") {
		r.createCalled = true
		path := args[len(args)-1]
		raw, err := os.ReadFile(path)
		if err != nil {
			r.t.Fatal(err)
		}
		var manifest struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			r.t.Fatal(err)
		}
		if manifest.Metadata.Name != "customer-a" || manifest.Metadata.Labels["layersentry.io/managed"] != "true" || manifest.Metadata.Labels["layersentry.io/tenant-hash"] == "" {
			r.t.Fatalf("unsafe namespace manifest: %#v", manifest)
		}
		return CommandResult{Stdout: "namespace/customer-a created"}, nil
	}
	if strings.Contains(joined, " get namespaces -o json") {
		return CommandResult{Stdout: `{"items":[{"metadata":{"name":"customer-a","labels":{"layersentry.io/managed":"true"}}}]}`}, nil
	}
	return CommandResult{}, nil
}

func TestCreateNamespaceUsesTypedOwnedManifestAndReadback(t *testing.T) {
	root, ws := tempWorkspace(t)
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve("tenant-a", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	runner := &namespaceRunner{t: t}
	client, err := NewClient(registry, runner, ClientConfig{
		KubeOneBinary: executable(t, root, "kubeone"),
		KubectlBinary: executable(t, root, "kubectl"), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	namespace, created, err := client.CreateNamespace(context.Background(), resolved, "customer-a")
	if err != nil || !created || !runner.createCalled || namespace.Name != "customer-a" || !namespace.LayerSentryManaged {
		t.Fatalf("namespace creation failed: namespace=%#v created=%v called=%v err=%v", namespace, created, runner.createCalled, err)
	}
}

func TestCreateNamespaceRejectsUnboundedInput(t *testing.T) {
	client := &Client{}
	for _, name := range []string{"", "UPPER", "../escape", strings.Repeat("a", 64)} {
		if _, _, err := client.CreateNamespace(context.Background(), Workspace{}, name); err == nil {
			t.Fatalf("invalid namespace %q was accepted", name)
		}
	}
}
