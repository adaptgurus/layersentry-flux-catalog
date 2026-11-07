package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Uses the actual installed/compiled portal with private files only. No native
// credentials or Kubernetes resources are present in this startup rejection.
func TestCompiledPortalRejectsCrossWorkspaceInput(t *testing.T) {
	binary := os.Getenv("LAYERSENTRY_KUBEONE_PORTAL_TEST_BINARY")
	if binary == "" {
		t.Skip("explicit compiled portal binary required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("test binary must be absolute")
	}
	root := t.TempDir()
	for _, name := range []string{"cluster-a", "cluster-b"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	foreign := filepath.Join(root, "cluster-b", "kubeone.yaml")
	if err := os.WriteFile(foreign, []byte("# foreign fixture, no hosts\n"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(root, "registry.json")
	if err := os.WriteFile(registry, []byte(`{"clusters":[{"tenant":"tenant-a","cluster_id":"cluster-a","directory":"cluster-a","manifest":"../cluster-b/kubeone.yaml","kubeconfig":"kubeconfig","suspended":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LAYERSENTRY_KUBEONE_WORKSPACE_ROOT=" + root,
		"LAYERSENTRY_KUBEONE_REGISTRY_FILE=" + registry, "LAYERSENTRY_GATEWAY_TOKEN=" + strings.Repeat("x", 32),
		"LAYERSENTRY_KUBEONE_PORTAL_LISTEN=127.0.0.1:0", "LAYERSENTRY_KUBEONE_BIN=/usr/bin/false", "LAYERSENTRY_KUBECTL_BIN=/usr/bin/false"}
	out, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "input path escapes cluster workspace") {
		t.Fatalf("portal did not reject cross-workspace input at startup: %v %s", err, out)
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "# foreign fixture, no hosts\n" {
		t.Fatal("foreign file changed")
	}
}
