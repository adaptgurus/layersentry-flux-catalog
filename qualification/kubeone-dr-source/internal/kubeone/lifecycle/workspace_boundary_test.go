package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

// A shared registry root is not a tenant boundary: every cluster's inputs and
// generated credentials must remain inside its own registered workspace.
func TestRegistryRejectsCrossWorkspaceInputs(t *testing.T) {
	for _, field := range []string{"manifest", "tfjson", "credentials"} {
		for _, link := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/relative", true: "/symlink"}[link], func(t *testing.T) {
				root, ws := tempWorkspace(t)
				foreign := filepath.Join(root, "tenant-b", "cluster-b")
				if err := os.MkdirAll(foreign, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "input"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				ref := "../../tenant-b/cluster-b/input"
				if link {
					if err := os.Symlink(foreign, filepath.Join(root, ws.Directory, "foreign")); err != nil {
						t.Fatal(err)
					}
					ref = "foreign/input"
				}
				switch field {
				case "manifest":
					ws.Manifest = ref
				case "tfjson":
					ws.TFJSON = ref
				case "credentials":
					ws.Credentials = ref
				}
				if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
					t.Fatal("cross-workspace input admitted")
				}
			})
		}
	}
}

func TestRegistryRejectsCrossWorkspaceKubeconfigParent(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-output", true: "existing-output"}[exists], func(t *testing.T) {
			root, ws := tempWorkspace(t)
			foreign := filepath.Join(root, "tenant-b", "cluster-b")
			if err := os.MkdirAll(foreign, 0700); err != nil {
				t.Fatal(err)
			}
			if exists {
				if err := os.WriteFile(filepath.Join(foreign, "kubeconfig"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(foreign, filepath.Join(root, ws.Directory, "foreign")); err != nil {
				t.Fatal(err)
			}
			ws.Kubeconfig, ws.Provisionable, ws.ExpectedNodes = "foreign/kubeconfig", true, 4
			if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
				t.Fatal("cross-workspace kubeconfig admitted")
			}
		})
	}
}

func TestRegistryRejectsAliasedWorkspaceOwnership(t *testing.T) {
	for _, mode := range []string{"same", "symlink", "nested", "root"} {
		t.Run(mode, func(t *testing.T) {
			root, ws := tempWorkspace(t)
			foreign := ws
			foreign.Tenant, foreign.ClusterID = "tenant-b", "cluster-b"
			switch mode {
			case "symlink":
				if err := os.Symlink(filepath.Join(root, ws.Directory), filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				foreign.Directory = "alias"
			case "nested":
				foreign.Directory = filepath.Join(ws.Directory, "nested")
				if err := os.MkdirAll(filepath.Join(root, foreign.Directory), 0700); err != nil {
					t.Fatal(err)
				}
			case "root":
				foreign.Directory = "."
			}
			if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws, foreign}}); err == nil {
				t.Fatal("overlapping workspace ownership admitted")
			}
		})
	}
}

func TestRegistryAllowsSeparateWorkspacesAndContainedPaths(t *testing.T) {
	root, ws := tempWorkspace(t)
	second := ws
	second.Tenant, second.ClusterID, second.Directory = "tenant-b", "cluster-b", "tenant-b/cluster-b"
	for _, item := range []*Workspace{&ws, &second} {
		dir := filepath.Join(root, item.Directory, "inputs")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"kubeone.yaml", "tf.json", "credentials.yaml"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		item.Manifest, item.TFJSON, item.Credentials = "inputs/kubeone.yaml", "inputs/tf.json", "inputs/credentials.yaml"
		item.Kubeconfig, item.Provisionable, item.ExpectedNodes = "inputs/new-kubeconfig", true, 4
	}
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws, second}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []Workspace{ws, second} {
		got, err := registry.Resolve(item.Tenant, item.ClusterID)
		if err != nil || got.Kubeconfig != filepath.Join(root, item.Directory, item.Kubeconfig) {
			t.Fatalf("valid workspace rejected: %v", err)
		}
	}
}
