package lifecycle

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

func TestAPIProxyRegistryRejectsRemoteOrAmbiguousEndpoint(t *testing.T) {
	for _, value := range []string{"https://127.0.0.1:1080", "socks5://10.254.60.97:1080", "socks5://localhost:1080", "socks5://user:pass@127.0.0.1:1080", "socks5://127.0.0.1:01080", "socks5://127.0.0.1:80", "socks5://127.0.0.1:65536", "socks5://127.0.0.1:1080/", "socks5://127.0.0.1:1080?x=y", "socks5://127.0.0.1:1080#x", " socks5://127.0.0.1:1080"} {
		root, ws := secureProxyWorkspace(t)
		ws.APIProxyURL = value
		if _, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}}); err == nil {
			t.Fatalf("unsafe relay admitted: %q", value)
		}
	}
}

func TestAPIProxyCredentialsFailClosedAndRedact(t *testing.T) {
	for _, fault := range []string{"missing", "public", "symlink", "hardlink", "unknown-field", "trailing", "directory-writable", "no-reference"} {
		t.Run(fault, func(t *testing.T) {
			root, ws := secureProxyWorkspace(t)
			ws.APIProxyURL = "socks5://127.0.0.1:19446"
			ws.APIProxyCredentials = "api-relay-credentials.json"
			path := filepath.Join(root, ws.Directory, ws.APIProxyCredentials)
			secret := strings.Repeat("privateSecret", 4)
			raw := []byte(`{"username":"` + strings.Repeat("u", 32) + `","password":"` + secret + `"}`)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing":
				os.Remove(path)
			case "public":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "hardlink":
				os.Link(path, path+".alias")
			case "unknown-field":
				os.WriteFile(path, []byte(strings.TrimSuffix(string(raw), "}")+`,"foreign":true}`), 0600)
			case "trailing":
				os.WriteFile(path, append(raw, []byte(` {}`)...), 0600)
			case "directory-writable":
				os.Chmod(filepath.Dir(path), 0777)
			case "no-reference":
				ws.APIProxyCredentials = ""
			}
			_, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
			if err == nil {
				t.Fatal("unsafe credential custody admitted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("credential disclosed by admission")
			}
		})
	}
}

func TestPortalAPIProxyDownloadUsesNativeExport(t *testing.T) {
	root, ws := secureProxyWorkspace(t)
	ws.APIProxyURL = "socks5://127.0.0.1:19446"
	ws.APIProxyCredentials = "api-relay-credentials.json"
	secret := strings.Repeat("b", 32)
	if err := os.WriteFile(filepath.Join(root, ws.Directory, ws.APIProxyCredentials), []byte(`{"username":"`+strings.Repeat("a", 32)+`","password":"`+secret+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := registry.Resolve(ws.Tenant, ws.ClusterID)
	private := []byte("private-server-proxy-url:" + secret)
	if err := os.WriteFile(resolved.Kubeconfig, private, 0600); err != nil {
		t.Fatal(err)
	}
	public := "apiVersion: v1\nkind: Config\n"
	runner := &fakeRunner{status: map[string]CommandResult{"kubeconfig --manifest " + resolved.Manifest + " -t " + resolved.TFJSON + " --credentials " + resolved.Credentials: {Stdout: public}}}
	client, err := NewClient(registry, runner, ClientConfig{KubeOneBinary: executable(t, root, "native-kubeone"), KubectlBinary: executable(t, root, "native-kubectl")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPortal(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := platformapi.NewGatewayAuth(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	h := auth.Middleware(p.Handler())
	foreign := portalRequest(t, h, http.MethodGet, "/v1/kubernetes/clusters/"+ws.ClusterID+"/kubeconfig", "", "foreign")
	if foreign.Code != http.StatusNotFound || len(runner.calls) != 0 {
		t.Fatal("foreign tenant dispatched export")
	}
	r := portalRequest(t, h, http.MethodGet, "/v1/kubernetes/clusters/"+ws.ClusterID+"/kubeconfig", "", ws.Tenant)
	if r.Code != http.StatusOK || r.Body.String() != strings.TrimSpace(public) || strings.Contains(r.Body.String(), secret) {
		t.Fatal("private relay credentials exported")
	}
	after, err := os.ReadFile(resolved.Kubeconfig)
	if err != nil || string(after) != string(private) {
		t.Fatal("download altered private runtime config")
	}
}

func TestAPIProxyNativeKubectlPreservesEndpointAndTLS(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("native kubectl unavailable")
	}
	kubectl, err = filepath.Abs(kubectl)
	if err != nil {
		t.Fatal(err)
	}
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "one-cluster", true: "ambiguous-clusters"}[ambiguous], func(t *testing.T) {
			root, ws := secureProxyWorkspace(t)
			ws.APIProxyURL = "socks5://127.0.0.1:19446"
			ws.APIProxyCredentials = "api-relay-credentials.json"
			credential := apiProxyCredentials{Username: strings.Repeat("a", 32), Password: strings.Repeat("b", 32)}
			credentialRaw, _ := json.Marshal(credential)
			if err := os.WriteFile(filepath.Join(root, ws.Directory, ws.APIProxyCredentials), credentialRaw, 0600); err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistry(root, RegistryFile{Clusters: []Workspace{ws}})
			if err != nil {
				t.Fatal(err)
			}
			resolved, _ := registry.Resolve(ws.Tenant, ws.ClusterID)
			native := `apiVersion: v1
kind: Config
clusters:
- name: native-cluster
  cluster:
    server: https://10.254.200.10:6443
    certificate-authority-data: Y2EtYnl0ZXM=
users:
- name: native-admin
  user:
    client-certificate-data: Y2VydC1ieXRlcw==
    client-key-data: a2V5LWJ5dGVz
contexts:
- name: native-context
  context:
    cluster: native-cluster
    user: native-admin
current-context: native-context
`
			if ambiguous {
				native = strings.Replace(native, "users:", "- name: foreign-cluster\n  cluster:\n    server: https://foreign.invalid\nusers:", 1)
			}
			script := filepath.Join(root, "kubeone-native-export")
			if err = os.WriteFile(script, []byte("#!/bin/sh\ncat <<'KUBECONFIG'\n"+native+"KUBECONFIG\n"), 0755); err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(registry, noProxySecretRunner{t: t, username: credential.Username, password: credential.Password}, ClientConfig{KubeOneBinary: script, KubectlBinary: kubectl})
			if err != nil {
				t.Fatal(err)
			}
			err = client.PersistKubeconfig(context.Background(), resolved)
			if ambiguous {
				if err == nil {
					t.Fatal("ambiguous native cluster exported")
				}
				prior, e := os.ReadFile(resolved.Kubeconfig)
				if e != nil || string(prior) != "x" {
					t.Fatal("failed publication replaced original")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := ExecRunner{}.Run(context.Background(), resolved.Directory, kubectl, []string{"--kubeconfig", resolved.Kubeconfig, "config", "view", "--raw", "-o", "json"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Clusters []struct {
					Cluster map[string]any `json:"cluster"`
				} `json:"clusters"`
				Users []struct {
					User map[string]any `json:"user"`
				} `json:"users"`
			}
			if json.Unmarshal([]byte(result.Stdout), &doc) != nil || len(doc.Clusters) != 1 || len(doc.Users) != 1 {
				t.Fatal("native consumer could not read persisted credentials")
			}
			c := doc.Clusters[0].Cluster
			u := doc.Users[0].User
			if c["server"] != "https://10.254.200.10:6443" || c["certificate-authority-data"] != "Y2EtYnl0ZXM=" || c["proxy-url"] != "socks5://"+credential.Username+":"+credential.Password+"@127.0.0.1:19446" || c["insecure-skip-tls-verify"] == true || u["client-certificate-data"] != "Y2VydC1ieXRlcw==" || u["client-key-data"] != "a2V5LWJ5dGVz" {
				t.Fatal("relay changed native endpoint or TLS custody")
			}
			info, err := os.Stat(resolved.Kubeconfig)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private kubeconfig mode differs")
			}
			exported, err := client.DownloadKubeconfig(context.Background(), resolved)
			if err != nil || strings.Contains(string(exported), "proxy-url") {
				t.Fatal("private server relay leaked into downloadable native kubeconfig")
			}
		})
	}
}

type noProxySecretRunner struct {
	t                  *testing.T
	username, password string
}

func (r noProxySecretRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	for _, value := range append(append([]string{}, args...), env...) {
		if strings.Contains(value, r.username) || strings.Contains(value, r.password) {
			r.t.Fatal("relay credential disclosed in process arguments or environment")
		}
	}
	return (ExecRunner{}).Run(ctx, dir, binary, args, env)
}

func secureProxyWorkspace(t *testing.T) (string, Workspace) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".layersentry-proxy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	dir := filepath.Join("lab-dc", "kubeone-dc")
	if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kubeone.yaml", "kubeconfig", "tf.json", "credentials.yaml"} {
		if err := os.WriteFile(filepath.Join(root, dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, Workspace{Tenant: "lab-dc", ClusterID: "kubeone-dc", Directory: dir, Manifest: "kubeone.yaml", Kubeconfig: "kubeconfig", TFJSON: "tf.json", Credentials: "credentials.yaml", ExpectedCPNodes: 3}
}
