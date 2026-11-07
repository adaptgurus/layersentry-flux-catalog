package workspaceproof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func manifestFixture(t *testing.T) ([]byte, ManifestBinding) {
	t.Helper()
	raw, err := os.ReadFile("testdata/original-manifest-projection.json")
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		ControlPlane struct {
			Hosts []struct{ PrivateAddress, PublicAddress, SSHHostPublicKey, SSHPrivateKeyFile string }
		}
		StaticWorkers struct {
			Hosts []struct{ PrivateAddress, PublicAddress, SSHHostPublicKey, SSHPrivateKeyFile string }
		}
	}
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	b := ManifestBinding{OriginalSHA256: Digest(raw), PrivateKeyFile: original.ControlPlane.Hosts[0].SSHPrivateKeyFile}
	for i, h := range original.ControlPlane.Hosts {
		b.ControlPlanes[i] = HostBinding{h.PrivateAddress, h.PublicAddress, h.SSHHostPublicKey}
	}
	h := original.StaticWorkers.Hosts[0]
	b.Worker = HostBinding{h.PrivateAddress, h.PublicAddress, h.SSHHostPublicKey}
	// Test-only bastion, deliberately not an enrollment or a live route.
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	b.Bastion = BastionBinding{"10.254.60.97", base64.StdEncoding.EncodeToString(k.Marshal())}
	return raw, b
}

func TestManifestSuccessorPreservesEveryOtherSemanticField(t *testing.T) {
	raw, b := manifestFixture(t)
	out, err := TransformManifest(raw, b)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if json.Unmarshal(raw, &before) != nil || yaml.Unmarshal(out, &after) != nil {
		t.Fatal("decode")
	}
	for _, name := range []string{"controlPlane", "staticWorkers"} {
		hosts := after[name].(map[string]any)["hosts"].([]any)
		for _, v := range hosts {
			h := v.(map[string]any)
			if h["publicAddress"] != h["privateAddress"] || h["sshUsername"] != "ubuntu" || h["bastion"] != b.Bastion.Address || h["bastionPort"] != 22 || h["bastionUser"] != "ubuntu" || h["bastionHostPublicKey"] != b.Bastion.HostPublicKey || h["bastionPrivateKeyFile"] != b.PrivateKeyFile {
				t.Fatal("wrong native host delta")
			}
			delete(h, "bastion")
			delete(h, "bastionPort")
			delete(h, "bastionUser")
			delete(h, "bastionHostPublicKey")
			delete(h, "bastionPrivateKeyFile")
			for _, expected := range append(b.ControlPlanes[:], b.Worker) {
				if h["privateAddress"] == expected.PrivateAddress {
					h["publicAddress"] = expected.PublicAddress
				}
			}
		}
	}
	// JSON normalizes YAML integer types, allowing complete recursive comparison.
	normalized, _ := json.Marshal(after)
	var normalizedAfter map[string]any
	_ = json.Unmarshal(normalized, &normalizedAfter)
	if !reflect.DeepEqual(before, normalizedAfter) {
		t.Fatal("a non-SSH field changed")
	}
	if Digest(raw) != b.OriginalSHA256 {
		t.Fatal("original mutated")
	}
}

func TestManifestSuccessorRejectsHostAndAuthorityChanges(t *testing.T) {
	raw, b := manifestFixture(t)
	for _, tc := range []struct{ name, old, new string }{
		{"root-auth", "\"ubuntu\"", "\"root\""},
		{"string-port", "\"sshPort\": 22", "\"sshPort\": \"22\""},
		{"unknown-host-field", "\"sshPort\": 22", "\"sshPort\": 22, \"sshAgentSocket\": \"agent\""},
		{"wrong-original-key", b.ControlPlanes[0].HostPublicKey, b.ControlPlanes[1].HostPublicKey},
		{"wrong-private-address", "10.254.200.21", "10.254.200.99"},
		{"wrong-native-api", "kubeone.k8c.io/v1beta2", "kubeone.k8c.io/v1beta1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := []byte(strings.ReplaceAll(string(raw), tc.old, tc.new))
			c := b
			c.OriginalSHA256 = Digest(changed)
			if _, err := TransformManifest(changed, c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := TransformManifest(append(raw, ' '), b); err == nil {
		t.Fatal("raw custody drift accepted")
	}
	for _, mutate := range []func(*ManifestBinding){func(c *ManifestBinding) { c.Bastion.Address = c.ControlPlanes[0].PublicAddress }, func(c *ManifestBinding) { c.Bastion.HostPublicKey = c.Worker.HostPublicKey }, func(c *ManifestBinding) { c.PrivateKeyFile = "/root/.ssh/id_rsa" }, func(c *ManifestBinding) { c.Bastion.HostPublicKey = "ssh-ed25519 " + c.Bastion.HostPublicKey }} {
		c := b
		mutate(&c)
		if _, err := TransformManifest(raw, c); err == nil {
			t.Fatal("invalid authority accepted")
		}
	}
}

func TestManifestParserRejectsAmbiguousOrUnboundedYAML(t *testing.T) {
	for _, raw := range []string{
		"a: 1\na: 2\n", "a: &x 1\nb: *x\n", "a: {<<: {b: 1}}\n", "1: value\n", "a: !custom value\n", "a: 1\n---\nb: 2\n", "a: !!binary Zm9v\n", strings.Repeat("[", 34) + "1" + strings.Repeat("]", 34), strings.Repeat("a", MaxManifestBytes+1),
	} {
		if _, err := parseManifest([]byte(raw)); err == nil {
			t.Fatalf("accepted hostile YAML length %d", len(raw))
		}
	}
}
