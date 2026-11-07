// Package workspaceproof owns the bounded, read-only native observation protocol
// shared by the KubeOne workspace publisher and the native qualification owner.
package workspaceproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var ErrAdmission = errors.New("KubeOne workspace successor admission rejected")

const MaxManifestBytes = 64 << 10

// HostBinding is the previously admitted native node identity. PublicAddress
// is the old address, not a newly discovered SSH key source.
type HostBinding struct {
	PrivateAddress string `json:"private_address"`
	PublicAddress  string `json:"public_address"`
	HostPublicKey  string `json:"host_public_key"`
}

type BastionBinding struct {
	Address       string `json:"address"`
	HostPublicKey string `json:"host_public_key"`
}

// ManifestBinding is server-owned admission. It does not establish native
// enrollment or readiness; those require the fresh privileged observation.
type ManifestBinding struct {
	OriginalSHA256 string         `json:"original_sha256"`
	PrivateKeyFile string         `json:"private_key_file"`
	ControlPlanes  [3]HostBinding `json:"control_planes"`
	Worker         HostBinding    `json:"worker"`
	Bastion        BastionBinding `json:"bastion"`
}

func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validWire(s string) bool {
	if len(s) > 4096 {
		return false
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(wire) != s {
		return false
	}
	key, err := ssh.ParsePublicKey(wire)
	return err == nil && bytes.Equal(key.Marshal(), wire)
}

func validAddress(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s && a.IsPrivate() && !a.IsUnspecified()
}

func (b ManifestBinding) Validate() error {
	if len(b.OriginalSHA256) != 64 || !filepath.IsAbs(b.PrivateKeyFile) || filepath.Clean(b.PrivateKeyFile) != b.PrivateKeyFile || b.PrivateKeyFile != "/var/lib/layersentry/kubeone/lab-dc/kubeone-dc/ssh-private-key" {
		return ErrAdmission
	}
	h, err := hex.DecodeString(b.OriginalSHA256)
	if err != nil || hex.EncodeToString(h) != b.OriginalSHA256 {
		return ErrAdmission
	}
	if !validAddress(b.Bastion.Address) || !validWire(b.Bastion.HostPublicKey) {
		return ErrAdmission
	}
	seen := map[string]bool{b.Bastion.Address: true}
	keys := map[string]bool{b.Bastion.HostPublicKey: true}
	for _, host := range append(b.ControlPlanes[:], b.Worker) {
		if !validAddress(host.PrivateAddress) || !validAddress(host.PublicAddress) || host.PrivateAddress == host.PublicAddress || !validWire(host.HostPublicKey) || keys[host.HostPublicKey] || seen[host.PrivateAddress] || seen[host.PublicAddress] {
			return ErrAdmission
		}
		seen[host.PrivateAddress], seen[host.PublicAddress], keys[host.HostPublicKey] = true, true, true
	}
	return nil
}

func parseManifest(raw []byte) (*yaml.Node, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return nil, ErrAdmission
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var doc, extra yaml.Node
	if d.Decode(&doc) != nil || d.Decode(&extra) != io.EOF || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, ErrAdmission
	}
	count := 0
	var walk func(*yaml.Node, int) bool
	walk = func(n *yaml.Node, depth int) bool {
		count++
		if depth > 32 || count > 4096 || n.Anchor != "" || n.Alias != nil || n.Kind == yaml.AliasNode {
			return false
		}
		switch n.Kind {
		case yaml.DocumentNode:
		case yaml.MappingNode:
			if n.Tag != "!!map" || len(n.Content)%2 != 0 {
				return false
			}
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		case yaml.SequenceNode:
			if n.Tag != "!!seq" {
				return false
			}
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str", "!!bool", "!!int", "!!null":
			default:
				return false
			}
		default:
			return false
		}
		for _, c := range n.Content {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&doc, 0) {
		return nil, ErrAdmission
	}
	return &doc, nil
}

func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func scalar(n *yaml.Node, tag, value string) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == tag && n.Value == value
}
func stringNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// TransformManifest constructs the only admitted delta. The original raw digest
// must already be approved. No filesystem, native operation, or trust update is
// performed here. Original full-wire node keys and every other YAML node remain.
func TransformManifest(raw []byte, b ManifestBinding) ([]byte, error) {
	if b.Validate() != nil || Digest(raw) != b.OriginalSHA256 {
		return nil, ErrAdmission
	}
	doc, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	root := doc.Content[0]
	if !scalar(field(root, "apiVersion"), "!!str", "kubeone.k8c.io/v1beta2") || !scalar(field(root, "kind"), "!!str", "KubeOneCluster") || !scalar(field(root, "name"), "!!str", "layersentry-kubeone-dc") {
		return nil, ErrAdmission
	}
	groups := []struct {
		name  string
		hosts []HostBinding
	}{{"controlPlane", b.ControlPlanes[:]}, {"staticWorkers", []HostBinding{b.Worker}}}
	for _, group := range groups {
		hosts := field(field(root, group.name), "hosts")
		if hosts == nil || hosts.Kind != yaml.SequenceNode || len(hosts.Content) != len(group.hosts) {
			return nil, ErrAdmission
		}
		for i, node := range hosts.Content {
			h := group.hosts[i]
			if node.Kind != yaml.MappingNode || len(node.Content) != 12 {
				return nil, ErrAdmission
			}
			for key, value := range map[string]string{"privateAddress": h.PrivateAddress, "publicAddress": h.PublicAddress, "sshHostPublicKey": h.HostPublicKey, "sshUsername": "ubuntu", "sshPrivateKeyFile": b.PrivateKeyFile} {
				if !scalar(field(node, key), "!!str", value) {
					return nil, ErrAdmission
				}
			}
			if !scalar(field(node, "sshPort"), "!!int", strconv.Itoa(22)) {
				return nil, ErrAdmission
			}
			field(node, "publicAddress").Value = h.PrivateAddress
			for _, pair := range [][2]string{{"bastion", b.Bastion.Address}, {"bastionUser", "ubuntu"}, {"bastionHostPublicKey", b.Bastion.HostPublicKey}, {"bastionPrivateKeyFile", b.PrivateKeyFile}} {
				node.Content = append(node.Content, stringNode(pair[0]), stringNode(pair[1]))
			}
			node.Content = append(node.Content, stringNode("bastionPort"), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "22"})
		}
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if encoder.Encode(doc) != nil || encoder.Close() != nil || out.Len() > MaxManifestBytes {
		return nil, ErrAdmission
	}
	if _, err := parseManifest(out.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
