package statusreadback

import (
	"encoding/json"
	"strings"
	"unicode"
)

// KubeSystemNamespaceUID observes one namespace object instance. It does not
// identify an etcd cluster or establish quorum, storage or recovery independence.
func KubeSystemNamespaceUID(raw string) (string, error) {
	if bounded(raw) != nil {
		return "", errInventory
	}
	root, err := object(json.RawMessage(raw), "apiVersion", "kind", "metadata")
	if err != nil {
		return "", errInventory
	}
	apiVersion, err := text(root["apiVersion"])
	if err != nil || apiVersion != "v1" {
		return "", errInventory
	}
	kind, err := text(root["kind"])
	if err != nil || kind != "Namespace" {
		return "", errInventory
	}
	metadata, err := object(root["metadata"], "name", "uid")
	if err != nil {
		return "", errInventory
	}
	name, err := text(metadata["name"])
	if err != nil || name != "kube-system" {
		return "", errInventory
	}
	uid, err := text(metadata["uid"])
	if err != nil || uid == "" || strings.IndexFunc(uid, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return "", errInventory
	}
	// Preserve the opaque UID exactly; never case-fold or reinterpret it as a UUID.
	return uid, nil
}
