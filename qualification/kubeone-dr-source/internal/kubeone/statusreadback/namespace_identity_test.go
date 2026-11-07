package statusreadback

import (
	"strings"
	"testing"
)

const namespaceIdentityFixture = `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"Opaque-UID-Aa"}}`

func TestKubeSystemNamespaceUIDPreservesOpaqueIdentity(t *testing.T) {
	for _, raw := range []string{namespaceIdentityFixture, strings.Replace(namespaceIdentityFixture, `"uid":"Opaque-UID-Aa"`, `"uid":"Opaque-UID-Aa","labels":{"source":"fixture"}`, 1)} {
		uid, err := KubeSystemNamespaceUID(raw)
		if err != nil || uid != "Opaque-UID-Aa" {
			t.Fatalf("uid=%q err=%v", uid, err)
		}
	}
}

func TestKubeSystemNamespaceUIDRejectsAmbiguousOrIncompleteReadback(t *testing.T) {
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]", "trailing": namespaceIdentityFixture + `{}`,
		"version":       strings.Replace(namespaceIdentityFixture, `"v1"`, `"v2"`, 1),
		"kind":          strings.Replace(namespaceIdentityFixture, `"Namespace"`, `"NamespaceList"`, 1),
		"name":          strings.Replace(namespaceIdentityFixture, `"kube-system"`, `"other"`, 1),
		"metadata-null": `{"apiVersion":"v1","kind":"Namespace","metadata":null}`,
		"missing-uid":   `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system"}}`,
		"huge":          strings.Repeat(" ", maxBytes+1),
		"depth":         strings.Replace(namespaceIdentityFixture, `"uid":"Opaque-UID-Aa"`, `"uid":"ok","opaque":`+strings.Repeat("[", maxDepth)+`0`+strings.Repeat("]", maxDepth), 1),
		"invalid-utf8":  strings.Replace(namespaceIdentityFixture, "Opaque-UID-Aa", string([]byte{0xff}), 1),
	}
	for _, key := range []string{"apiVersion", "kind", "metadata", "name", "uid"} {
		needle := `"` + key + `":`
		cases["alias-"+key] = strings.Replace(namespaceIdentityFixture, needle, `"`+strings.ToUpper(key)+`":`, 1)
		var value string
		switch key {
		case "apiVersion":
			value = `"v1"`
		case "kind":
			value = `"Namespace"`
		case "metadata":
			value = `{}`
		case "name":
			value = `"kube-system"`
		case "uid":
			value = `"Opaque-UID-Aa"`
		}
		cases["duplicate-"+key] = strings.Replace(namespaceIdentityFixture, needle, needle+value+`,`+needle, 1)
	}
	for _, value := range []string{`null`, `1`, `true`, `{}`, `[]`, `""`, `" x"`, `"x "`, `"x\n"`, `"x\u0000"`, `"\ud800"`, `"\udc00"`} {
		cases["uid-"+value] = strings.Replace(namespaceIdentityFixture, `"Opaque-UID-Aa"`, value, 1)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if uid, err := KubeSystemNamespaceUID(raw); err == nil || uid != "" {
				t.Fatalf("invalid observation accepted uid=%q err=%v", uid, err)
			}
		})
	}
}
