package statusreadback

import (
	"fmt"
	"strings"
	"testing"
)

func TestInventoryDocumentAndUnicodeBoundaries(t *testing.T) {
	for name, raw := range map[string]string{
		"null": `null`, "missing-items": `{}`, "null-items": `{"items":null}`, "object-items": `{"items":{}}`, "null-item": `{"items":[null]}`,
		"duplicate-decoded-key": `{"items":[],"it\u0065ms":[]}`, "case-alias": `{"ITEMS":[]}`, "trailing": `{"items":[]} {}`,
		"raw-invalid-utf8": "{\"items\":[],\"ignored\":\"\xff\"}", "unpaired-high": `{"items":[],"ignored":"\ud800"}`, "unpaired-low": `{"items":[],"ignored":"\udc00"}`, "wrong-low": `{"items":[],"ignored":"\ud800\u0061"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Nodes(raw); err == nil {
				t.Fatal("invalid node document accepted")
			}
			if _, err := Pods(raw); err == nil {
				t.Fatal("invalid pod document accepted")
			}
		})
	}
	for name, raw := range map[string]string{
		"empty": `{"items":[]}`, "escaped-single-key": `{"it\u0065ms":[]}`, "paired-surrogate": `{"items":[],"ignored":"\ud83d\ude00"}`, "escaped-backslash": `{"items":[],"ignored":"\\ud800"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Nodes(raw); err != nil {
				t.Fatal(err)
			}
			if _, err := Pods(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInventorySelectedShapes(t *testing.T) {
	for name, item := range map[string]string{
		"null-metadata": `{"metadata":null}`, "number-name": `{"metadata":{"name":1}}`, "null-name": `{"metadata":{"name":null}}`, "duplicate-name": `{"metadata":{"name":"a","n\u0061me":"b"}}`, "case-status": `{"Status":{}}`, "null-status": `{"status":null}`,
		"null-labels": `{"metadata":{"labels":null}}`, "bad-role-value": `{"metadata":{"labels":{"node-role.kubernetes.io/control-plane":true}}}`,
		"null-conditions": `{"status":{"conditions":null}}`, "null-condition": `{"status":{"conditions":[null]}}`, "missing-condition-type": `{"status":{"conditions":[{"status":"True"}]}}`, "null-condition-status": `{"status":{"conditions":[{"type":"Ready","status":null}]}}`, "boolean-condition": `{"status":{"conditions":[{"type":"Ready","status":true}]}}`, "duplicate-ready": `{"status":{"conditions":[{"type":"Ready","status":"False"},{"type":"Ready","status":"True"}]}}`,
	} {
		t.Run("node/"+name, func(t *testing.T) {
			if nodes, err := Nodes(`{"items":[` + item + `]}`); err == nil || nodes != nil {
				t.Fatal("malformed selected node projection accepted")
			}
		})
	}
	for name, status := range map[string]string{
		"null": `null`, "null-phase": `{"phase":null}`, "number-phase": `{"phase":3}`, "null-containers": `{"phase":"Running","containerStatuses":null}`, "null-container": `{"phase":"Running","containerStatuses":[null]}`, "number-name": `{"phase":"Running","containerStatuses":[{"name":5,"ready":true}]}`, "null-name": `{"phase":"Running","containerStatuses":[{"name":null,"ready":true}]}`, "string-ready": `{"phase":"Running","containerStatuses":[{"name":"a","ready":"true"}]}`, "null-ready": `{"phase":"Running","containerStatuses":[{"name":"a","ready":null}]}`, "missing-ready": `{"phase":"Running","containerStatuses":[{"name":"a"}]}`, "duplicate-decoded-name": `{"phase":"Running","containerStatuses":[{"name":"a","ready":true},{"name":"\u0061","ready":true}]}`,
	} {
		t.Run("pod/"+name, func(t *testing.T) {
			if pods, err := Pods(`{"items":[{"status":` + status + `}]}`); err == nil || pods != nil {
				t.Fatal("malformed selected pod projection accepted")
			}
		})
	}
}

func TestInventoryBoundsIncludeIgnoredEnrichment(t *testing.T) {
	base := `{"items":[]}`
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"byte-at-limit", base + strings.Repeat(" ", maxBytes-len(base)), true},
		{"byte-over-limit", base + strings.Repeat(" ", maxBytes-len(base)+1), false},
		{"scalar-at-limit", `{"items":[],"ignored":"` + strings.Repeat("x", maxScalar) + `"}`, true},
		{"scalar-over-limit", `{"items":[],"ignored":"` + strings.Repeat("x", maxScalar+1) + `"}`, false},
		{"depth-at-limit", `{"items":[],"ignored":` + strings.Repeat("[", maxDepth-1) + "0" + strings.Repeat("]", maxDepth-1) + `}`, true},
		{"depth-over-limit", `{"items":[],"ignored":` + strings.Repeat("[", maxDepth) + "0" + strings.Repeat("]", maxDepth) + `}`, false},
		{"tokens-at-limit", `{"items":[],"ignored":[` + strings.Repeat("0,", maxTokens-9) + "0" + `]}`, true},
		{"tokens-over-limit", `{"items":[],"ignored":[` + strings.Repeat("0,", maxTokens-8) + "0" + `]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Nodes(tc.raw); (err == nil) != tc.valid {
				t.Fatal(fmt.Sprint("ignored enrichment bound mismatch: ", err))
			}
		})
	}
}

func TestInventoryNativeProjectionControls(t *testing.T) {
	nodes, err := Nodes(`{"items":[{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":"","other":"enrichment"}},"status":{"conditions":[{"type":"MemoryPressure","status":"False"},{"type":"Ready","status":"True","lastTransitionTime":"2026-10-15T00:00:00Z"}]}}]}`)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "cp1" || !nodes[0].Ready || !nodes[0].ControlPlane {
		t.Fatal("native node projection rejected", err)
	}
	pods, err := Pods(`{"items":[{"status":{"phase":"Succeeded"}},{"status":{"phase":"Running","containerStatuses":[{"name":"a","ready": true,"restartCount":1},{"name":"b","ready":false}]}}]}`)
	if err != nil || len(pods) != 2 || pods[0].Phase != "Succeeded" || pods[1].ContainersReady {
		t.Fatal("ordinary completed/nonready pod projection changed", err)
	}
}
