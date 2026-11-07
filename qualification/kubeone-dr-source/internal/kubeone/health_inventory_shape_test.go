package kubeone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Actual Status/WaitHealthy with synthetic runner output only; no cluster API,
// native lifecycle, kubectl process or membership/DR proof is exercised.
func TestHealthInventoryRejectsAmbiguousReadback(t *testing.T) {
	node := `{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}`
	nodes := `{"items":[` + node + `]}`
	pods := `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"api","ready":true}]}}]}`
	for _, tc := range []struct{ name, nodeReply, podReply string }{
		{"null-nodes", `null`, pods},
		{"missing-node-items", `{}`, pods},
		{"null-node-items", `{"items":null}`, pods},
		{"null-pods", nodes, `null`},
		{"missing-pod-items", nodes, `{}`},
		{"null-pod-items", nodes, `{"items":null}`},
		{"duplicate-node-items", `{"items":[],"items":[` + node + `]}`, pods},
		{"case-aliased-node-items", `{"Items":[` + node + `]}`, pods},
		{"contradictory-ready", strings.Replace(nodes, `{"type":"Ready","status":"True"}`, `{"type":"Ready","status":"True"},{"type":"Ready","status":"False"}`, 1), pods},
		{"duplicate-identical-ready", strings.Replace(nodes, `{"type":"Ready","status":"True"}`, `{"type":"Ready","status":"True"},{"type":"Ready","status":"True"}`, 1), pods},
		{"duplicate-condition-type", strings.Replace(nodes, `"type":"Ready"`, `"type":"MemoryPressure","type":"Ready"`, 1), pods},
		{"duplicate-condition-status", strings.Replace(nodes, `"status":"True"`, `"status":"False","status":"True"`, 1), pods},
		{"case-aliased-condition-type", strings.Replace(nodes, `"type":"Ready"`, `"Type":"Ready"`, 1), pods},
		{"duplicate-pod-phase", nodes, `{"items":[{"status":{"phase":"Pending","phase":"Succeeded"}}]}`},
		{"case-aliased-pod-status", nodes, `{"items":[{"Status":{"phase":"Succeeded"}}]}`},
		{"duplicate-container-record", nodes, `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"api","ready":true},{"name":"api","ready":true}]}}]}`},
		{"missing-container-name", nodes, `{"items":[{"status":{"phase":"Running","containerStatuses":[{"ready":true}]}}]}`},
		{"blank-container-name", nodes, strings.Replace(pods, `"name":"api"`, `"name":" "`, 1)},
		{"missing-container-ready", nodes, `{"items":[{"status":{"phase":"Running","containerStatuses":[{"name":"api"}]}}]}`},
		{"null-container-ready", nodes, strings.Replace(pods, `"ready":true`, `"ready":null`, 1)},
		{"duplicate-container-ready", nodes, strings.Replace(pods, `"ready":true`, `"ready":false,"ready":true`, 1)},
		{"case-aliased-container-ready", nodes, strings.Replace(pods, `"ready":true`, `"Ready":true`, 1)},
		{"trailing-pod-document", nodes, pods + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, ws, runner := identityStatusClient(t, []string{"cp1"})
			base := "--kubeconfig " + ws.Kubeconfig + " "
			runner.status[base+"get nodes -o json"] = CommandResult{Stdout: tc.nodeReply}
			runner.status[base+"get pods -n kube-system -o json"] = CommandResult{Stdout: tc.podReply}
			status, err := client.Status(t.Context(), ws)
			t.Logf("SOURCE_ONLY fault=%s status=%+v err=%v live_cluster_proof=false", tc.name, status, err)
			if !errors.Is(err, ErrValidation) || status.ReadyNodes != 0 || status.ReadyControlPlanes != 0 || len(status.Nodes) != 0 {
				t.Error("malformed or ambiguous native inventory accepted or partially counted")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			last, waitErr := client.WaitHealthy(ctx, ws, 1, 1)
			if !errors.Is(waitErr, context.DeadlineExceeded) || last.ReadyNodes != 0 || last.ReadyControlPlanes != 0 {
				t.Errorf("invalid inventory proved healthy: last=%+v err=%v", last, waitErr)
			}
		})
	}
}

func TestHealthInventoryNativeShapeControls(t *testing.T) {
	for _, tc := range []struct {
		name, nodes, pods string
		healthy           bool
	}{
		{"empty-inventories", `{"items":[]}`, `{"items":[]}`, false},
		{"missing-ready-condition", `{"items":[{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[]}}]}`, `{"items":[]}`, false},
		{"nonready-node", `{"items":[{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`, `{"items":[]}`, false},
		{"running-pod-no-status", "", `{"items":[{"status":{"phase":"Running","containerStatuses":[]}}]}`, false},
		{"completed-pod", "", `{"items":[{"status":{"phase":"Succeeded"}}]}`, true},
		{"native-unknown-enrichment", "", `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"8"},"items":[{"metadata":{"name":"api","namespace":"kube-system"},"status":{"phase":"Running","podIP":"192.0.2.1","containerStatuses":[{"name":"api","ready":true,"restartCount":0,"imageID":"fixture-only"},{"name":"sidecar","ready":true}]}}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, ws, runner := identityStatusClient(t, []string{"cp1"})
			base := "--kubeconfig " + ws.Kubeconfig + " "
			if tc.nodes != "" {
				runner.status[base+"get nodes -o json"] = CommandResult{Stdout: tc.nodes}
			}
			runner.status[base+"get pods -n kube-system -o json"] = CommandResult{Stdout: tc.pods}
			status, err := client.Status(t.Context(), ws)
			if err != nil {
				t.Fatal("native-shaped control rejected", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			_, waitErr := client.WaitHealthy(ctx, ws, 1, 1)
			if (waitErr == nil) != tc.healthy {
				t.Fatal(fmt.Sprint("ordinary readiness control disagrees ", status, waitErr))
			}
		})
	}
}
