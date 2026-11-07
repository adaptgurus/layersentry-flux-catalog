package lifecycle

import (
	"net/http"
	"strings"
	"testing"
)

// The fence signs a Velero Backup UID, but a Restore references the Backup by
// NAME. If the named Backup CR is replaced (e.g. deleted and re-synced from a
// different repository generation) after admission, the restore would carry
// bytes the external witness never attested. Every restore is bound to the
// signed UID immediately before and after the native Restore runs.
func TestDRRestoreRefusesBackupReplacedAfterAdmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		swapAfter int
	}{
		{"before-first-restore", 2},
		{"during-first-restore", 3},
		{"before-second-restore", 4},
		{"during-second-restore", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("3", 32)
			x.fence(nonce, "FAILOVER", nil)
			x.runner.mu.Lock()
			x.runner.swapBackupAfterReads = tc.swapAfter
			x.runner.swapBackupUID = strings.Repeat("f", 36)
			x.runner.mu.Unlock()
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatalf("admission (backup unchanged at that point): %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			if job.Status != "UNKNOWN" || job.EvidenceLabel != "UNKNOWN" {
				t.Fatalf("restore of a replaced backup generation was observed as recovered: %+v", job)
			}
			if tc.swapAfter == 2 && x.runner.restoreCalls != 0 {
				t.Fatal("restore created from a backup generation the fence never signed", x.runner.restoreCalls)
			}
			for _, s := range job.Steps {
				if s.State == "RESTORE_COMPLETED" && s.Kind == "STATEFUL" {
					t.Fatal("stateful step completed against a replaced backup", job.Steps)
				}
			}
		})
	}
}

// A Restore CR "Completed" is not PVC-byte evidence. The Kopia
// PodVolumeRestore must belong to THIS Restore object (UID, not only the
// reusable deterministic name) and must have written into the configured
// application PVC.
func TestDRStatefulRestoreRequiresVolumeBytesBoundToRestoreAndPVC(t *testing.T) {
	for _, tc := range []struct {
		name               string
		restoreUID, pvcUID string
	}{
		{"foreign-restore-uid", strings.Repeat("7", 36), ""},
		{"foreign-pvc", "", strings.Repeat("6", 36)},
		{"unlabelled-pvc", "", "-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("4", 32)
			x.fence(nonce, "FAILOVER", nil)
			x.runner.mu.Lock()
			x.runner.pvrRestoreUID, x.runner.pvrPVCUID = tc.restoreUID, tc.pvcUID
			x.runner.mu.Unlock()
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatalf("setup: %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			if job.Status != "UNKNOWN" || job.Steps[1].State == "RESTORE_COMPLETED" {
				t.Fatalf("unbound volume restore accepted as PVC bytes: %+v", job)
			}
		})
	}
}

// Between restore observation and promotion the restored PVC can be deleted
// and re-provisioned empty under the same name (StatefulSet, operator, human).
// A merely Bound PVC with that name is not the recovered volume.
func TestDRCompletionRefusesReplacedRestoredPVC(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("5", 32)
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
		t.Fatalf("setup: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("setup restore", job)
	}
	x.completion(job, nil)
	x.runner.mu.Lock()
	x.runner.pvcUID = strings.Repeat("8", 36) // same name, new empty volume
	x.runner.mu.Unlock()
	if r := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); r.Code != 409 {
		t.Fatalf("replaced PVC promoted as recovered data: %d %s", r.Code, r.Body.String())
	}
	if j, err := readDRTransition(x.ws); err != nil || j.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("journal promoted with replaced PVC", err, j)
	}
	// Positive control: the PVC Velero actually restored is still present.
	x.runner.mu.Lock()
	x.runner.pvcUID = ""
	x.runner.mu.Unlock()
	if r := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); r.Code != 200 {
		t.Fatalf("restored PVC not promoted: %d %s", r.Code, r.Body.String())
	}
}

// Full DC loss: the DR-side controller must finish detection, fenced restore
// and promotion using only DR-site Kubernetes APIs plus external signed
// proofs. Apart from health probes, nothing may be sent to the lost DC.
func TestDRAutomationCompletesWithDCUnreachable(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	autoDRSustainedOutage(t, x, a, &state)
	intent, err := readAutoDRFenceIntent(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	x.fence(intent.OperationID, "FAILOVER", nil)
	automaticDRTickFixture(t, x, a, &state)
	x.completion(x.waitRestore(intent.OperationID), nil)
	automaticDRTickFixture(t, x, a, &state)
	if j, err := readDRTransition(x.ws); err != nil || j.Status != "VERIFIED" || state.State != "DR_ACTIVE" {
		t.Fatal("DR-only continuation did not promote", err, j, state)
	}
	x.runner.mu.Lock()
	defer x.runner.mu.Unlock()
	if len(x.runner.sourceMutationsOrReads) != 0 {
		t.Fatal("failover depended on the lost DC site", x.runner.sourceMutationsOrReads)
	}
}

// The independent verifier attests application TRAFFIC cutover. A proof
// whose routed endpoint is a KubeOne/Kubernetes API server (:6443) only
// shows that a control plane answers, not that customers reach the
// recovered workload on the DR writer. Both directions bind the one
// registered public workload route.
func TestDRCompletionBindsWorkloadRouteNotKubernetesAPI(t *testing.T) {
	for _, apiEndpoint := range []string{"https://dr.lab.internal:6443", "https://dc.lab.internal:6443"} {
		t.Run(apiEndpoint, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("6", 32)
			x.fence(nonce, "FAILOVER", nil)
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatalf("setup: %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			x.completion(job, func(p *DRCompletionProof) { p.RoutedEndpoint = apiEndpoint })
			if r := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); r.Code != 409 {
				t.Fatalf("Kubernetes API reachability accepted as workload traffic cutover: %d %s", r.Code, r.Body.String())
			}
			if j, err := readDRTransition(x.ws); err != nil || j.Status == "VERIFIED" {
				t.Fatal("promoted without workload route proof", err, j)
			}
		})
	}
}

func TestDRExecutionProfileRequiresDistinctWorkloadRoute(t *testing.T) {
	x := setupDRExecutionFixture(t)
	cfg := x.portal.recovery.config
	for route, ok := range map[string]bool{
		"https://shop.tenant-a.example":      true,
		"https://shop.tenant-a.example:8443": true,
		"":                                   false,
		"https://dr.lab.internal:6443":       false, // DR Kubernetes API
		"https://dc.lab.internal":            false, // DC API host on another port
		"https://shop.tenant-a.example:6443": false,
		"http://shop.tenant-a.example":       false,
		"https://shop.tenant-a.example/app":  false,
		"https://user@shop.tenant-a.example": false,
		"https://localhost":                  false,
		"https://shop.tenant-a.example:0443": false,
	} {
		cfg.DRExecutions = []DRExecutionProfile{x.config}
		cfg.DRExecutions[0].ServiceRoute = route
		if err := cfg.Validate(); (err == nil) != ok {
			t.Errorf("service route %q: accepted=%v want %v (%v)", route, err == nil, ok, err)
		}
	}
}
