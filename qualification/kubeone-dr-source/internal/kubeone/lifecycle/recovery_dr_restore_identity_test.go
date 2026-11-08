package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func drIdentityPendingFixture(t *testing.T) (*drTestSite, string, DRTransitionJob) {
	t.Helper()
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("7", 32)
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted {
		t.Fatalf("fixture admission: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatalf("fixture restore: %+v", job)
	}
	return x, nonce, job
}

func writeDRIdentityJournalFixture(t *testing.T, x *drTestSite, job DRTransitionJob) {
	t.Helper()
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drTransitionPath(x.ws), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func legacyDRIdentityFixture(job DRTransitionJob) DRTransitionJob {
	job.RestoreIdentityVersion = 0
	job.Steps = append([]DRRestoreStep(nil), job.Steps...)
	for i := range job.Steps {
		job.Steps[i].RestoreUID = ""
	}
	return job
}

func assertNoDRFenceIntentFixture(t *testing.T, x *drTestSite) {
	t.Helper()
	if _, err := os.Lstat(autoDRFenceIntentPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unqualified recovery created or adopted a fencing intent: %v", err)
	}
}

func TestDRCompletionRejectsReplacedRestoreUID(t *testing.T) {
	for _, stepIndex := range []int{0, 1} {
		kind := []string{"stateless", "stateful"}[stepIndex]
		t.Run(kind, func(t *testing.T) {
			x, _, job := drIdentityPendingFixture(t)
			x.completion(job, nil)
			x.runner.mu.Lock()
			name := job.Steps[stepIndex].RestoreName
			replacement := x.runner.restored[name]
			replacement.Metadata.UID = strings.Repeat("7", 36)
			x.runner.restored[name] = replacement
			x.runner.mu.Unlock()
			r := portalAdminRequest(t, x.handler, http.MethodPost,
				"/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
			if r.Code != http.StatusConflict {
				t.Fatalf("same-name replacement Restore was promoted: HTTP %d %s", r.Code, r.Body.String())
			}
			current, err := readDRTransition(x.ws)
			if err != nil || current.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatalf("replacement altered pending journal: %+v %v", current, err)
			}
		})
	}
}

func TestDRRestoreUIDPersistedBeforeFirstObservation(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("8", 32)
	var observations []string
	var failures []string
	x.runner.beforeRestoreRead = func(name string) {
		job, err := readDRTransition(x.ws)
		if err != nil {
			failures = append(failures, err.Error())
			return
		}
		for _, step := range job.Steps {
			if step.RestoreName != name {
				continue
			}
			if job.Status != "RUNNING" || job.RestoreIdentityVersion != drRestoreIdentityVersion ||
				step.State != "SUBMITTED" || step.RestoreUID != x.runner.restored[name].Metadata.UID {
				failures = append(failures, fmt.Sprintf("UID not durable before GET: %+v", job))
			}
			observations = append(observations, name)
			return
		}
		failures = append(failures, "observed Restore is absent from durable journal")
	}
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted {
		t.Fatalf("fixture admission: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(nonce)
	x.runner.mu.Lock()
	defer x.runner.mu.Unlock()
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || len(observations) != 2 || len(failures) != 0 {
		t.Fatalf("durable created UID observation failed: %+v reads=%v failures=%v", job, observations, failures)
	}
	if !drRestoreIdentitiesBound(job) {
		t.Fatal("completed journal lost created Restore identities")
	}
}

func TestDRCreateResponseUIDRejectsFirstReadReplacement(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("9", 32)
	x.runner.afterRestoreCreated = func(name string) {
		value := x.runner.restored[name]
		value.Metadata.UID = strings.Repeat("9", 36)
		x.runner.restored[name] = value
	}
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted {
		t.Fatalf("fixture admission: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "UNKNOWN" || job.Steps[0].State != "SUBMITTED" ||
		job.Steps[0].RestoreUID != strings.Repeat("e", 36) ||
		job.Steps[1].RestoreUID != "" || x.runner.restoreCalls != 1 {
		t.Fatalf("replacement GET adopted instead of created UID: %+v calls=%d", job, x.runner.restoreCalls)
	}
	if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted || x.runner.restoreCalls != 1 {
		t.Fatalf("UNKNOWN mutation replayed: HTTP %d calls=%d", r.Code, x.runner.restoreCalls)
	}
}

type drIdentityCommandRunner func(context.Context, string, string, []string, []string) (CommandResult, error)

func (f drIdentityCommandRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	return f(ctx, dir, binary, args, env)
}

func TestDRCreateResponseFailureRetainsOnlyKnownIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		malformed  bool
		missingUID bool
	}{
		{name: "malformed-response", malformed: true},
		{name: "valid-response-without-uid", missingUID: true},
		{name: "created-uid-with-unexpected-spec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			base := x.runner
			restoreReads := 0
			base.beforeRestoreRead = func(string) { restoreReads++ }
			x.portal.Client.runner = drIdentityCommandRunner(func(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
				result, err := base.Run(ctx, dir, binary, args, env)
				if err == nil && strings.Contains(strings.Join(args, " "), " create -f ") &&
					strings.HasSuffix(strings.Join(args, " "), " -o json") {
					if tc.malformed {
						result.Stdout = "{"
					} else {
						var created nativeVeleroRestore
						if e := json.Unmarshal([]byte(result.Stdout), &created); e != nil {
							return CommandResult{}, e
						}
						if tc.missingUID {
							created.Metadata.UID = ""
						} else {
							created.Spec.BackupName = "unexpected-backup"
						}
						raw, e := json.Marshal(created)
						if e != nil {
							return CommandResult{}, e
						}
						result.Stdout = string(raw)
					}
				}
				return result, err
			})
			nonce := strings.Repeat("a", 32)
			x.fence(nonce, "FAILOVER", nil)
			if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted {
				t.Fatalf("fixture admission: %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			wantUID, wantState := strings.Repeat("e", 36), "SUBMITTED"
			if tc.malformed || tc.missingUID {
				wantUID, wantState = "", "PENDING"
			}
			base.mu.Lock()
			defer base.mu.Unlock()
			if job.Status != "UNKNOWN" || job.Steps[0].RestoreUID != wantUID ||
				job.Steps[0].State != wantState || base.restoreCalls != 1 || restoreReads != 0 {
				t.Fatalf("ambiguous create was accepted or known UID discarded: %+v calls=%d GETs=%d", job, base.restoreCalls, restoreReads)
			}
		})
	}
}

func TestDRCreatedUIDPersistenceFailureStopsFurtherNativeCalls(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("b", 32)
	faults := make(chan error, 1)
	reads := 0
	x.runner.beforeRestoreRead = func(string) { reads++ }
	x.runner.afterRestoreCreated = func(string) {
		// Only the new test's TempDir journal is faulted. A directory at the
		// publication path forces atomic replacement to fail even under root.
		path := drTransitionPath(x.ws)
		if err := os.Remove(path); err != nil {
			faults <- err
			return
		}
		faults <- os.Mkdir(path, 0700)
	}
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted {
		t.Fatalf("fixture admission: %d %s", r.Code, r.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		x.portal.mu.Lock()
		running := x.portal.running[registryKey(x.ws.Tenant, x.ws.ClusterID)]
		x.portal.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("executor did not stop after journal failure")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-faults:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore creation fault hook was not reached")
	}
	x.runner.mu.Lock()
	defer x.runner.mu.Unlock()
	if x.runner.restoreCalls != 1 || x.runner.modifierCalls != 0 || reads != 0 {
		t.Fatalf("native execution continued without durable UID: restores=%d modifiers=%d GETs=%d",
			x.runner.restoreCalls, x.runner.modifierCalls, reads)
	}
	if _, err := readDRTransition(x.ws); err == nil {
		t.Fatal("unreadable journal became a completed recovery")
	}
}

func TestDRIdentityJournalVersionBoundary(t *testing.T) {
	x, _, job := drIdentityPendingFixture(t)
	if job.RestoreIdentityVersion != drRestoreIdentityVersion || !drRestoreIdentitiesBound(job) {
		t.Fatal("new journal has no complete versioned identity binding")
	}
	future := job
	future.RestoreIdentityVersion = drRestoreIdentityVersion + 1
	writeDRIdentityJournalFixture(t, x, future)
	if _, err := readDRTransition(x.ws); err == nil {
		t.Fatal("unsupported future journal version was accepted")
	}
	missing := job
	missing.Steps = append([]DRRestoreStep(nil), job.Steps...)
	missing.Steps[0].RestoreUID = ""
	writeDRIdentityJournalFixture(t, x, missing)
	if _, err := readDRTransition(x.ws); err == nil {
		t.Fatal("versioned completed step without created UID was accepted")
	}
	legacy := legacyDRIdentityFixture(job)
	writeDRIdentityJournalFixture(t, x, legacy)
	read, err := readDRTransition(x.ws)
	if err != nil || read.RestoreIdentityVersion != 0 || read.Steps[0].RestoreUID != "" {
		t.Fatalf("legacy journal is not readable for reconciliation: %+v %v", read, err)
	}
}

func TestDRLegacyUnfinishedIdentityNeverPromotesOrReplays(t *testing.T) {
	for _, status := range []string{"RUNNING", "UNKNOWN", "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC"} {
		t.Run(status, func(t *testing.T) {
			x, nonce, job := drIdentityPendingFixture(t)
			legacy := legacyDRIdentityFixture(job)
			legacy.Status = status
			writeDRIdentityJournalFixture(t, x, legacy)
			if _, err := readDRTransition(x.ws); err != nil {
				t.Fatal("legacy reconciliation read failed", err)
			}
			x.completion(legacy, nil)
			if r := portalAdminRequest(t, x.handler, http.MethodPost,
				"/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); r.Code != http.StatusConflict {
				t.Fatalf("legacy job promoted without original UID: %d %s", r.Code, r.Body.String())
			}
			if r := x.begin(nonce, "FAILOVER"); r.Code != http.StatusAccepted || x.runner.restoreCalls != 2 {
				t.Fatalf("same-id reconciliation replayed a native restore: %d calls=%d", r.Code, x.runner.restoreCalls)
			}
			fresh := strings.Repeat("c", 32)
			x.fence(fresh, "FAILOVER", nil)
			if r := x.begin(fresh, "FAILOVER"); r.Code != http.StatusConflict || x.runner.restoreCalls != 2 {
				t.Fatalf("legacy job was redispatched under new nonce: %d calls=%d", r.Code, x.runner.restoreCalls)
			}
		})
	}
}

func TestDRAutomationLegacyVerifiedIdentityNeverClaimsActiveOrFences(t *testing.T) {
	x, _, job := drIdentityPendingFixture(t)
	x.completion(job, nil)
	if r := portalAdminRequest(t, x.handler, http.MethodPost,
		"/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); r.Code != http.StatusOK {
		t.Fatalf("qualified positive control: %d %s", r.Code, r.Body.String())
	}
	verified, err := readDRTransition(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyDRIdentityFixture(verified)
	writeDRIdentityJournalFixture(t, x, legacy)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "RESTORE_IDENTITY_RECONCILIATION_REQUIRED" {
		t.Fatalf("legacy history was promoted to active-writer status: %+v", state)
	}
	assertNoDRFenceIntentFixture(t, x)
	dest, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"FAILOVER", "FAILBACK"} {
		if err := x.portal.automaticDRStart(context.Background(), a, x.ws, dest, legacy, direction, &state); err != nil {
			t.Fatal(err)
		}
		if state.State != "RESTORE_IDENTITY_RECONCILIATION_REQUIRED" {
			t.Fatalf("legacy direct automatic start was not blocked: %s %+v", direction, state)
		}
		assertNoDRFenceIntentFixture(t, x)
	}
	fresh := strings.Repeat("d", 32)
	x.fence(fresh, "FAILBACK", nil)
	if r := x.begin(fresh, "FAILBACK"); r.Code != http.StatusConflict || x.runner.restoreCalls != 2 {
		t.Fatalf("legacy verified history authorized reverse recovery: %d calls=%d", r.Code, x.runner.restoreCalls)
	}
}

func TestDRAutomationRejectsVersionedVerifiedWithoutBinding(t *testing.T) {
	x, _, job := drIdentityPendingFixture(t)
	bad := job
	bad.Status, bad.EvidenceLabel = "VERIFIED", "EXTERNAL_RECOVERY_VERIFIED"
	bad.RecoveryProofSHA256 = strings.Repeat("d", 64)
	bad.Steps = append([]DRRestoreStep(nil), job.Steps...)
	bad.Steps[0].State, bad.Steps[0].RestoreUID = "PENDING", ""
	writeDRIdentityJournalFixture(t, x, bad)
	if _, err := readDRTransition(x.ws); err == nil {
		t.Fatal("versioned VERIFIED journal accepted an unbound pending step")
	}
	a := registeredAutoDRPolicy(t, x)
	dest, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	state := AutoDRStatus{}
	err = x.portal.automaticDRTick(context.Background(), a, x.ws, dest, &state)
	if err == nil || state.State != "AMBIGUOUS_TRANSITION" || x.runner.restoreCalls != 2 {
		t.Fatalf("malformed verified history claimed active or dispatched: %+v err=%v calls=%d", state, err, x.runner.restoreCalls)
	}
	assertNoDRFenceIntentFixture(t, x)
}

func TestDRCSIDataMoverBlockedBeforeRestoreAndFenceIntent(t *testing.T) {
	for _, direction := range []string{"FAILOVER", "FAILBACK"} {
		t.Run(direction, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			x.config.Workloads[1].VolumeRecoveryKind = "CSI_DATAMOVER"
			x.portal.recovery.config.DRExecutions[0] = x.config
			if err := x.portal.recovery.config.Validate(); err != nil {
				t.Fatal("qualification gate must not remove the generic CSI profile schema", err)
			}
			nonce := strings.Repeat("e", 32)
			x.fence(nonce, direction, nil)
			if r := x.begin(nonce, direction); r.Code != http.StatusConflict ||
				!strings.Contains(r.Body.String(), "CSI Data Mover") {
				t.Fatalf("unqualified CSI restore was admitted: %d %s", r.Code, r.Body.String())
			}
			dest, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
			if err != nil {
				t.Fatal(err)
			}
			state := AutoDRStatus{ClusterID: x.ws.ClusterID, TargetClusterID: dest.ClusterID, ObservedAt: time.Now().UTC()}
			if err := x.portal.automaticDRStart(context.Background(), a, x.ws, dest, DRTransitionJob{}, direction, &state); err != nil {
				t.Fatal(err)
			}
			if state.State != "VOLUME_RESTORE_NOT_QUALIFIED" {
				t.Fatalf("automatic CSI qualification did not block: %+v", state)
			}
			assertNoDRFenceIntentFixture(t, x)
			if _, err := os.Lstat(drTransitionPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("CSI rejection created a restore journal: %v", err)
			}
			if x.runner.restoreCalls != 0 || x.runner.modifierCalls != 0 {
				t.Fatalf("CSI rejection performed native writes: restores=%d modifiers=%d", x.runner.restoreCalls, x.runner.modifierCalls)
			}
			if direction == "FAILOVER" {
				autoDRSustainedOutage(t, x, a, &state)
				if state.State != "VOLUME_RESTORE_NOT_QUALIFIED" {
					t.Fatalf("sustained outage bypassed CSI qualification: %+v", state)
				}
				assertNoDRFenceIntentFixture(t, x)
			}
		})
	}
}

func TestDRCSICompletedNameOnlyEvidenceNeverQualifiesPVC(t *testing.T) {
	for _, inventedLabel := range []bool{false, true} {
		t.Run(fmt.Sprintf("invented-pvc-uid-label-%v", inventedLabel), func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			profile := x.config.Workloads[1]
			profile.VolumeRecoveryKind = "CSI_DATAMOVER"
			x.runner.pvcUID = strings.Repeat("8", 36) // same name, replacement claim
			name, uid := "lsdr-csi-identity-fixture", strings.Repeat("e", 36)
			labels := map[string]string{"velero.io/restore-name": name, "velero.io/restore-uid": uid}
			if inventedLabel {
				labels["velero.io/pvc-uid"] = x.runner.pvcUID
			}
			payload, err := json.Marshal(map[string]any{
				"apiVersion": "velero.io/v2alpha1", "kind": "DataDownloadList",
				"items": []any{map[string]any{
					"metadata": map[string]any{"name": "csi-download", "namespace": "velero",
						"uid": strings.Repeat("a", 36), "labels": labels},
					"spec":   map[string]any{"targetVolume": map[string]string{"pvc": profile.PVCName, "namespace": profile.Namespace}},
					"status": map[string]string{"phase": "Completed"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			x.portal.Client.runner = drIdentityCommandRunner(func(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
				calls++
				if strings.Contains(strings.Join(args, " "), "get datadownloads.velero.io") {
					return CommandResult{Stdout: string(payload)}, nil
				}
				return x.runner.Run(ctx, dir, binary, args, env)
			})
			if err := x.portal.recovery.verifyVolumeRestoreEvidence(context.Background(), x.ws, profile, name, uid); err == nil ||
				!strings.Contains(err.Error(), "not qualified") {
				t.Fatalf("name-only CSI download qualified a replacement PVC: %v", err)
			}
			if _, err := x.portal.recovery.createVeleroRestore(context.Background(), x.ws, profile, name); err == nil ||
				!strings.Contains(err.Error(), "not qualified") {
				t.Fatalf("direct legacy CSI create helper bypassed qualification: %v", err)
			}
			if calls != 0 {
				t.Fatalf("unqualified CSI path reached native executor: %d calls", calls)
			}
		})
	}
}
