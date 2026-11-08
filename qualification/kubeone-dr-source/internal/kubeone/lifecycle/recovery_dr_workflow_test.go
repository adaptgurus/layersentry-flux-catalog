package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type drNativeRunner struct {
	*recoveryFakeRunner
	mu                  sync.Mutex
	restored            map[string]nativeVeleroRestore
	restoreCalls        int
	modifierCalls       int
	backupUID           string
	drKubeLeader        *drFakeKubernetesLeaderRunner
	failRestore         bool
	dirtyTarget         bool
	unhealthyPVC        bool
	sourceDown          bool
	healthReadDelay     time.Duration
	drDown              bool
	workerUnreadySite   string // test-only: one worker goes NotReady after restore
	staleBackup         bool
	backupStartedAt     time.Time // zero: started one second before completion
	autoRootCA          bool
	foreignConfigMap    bool
	onRecoveredPVCRead  func()
	afterRestoreCreated func(string) // called under mu, after create response is encoded
	beforeRestoreRead   func(string) // called under mu, before native GET readback
	// Backup CR replaced (same name, new UID) after the first N reads.
	backupReads, swapBackupAfterReads int
	swapBackupUID                     string
	pvcUID                            string // live restored PVC UID; empty: default
	pvrRestoreUID, pvrPVCUID          string // override PodVolumeRestore labels
	// Every non-health-probe command run against the DC (cluster-a) site.
	sourceMutationsOrReads []string
}

const drFixturePVCUID = "99999999-9999-4999-8999-999999999999"

func (r *drNativeRunner) livePVCUID() string {
	if r.pvcUID != "" {
		return r.pvcUID
	}
	return drFixturePVCUID
}

func (r *drNativeRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "leases.coordination.k8s.io") {
		if r.drKubeLeader == nil {
			return CommandResult{}, ErrValidation
		}
		return r.drKubeLeader.Run(ctx, dir, binary, args, env)
	}
	if strings.HasSuffix(dir, "cluster-a") && !strings.Contains(joined, "get --raw=/readyz") {
		r.sourceMutationsOrReads = append(r.sourceMutationsOrReads, joined)
	}
	if r.workerUnreadySite != "" && strings.HasSuffix(dir, r.workerUnreadySite) &&
		strings.Contains(joined, "get nodes -o json") {
		// Preserve all three healthy control-plane identities and mutate ONLY
		// the existing last worker's Ready condition in the native-shaped fixture.
		out, err := r.recoveryFakeRunner.Run(ctx, dir, binary, args, env)
		if err != nil {
			return out, err
		}
		const ready = `{"metadata":{"name":"worker1","labels":{}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}`
		const notReady = `{"metadata":{"name":"worker1","labels":{}},"status":{"conditions":[{"type":"Ready","status":"False"}]}}`
		if strings.Count(out.Stdout, ready) != 1 {
			return CommandResult{}, errors.New("isolated worker readiness fixture missing")
		}
		out.Stdout = strings.Replace(out.Stdout, ready, notReady, 1)
		return out, nil
	}
	if strings.Contains(joined, "get --raw=/readyz") {
		if r.healthReadDelay > 0 {
			time.Sleep(r.healthReadDelay)
		}
		if (strings.HasSuffix(dir, "cluster-a") && r.sourceDown) ||
			(strings.HasSuffix(dir, "cluster-dr") && r.drDown) {
			return CommandResult{}, errors.New("isolated fixture Kubernetes API unreachable")
		}
	}
	if strings.Contains(joined, "get backups.velero.io ") {
		name := ""
		for i, x := range args {
			if x == "backups.velero.io" && i+1 < len(args) {
				name = args[i+1]
			}
		}
		namespace := ""
		for _, x := range []string{"ls-http-dc", "ls-db-dc", "ls-http-dr", "ls-db-dr"} {
			if name == x {
				if strings.Contains(x, "http") {
					namespace = "app-http"
				} else {
					namespace = "app-pg"
				}
			}
		}
		v := nativeVeleroBackup{APIVersion: "velero.io/v1", Kind: "Backup"}
		v.Metadata.Name = name
		v.Metadata.Namespace = "velero"
		v.Metadata.UID = r.backupUID
		r.backupReads++
		if r.swapBackupAfterReads > 0 && r.backupReads > r.swapBackupAfterReads {
			v.Metadata.UID = r.swapBackupUID
		}
		v.Spec.IncludedNamespaces = []string{namespace}
		v.Spec.StorageLocation = "dr-s3"
		v.Status.Phase = "Completed"
		v.Status.CompletionTimestamp = time.Now().UTC()
		if r.staleBackup {
			v.Status.CompletionTimestamp = v.Status.CompletionTimestamp.Add(-2 * time.Hour)
		}
		v.Status.StartTimestamp = v.Status.CompletionTimestamp.Add(-time.Second)
		if !r.backupStartedAt.IsZero() {
			v.Status.StartTimestamp = r.backupStartedAt
			v.Status.CompletionTimestamp = r.backupStartedAt.Add(time.Second)
		}
		b, _ := json.Marshal(v)
		return CommandResult{Stdout: string(b)}, nil
	}
	if strings.Contains(joined, " get restores.velero.io ") {
		name := ""
		for i, x := range args {
			if x == "restores.velero.io" && i+1 < len(args) {
				name = args[i+1]
			}
		}
		if r.beforeRestoreRead != nil {
			r.beforeRestoreRead(name)
		}
		v, ok := r.restored[name]
		if !ok {
			return CommandResult{}, ErrValidation
		}
		raw, _ := json.Marshal(v)
		return CommandResult{Stdout: string(raw)}, nil
	}
	if strings.Contains(joined, " create -f ") {
		file := ""
		for i, arg := range args {
			if arg == "-f" && i+1 < len(args) {
				file = args[i+1]
			}
		}
		payload, err := os.ReadFile(file)
		if err != nil {
			return CommandResult{}, err
		}
		var kind struct {
			Kind      string `json:"kind"`
			Immutable bool   `json:"immutable"`
			Metadata  struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(payload, &kind); err != nil {
			return CommandResult{}, err
		}
		if kind.Kind == "ConfigMap" {
			modifier := kind.Data["resource-modifier.yaml"]
			if kind.Metadata.Namespace != "velero" || !kind.Immutable ||
				!strings.HasPrefix(kind.Metadata.Name, "lsdr-pvc-") ||
				!strings.Contains(modifier, "groupResource: persistentvolumeclaims") ||
				!strings.Contains(modifier, "- app-pg") ||
				!strings.Contains(modifier, "^postgres-data$") ||
				!strings.Contains(modifier, "path: /spec/volumeName") ||
				!strings.Contains(modifier, "operation: remove") {
				return CommandResult{}, ErrValidation
			}
			r.modifierCalls++
			return CommandResult{Stdout: "isolated immutable configmap created"}, nil
		}
		if kind.Kind != "Restore" {
			return CommandResult{}, ErrValidation
		}
		r.restoreCalls++
		if r.failRestore {
			return CommandResult{}, ErrValidation
		}
		var doc nativeVeleroRestore
		if err := json.Unmarshal(payload, &doc); err != nil {
			return CommandResult{}, err
		}
		v := doc
		v.APIVersion = "velero.io/v1"
		v.Kind = "Restore"
		v.Metadata.UID = strings.Repeat("e", 36)
		v.Status.Phase = "Completed"
		v.Status.CompletionTimestamp = time.Now().UTC()
		r.restored[v.Metadata.Name] = v
		raw, _ := json.Marshal(v)
		if r.afterRestoreCreated != nil {
			r.afterRestoreCreated(v.Metadata.Name)
		}
		return CommandResult{Stdout: string(raw)}, nil
	}
	if strings.Contains(joined, " get podvolumerestores.velero.io ") {
		name := ""
		for i, x := range args {
			if x == "-l" && i+1 < len(args) {
				name = strings.TrimPrefix(args[i+1], "velero.io/restore-name=")
			}
		}
		// Velero labelled the claim it wrote; a later live replacement
		// (r.pvcUID) does not change that historical record.
		restoreUID, pvcUID := r.restored[name].Metadata.UID, drFixturePVCUID
		if r.pvrRestoreUID != "" {
			restoreUID = r.pvrRestoreUID
		}
		if r.pvrPVCUID != "" {
			pvcUID = strings.TrimPrefix(r.pvrPVCUID, "-") // "-": label absent/empty
		}
		payload, _ := json.Marshal(map[string]any{"items": []any{map[string]any{
			"metadata": map[string]any{"labels": map[string]string{"velero.io/restore-name": name,
				"velero.io/restore-uid": restoreUID, "velero.io/pvc-uid": pvcUID}},
			"status": map[string]string{"phase": "Completed"},
		}}})
		return CommandResult{Stdout: string(payload)}, nil
	}
	if strings.Contains(joined, " get persistentvolumeclaims postgres-data -o json") {
		// The post-restore read is a real trust boundary: the independent
		// external fencer can revoke/refresh its signed epoch while the
		// native Kubernetes and Velero readbacks are in flight.
		if r.onRecoveredPVCRead != nil {
			cb := r.onRecoveredPVCRead
			r.onRecoveredPVCRead = nil
			cb()
		}
		phase := "Bound"
		if r.unhealthyPVC {
			phase = "Lost"
		}
		return CommandResult{Stdout: `{"metadata":{"name":"postgres-data","namespace":"app-pg","uid":"` + r.livePVCUID() + `"},"status":{"phase":"` + phase + `"}}`}, nil
	}
	if strings.Contains(joined, " get configmaps -o json") && r.autoRootCA {
		ns := ""
		for i, v := range args {
			if v == "-n" && i+1 < len(args) {
				ns = args[i+1]
			}
		}
		cm := map[string]any{"metadata": map[string]any{"name": "kube-root-ca.crt", "namespace": ns},
			"data": map[string]string{"ca.crt": "-----BEGIN CERTIFICATE-----..."}}
		items := []any{cm}
		if r.foreignConfigMap {
			items = append(items, map[string]any{"metadata": map[string]string{"name": "app-owned", "namespace": ns}, "data": map[string]string{"active": "old"}})
		}
		raw, _ := json.Marshal(map[string]any{"items": items})
		return CommandResult{Stdout: string(raw)}, nil
	}
	if strings.Contains(joined, " get secrets -o name") {
		if r.dirtyTarget {
			return CommandResult{Stdout: "secret/old-writer\n"}, nil
		}
		return CommandResult{}, nil
	}
	for _, resource := range []string{"pods", "persistentvolumeclaims", "deployments.apps", "statefulsets.apps", "services", "configmaps"} {
		if strings.Contains(joined, " get "+resource+" -o json") {
			if r.dirtyTarget {
				return CommandResult{Stdout: `{"items":[{"metadata":{"name":"old-writer"}}]}`}, nil
			}
			return CommandResult{Stdout: `{"items":[]}`}, nil
		}
	}
	return r.recoveryFakeRunner.Run(ctx, dir, binary, args, env)
}

type drTestSite struct {
	t            *testing.T
	portal       *Portal
	ws           Workspace
	handler      http.Handler
	runner       *drNativeRunner
	config       DRExecutionProfile
	fencePrivate ed25519.PrivateKey
	checkPrivate ed25519.PrivateKey
}

func setupDRExecutionFixture(t *testing.T) *drTestSite {
	t.Helper()
	p, ws, previous, _, handler := recoveryFixture(t, true)
	root := filepath.Dir(filepath.Dir(ws.Directory))
	fpub, fpriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cpub, cpriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	fencePub := filepath.Join(root, "dr-fence.pub")
	appPub := filepath.Join(root, "dr-app.pub")
	if e = os.WriteFile(fencePub, []byte(hex.EncodeToString(fpub)), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(appPub, []byte(hex.EncodeToString(cpub)), 0600); e != nil {
		t.Fatal(e)
	}
	profile := DRExecutionProfile{
		Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr",
		SourceEndpoint:                "https://dc.lab.internal:6443",
		ServiceRoute:                  "https://shop.tenant-a.example",
		FencePublicKeyFile:            fencePub,
		FenceEvidenceFile:             filepath.Join(root, "fence-receipt.json"),
		RecoveryVerifierPublicKeyFile: appPub,
		RecoveryVerificationFile:      filepath.Join(root, "app-recovery.json"),
		Workloads: []DRWorkloadProfile{
			{Namespace: "app-http", Kind: "STATELESS", BackupName: "ls-http-dc", FailbackBackupName: "ls-http-dr", StorageLocation: "dr-s3"},
			{Namespace: "app-pg", Kind: "STATEFUL", BackupName: "ls-db-dc", FailbackBackupName: "ls-db-dr", StorageLocation: "dr-s3", PVCName: "postgres-data", VolumeRecoveryKind: "FSB_KOPIA"},
		},
	}
	p.recovery.config.DRExecutions = []DRExecutionProfile{profile}
	if e = p.recovery.config.Validate(); e != nil {
		t.Fatal("qualification profile rejected", e)
	}
	rr := &drNativeRunner{
		recoveryFakeRunner: previous,
		restored:           map[string]nativeVeleroRestore{},
		backupUID:          strings.Repeat("b", 36),
		drKubeLeader: newDRFakeKubernetesLeaderRunner(DRAutomationPolicy{
			Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr", PollSeconds: 15,
		}),
	}
	p.Client.runner = rr
	enable := portalAdminRequest(t, handler, http.MethodPut, "/v1/kubernetes/clusters/cluster-a/dr",
		`{"enabled":true,"target_cluster_id":"cluster-dr","target_endpoint":"https://dr.lab.internal:6443","destination_id":"nfs-dr"}`, "tenant-a")
	if enable.Code != 200 {
		t.Fatalf("cannot enable approved independent DR intent: %d %s", enable.Code, enable.Body.String())
	}
	return &drTestSite{t: t, portal: p, ws: ws, handler: handler, runner: rr, config: profile, fencePrivate: fpriv, checkPrivate: cpriv}
}

func (x *drTestSite) fence(nonce, direction string, change func(*DRFenceProof)) {
	t := x.t
	t.Helper()
	now := time.Now().UTC()
	fenced, writer := "cluster-a", "cluster-dr"
	if direction == "FAILBACK" {
		fenced, writer = writer, fenced
	}
	epoch := uint64(55)
	if direction == "FAILBACK" {
		epoch = 56
	}
	proof := DRFenceProof{
		Version: 1, OperationID: nonce, Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr",
		Direction: direction, FencedClusterID: fenced, ActiveWriterClusterID: writer, FenceEpoch: epoch,
		FenceReadbackSHA256: strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now.Add(3 * time.Minute),
		Workloads: make([]DRFenceWorkload, 0, 2),
	}
	for _, w := range x.config.Workloads {
		backup := w.BackupName
		if direction == "FAILBACK" {
			backup = w.FailbackBackupName
		}
		proof.Workloads = append(proof.Workloads, DRFenceWorkload{
			Namespace: w.Namespace, BackupName: backup,
			DataSHA256: strings.Repeat("c", 64), BackupUID: x.runner.backupUID})
	}
	if change != nil {
		change(&proof)
	}
	raw, _ := json.Marshal(proof)
	env := DRSignedFence{Payload: proof, Signature: hex.EncodeToString(ed25519.Sign(x.fencePrivate, raw))}
	encoded, _ := json.Marshal(env)
	if err := os.WriteFile(x.config.FenceEvidenceFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
func (x *drTestSite) completion(job DRTransitionJob, change func(*DRCompletionProof)) {
	t := x.t
	t.Helper()
	// One registered public workload route; the signer attests which site serves it.
	writer, fenced, endpoint := "cluster-dr", "cluster-a", x.config.ServiceRoute
	if job.Direction == "FAILBACK" {
		writer, fenced = fenced, writer
	}
	now := time.Now().UTC()
	proof := DRCompletionProof{
		Version: 2, OperationID: job.ID, Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr",
		Direction: job.Direction, ActiveWriterClusterID: writer, FencedClusterID: fenced, FenceEpoch: job.FenceEpoch,
		RoutedEndpoint: endpoint, EndpointReadbackSHA256: strings.Repeat("d", 64),
		LastRecoverableWriteAt: now.Add(-45 * time.Second), FailureObservedAt: now,
		RecoveryWatermark: "pg:timeline-1:lsn-0A-B2", MeasuredRPOSeconds: 45,
		MeasuredRTOSeconds: 135, IssuedAt: now, ExpiresAt: now.Add(3 * time.Minute),
	}
	for i, step := range job.Steps {
		point := DRCompletedWorkload{
			Namespace: step.Namespace, Kind: step.Kind, PVCName: x.config.Workloads[i].PVCName,
			ExpectedDataSHA256: step.ExpectedDataSHA256, ObservedDataSHA256: step.ExpectedDataSHA256,
			ApplicationReadbackSHA256: strings.Repeat("e", 64),
		}
		if step.Kind == "STATEFUL" {
			point.LastRecoverableWriteAt = proof.LastRecoverableWriteAt
			point.RecoveryWatermark = proof.RecoveryWatermark
			point.StorageProbePVCUID = drFixturePVCUID
			point.StorageProbeCompletedAt = now
			point.StorageProbeReadbackSHA256 = drStorageProbeChallengeDigest(proof, point)
		}
		proof.Workloads = append(proof.Workloads, point)
	}
	if change != nil {
		change(&proof)
	}
	payload, _ := json.Marshal(proof)
	env := DRSignedCompletion{Payload: proof, Signature: hex.EncodeToString(ed25519.Sign(x.checkPrivate, payload))}
	encoded, _ := json.Marshal(env)
	if err := os.WriteFile(x.config.RecoveryVerificationFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
func (x *drTestSite) begin(nonce, direction string) *httptest.ResponseRecorder {
	route := "/v1/kubernetes/clusters/cluster-a/dr/failover"
	if direction == "FAILBACK" {
		route = "/v1/kubernetes/clusters/cluster-a/dr/failback"
	}
	r := newRecoveryAdminRequest(http.MethodPost, route, "{}", "tenant-a")
	r.Header.Set("Idempotency-Key", nonce)
	w := httptest.NewRecorder()
	x.handler.ServeHTTP(w, r)
	return w
}
func (x *drTestSite) waitRestore(jobID string) DRTransitionJob {
	t := x.t
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := readDRTransition(x.ws)
		if err == nil && got.ID == jobID && got.Status != "RUNNING" {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("DR journal stuck: state=%+v err=%v", got, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDRWarmFailoverAndSignedFailbackIsolatedWorkflows(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("1", 32)
	x.fence(nonce, "FAILOVER", nil)
	rec := x.begin(nonce, "FAILOVER")
	if rec.Code != 202 {
		t.Fatalf("signed failover not dispatched: %d %s", rec.Code, rec.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
		job.EvidenceLabel != "UNKNOWN" || x.runner.restoreCalls != 2 {
		t.Fatalf("restore cannot be marked ready before independent app proof: %+v calls=%d", job, x.runner.restoreCalls)
	}
	again := x.begin(nonce, "FAILOVER")
	if again.Code != 202 || x.runner.restoreCalls != 2 {
		t.Fatal("idempotency replay mutated Kubernetes", again.Code)
	}
	earlyBack := x.begin(strings.Repeat("2", 32), "FAILBACK")
	if earlyBack.Code != 409 {
		t.Fatal("unverified failover authorized failback", earlyBack.Code)
	}
	x.completion(job, nil)
	done := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
	if done.Code != 200 {
		t.Fatalf("verified app+PVC cutover blocked: %d %s", done.Code, done.Body.String())
	}
	first, e := readDRTransition(x.ws)
	if e != nil || first.Status != "VERIFIED" || first.MeasuredRPOSeconds != 45 || first.MeasuredRTOSeconds != 135 {
		t.Fatal("signed real-world measurement state missing", e, first)
	}
	reverse := strings.Repeat("3", 32)
	x.runner.mu.Lock()
	x.runner.backupUID = strings.Repeat("c", 36)                // fresh reverse backup, not the original DC generation
	x.runner.backupStartedAt = first.UpdatedAt.Add(time.Second) // taken after DR became the verified writer
	x.runner.mu.Unlock()
	x.fence(reverse, "FAILBACK", nil)
	back := x.begin(reverse, "FAILBACK")
	if back.Code != 202 {
		t.Fatalf("reverse protected restore blocked: %d %s", back.Code, back.Body.String())
	}
	next := x.waitRestore(reverse)
	if next.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || x.runner.restoreCalls != 4 {
		t.Fatal("real reverse direction did not use independent DR backup", next, x.runner.restoreCalls)
	}
	x.completion(next, nil)
	confirmed := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
	if confirmed.Code != 200 {
		t.Fatal("signed failback completion blocked", confirmed.Code, confirmed.Body.String())
	}
	final, e := readDRTransition(x.ws)
	if e != nil || final.Direction != "FAILBACK" || final.Status != "VERIFIED" {
		t.Fatal("failback not verified", e, final)
	}
}

func TestDRRejectsForgedOrExpiredNativeFencingBeforeRestore(t *testing.T) {
	for _, fault := range []string{"absent", "invalid-signature", "wrong-writer", "expired", "wrong-backup", "no-fence-epoch", "dirty-target", "failed-backup"} {
		t.Run(fault, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("a", 32)
			if fault != "absent" {
				x.fence(nonce, "FAILOVER", func(p *DRFenceProof) {
					switch fault {
					case "wrong-writer":
						p.ActiveWriterClusterID = "cluster-a"
					case "expired":
						p.IssuedAt = p.IssuedAt.Add(-10 * time.Minute)
						p.ExpiresAt = p.IssuedAt.Add(time.Minute)
					case "wrong-backup":
						p.Workloads[1].BackupName = "wrong-db"
					case "no-fence-epoch":
						p.FenceEpoch = 0
					}
				})
			}
			if fault == "invalid-signature" {
				raw, _ := os.ReadFile(x.config.FenceEvidenceFile)
				var v DRSignedFence
				json.Unmarshal(raw, &v)
				v.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
				raw, _ = json.Marshal(v)
				os.WriteFile(x.config.FenceEvidenceFile, raw, 0600)
			}
			if fault == "dirty-target" {
				x.runner.dirtyTarget = true
			}
			if fault == "failed-backup" {
				x.runner.backupUID = "other-not-matching-witness"
			}
			result := x.begin(nonce, "FAILOVER")
			if result.Code != 409 {
				t.Fatalf("unqualified native DR operation accepted: %d %s", result.Code, result.Body.String())
			}
			if x.runner.restoreCalls != 0 {
				t.Fatal("unqualified native mutation reached target")
			}
		})
	}
}
func TestDRRejectsBadIndependentApplicationCompletion(t *testing.T) {
	for _, fault := range []string{"missing", "wrong-checksum", "bad-route", "stale", "lost-pvc", "forged-signature"} {
		t.Run(fault, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("4", 32)
			x.fence(nonce, "FAILOVER", nil)
			if result := x.begin(nonce, "FAILOVER"); result.Code != 202 {
				t.Fatal("setup failover failed", result.Code)
			}
			job := x.waitRestore(nonce)
			if fault != "missing" {
				x.completion(job, func(p *DRCompletionProof) {
					switch fault {
					case "wrong-checksum":
						p.Workloads[1].ObservedDataSHA256 = strings.Repeat("0", 64)
					case "bad-route":
						p.RoutedEndpoint = "https://attacker.internal:6443"
					case "stale":
						p.IssuedAt = job.UpdatedAt.Add(-time.Second)
					}
				})
			}
			if fault == "lost-pvc" {
				x.runner.unhealthyPVC = true
			}
			if fault == "forged-signature" {
				raw, _ := os.ReadFile(x.config.RecoveryVerificationFile)
				var v DRSignedCompletion
				json.Unmarshal(raw, &v)
				v.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
				raw, _ = json.Marshal(v)
				os.WriteFile(x.config.RecoveryVerificationFile, raw, 0600)
			}
			checked := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
			if checked.Code != 409 {
				t.Fatal("unqualified app/PVC/traffic completion accepted", checked.Code)
			}
			current, e := readDRTransition(x.ws)
			if e != nil || current.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatal("unqualified DR was promoted", current, e)
			}
		})
	}
}

func TestDRPreflightAllowsOnlyKubernetesBuiltinRootCA(t *testing.T) {
	x := setupDRExecutionFixture(t)
	target, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	x.runner.autoRootCA = true
	if err := x.portal.recovery.targetNamespaceEmpty(context.Background(), target, x.config.Workloads[1]); err != nil {
		t.Fatal("normal Kubernetes namespace root CA rejected", err)
	}
	x.runner.foreignConfigMap = true
	if err := x.portal.recovery.targetNamespaceEmpty(context.Background(), target, x.config.Workloads[1]); err == nil {
		t.Fatal("existing application ConfigMap was treated as clean DR target")
	}
}

// A distinct backup UID is not enough for a reverse transfer: the generation
// must have STARTED after the previous transition made the other site the
// verified single writer, otherwise it cannot contain that writer's data.
func TestDRReverseTransitionRefusesBackupStartedBeforePriorVerification(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("8", 32)
	x.fence(nonce, "FAILOVER", nil)
	if first := x.begin(nonce, "FAILOVER"); first.Code != 202 {
		t.Fatalf("setup failed: %d %s", first.Code, first.Body.String())
	}
	job := x.waitRestore(nonce)
	x.completion(job, nil)
	if done := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); done.Code != 200 {
		t.Fatal("signed failover not verified", done.Code)
	}
	verified, err := readDRTransition(x.ws)
	if err != nil || verified.Status != "VERIFIED" {
		t.Fatal(err, verified)
	}
	for _, tc := range []struct {
		name    string
		started time.Time
	}{
		{"before-failover-request", verified.RequestedAt.Add(-time.Minute)},
		{"at-verification", verified.UpdatedAt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x.runner.mu.Lock()
			x.runner.backupUID = strings.Repeat("d", 36) // fresh UID, stale generation
			x.runner.backupStartedAt = tc.started
			x.runner.mu.Unlock()
			reverse := strings.Repeat("9", 32)
			x.fence(reverse, "FAILBACK", nil)
			if rejected := x.begin(reverse, "FAILBACK"); rejected.Code != 409 || x.runner.restoreCalls != 2 {
				t.Fatalf("pre-cutover backup generation accepted for failback: %d restores=%d", rejected.Code, x.runner.restoreCalls)
			}
		})
	}
	// A generation started after verification is the legitimate reverse copy.
	x.runner.mu.Lock()
	x.runner.backupStartedAt = verified.UpdatedAt.Add(2 * time.Second)
	x.runner.mu.Unlock()
	reverse := strings.Repeat("a", 32)
	x.fence(reverse, "FAILBACK", nil)
	if accepted := x.begin(reverse, "FAILBACK"); accepted.Code != 202 {
		t.Fatalf("post-verification reverse backup refused: %d %s", accepted.Code, accepted.Body.String())
	}
	if next := x.waitRestore(reverse); next.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || x.runner.restoreCalls != 4 {
		t.Fatal("legitimate reverse restore did not run", next, x.runner.restoreCalls)
	}
}

// After a full failover/failback cycle the original cycle-1 failover backup
// CR may still exist with its own distinct UID. Re-presenting it for the next
// failover must be refused: it predates the DC writer's resumed data.
func TestDRSecondFailoverRefusesFirstCycleBackupGeneration(t *testing.T) {
	x := setupDRExecutionFixture(t)
	cycleOneStart := time.Now().UTC().Add(-time.Minute)
	x.runner.mu.Lock()
	x.runner.backupStartedAt = cycleOneStart
	x.runner.mu.Unlock()
	nonce := strings.Repeat("4", 32)
	x.fence(nonce, "FAILOVER", nil)
	if first := x.begin(nonce, "FAILOVER"); first.Code != 202 {
		t.Fatalf("setup failed: %d %s", first.Code, first.Body.String())
	}
	x.completion(x.waitRestore(nonce), nil)
	if done := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); done.Code != 200 {
		t.Fatal("failover not verified", done.Code)
	}
	x.runner.mu.Lock()
	x.runner.backupUID = strings.Repeat("c", 36)
	x.runner.backupStartedAt = time.Now().UTC().Add(time.Second)
	x.runner.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	back := strings.Repeat("5", 32)
	x.fence(back, "FAILBACK", nil)
	if r := x.begin(back, "FAILBACK"); r.Code != 202 {
		t.Fatalf("failback setup failed: %d %s", r.Code, r.Body.String())
	}
	x.completion(x.waitRestore(back), nil)
	if done := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a"); done.Code != 200 {
		t.Fatal("failback not verified", done.Code)
	}
	calls := x.runner.restoreCalls
	// Cycle-1 generation (UID "b...", started before both verifications).
	x.runner.mu.Lock()
	x.runner.backupUID = strings.Repeat("b", 36)
	x.runner.backupStartedAt = cycleOneStart
	x.runner.mu.Unlock()
	again := strings.Repeat("e", 32)
	x.fence(again, "FAILOVER", func(p *DRFenceProof) { p.FenceEpoch = 57 })
	if r := x.begin(again, "FAILOVER"); r.Code != 409 || x.runner.restoreCalls != calls {
		t.Fatalf("first-cycle backup generation replayed into second failover: %d restores=%d", r.Code, x.runner.restoreCalls)
	}
}

// Promotion to VERIFIED single writer must re-confirm the CURRENT signed
// source-writer fence on every path, including manual completion. An expired
// lease or a changed epoch/lineage (e.g. the DC returned during failover)
// must block promotion even with a valid application/route proof.
func TestDRManualCompletionRequiresCurrentFence(t *testing.T) {
	for _, fault := range []string{"expired", "epoch-changed", "lineage-changed", "removed"} {
		t.Run(fault, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("f", 32)
			x.fence(nonce, "FAILOVER", nil)
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatalf("setup: %d %s", r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			x.completion(job, nil)
			switch fault {
			case "expired":
				x.fence(nonce, "FAILOVER", func(p *DRFenceProof) {
					p.IssuedAt = time.Now().UTC().Add(-4 * time.Minute)
					p.ExpiresAt = time.Now().UTC().Add(-time.Second)
				})
			case "epoch-changed":
				x.fence(nonce, "FAILOVER", func(p *DRFenceProof) { p.FenceEpoch = 99 })
			case "lineage-changed":
				x.fence(nonce, "FAILOVER", func(p *DRFenceProof) { p.Workloads[1].DataSHA256 = strings.Repeat("e", 64) })
			case "removed":
				if err := os.Remove(x.config.FenceEvidenceFile); err != nil {
					t.Fatal(err)
				}
			}
			done := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
			if done.Code != 409 {
				t.Fatalf("promotion without current fence: %d %s", done.Code, done.Body.String())
			}
			if j, err := readDRTransition(x.ws); err != nil || j.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatal("journal advanced without current fence", err, j)
			}
		})
	}
}
