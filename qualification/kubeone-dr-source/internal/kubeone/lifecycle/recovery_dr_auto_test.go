package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func registeredAutoDRPolicy(t *testing.T, x *drTestSite) DRAutomationPolicy {
	t.Helper()
	a := DRAutomationPolicy{
		Tenant: "tenant-a", SourceClusterID: "cluster-a", TargetClusterID: "cluster-dr",
		ControllerClusterID: "cluster-dr", Enabled: true, AutoFailover: true, AutoFailback: true,
		PollSeconds: 15, SourceFailureChecks: 3, TargetReadyChecks: 2,
		FailbackHealthyChecks: 3, FailbackHoldSeconds: 900,
		MaxBackupAgeSeconds: 1800, MaxRPOSeconds: 300,
	}
	x.portal.recovery.config.DRAutomation = []DRAutomationPolicy{a}
	if err := x.portal.recovery.config.Validate(); err != nil {
		t.Fatalf("valid automatic DR config rejected: %v", err)
	}
	return a
}

func automaticDRTickFixture(t *testing.T, x *drTestSite, a DRAutomationPolicy, state *AutoDRStatus) {
	t.Helper()
	dest, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.portal.automaticDRTick(context.Background(), a, x.ws, dest, state); err != nil {
		t.Fatal(err)
	}
}

func TestDRAutomationPolicyFailClosedAndTenantScoped(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	if err := x.portal.ValidateAutoDRControllerSite("cluster-dr"); err != nil {
		t.Fatal(err)
	}
	if err := x.portal.ValidateAutoDRControllerSite("cluster-a"); err == nil {
		t.Fatal("DC cannot be registered as independent DR-side controller")
	}
	tests := []struct {
		name   string
		change func(*DRAutomationPolicy)
	}{
		{"no-enabled", func(a *DRAutomationPolicy) { a.Enabled = false; a.AutoFailover = true }},
		{"site-identity", func(a *DRAutomationPolicy) { a.ControllerClusterID = "cluster-a" }},
		{"rapid-quorum", func(a *DRAutomationPolicy) { a.SourceFailureChecks = 1 }},
		{"dr-healthy-threshold", func(a *DRAutomationPolicy) { a.TargetReadyChecks = 1 }},
		{"short-poll", func(a *DRAutomationPolicy) { a.PollSeconds = 1 }},
		{"short-stability", func(a *DRAutomationPolicy) { a.FailbackHoldSeconds = 30 }},
		{"backup-age", func(a *DRAutomationPolicy) { a.MaxBackupAgeSeconds = 0 }},
		{"invalid-rpo", func(a *DRAutomationPolicy) { a.MaxRPOSeconds = 0 }},
		{"wrong-owner", func(a *DRAutomationPolicy) { a.Tenant = "another-tenant" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			invalid := a
			tc.change(&invalid)
			cfg := x.portal.recovery.config
			cfg.DRAutomation = []DRAutomationPolicy{invalid}
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe automation policy passed fail-closed validation")
			}
		})
	}
	cfg := x.portal.recovery.config
	cfg.DRAutomation = []DRAutomationPolicy{a, a}
	if err := cfg.Validate(); err == nil {
		t.Fatal("two controllers can supervise one signed DR pair")
	}
	targetURL := "/v1/kubernetes/clusters/cluster-a/dr/automation"
	self := portalAdminRequest(t, x.handler, http.MethodGet, targetURL, "", "tenant-a")
	if self.Code != 200 || !strings.Contains(self.Body.String(), `"enabled":true`) {
		t.Fatalf("tenant automatic DR status absent: %d %s", self.Code, self.Body.String())
	}
	foreign := portalAdminRequest(t, x.handler, http.MethodGet, targetURL, "", "tenant-b")
	if foreign.Code != http.StatusNotFound {
		t.Fatal("foreign tenant obtained DR status", foreign.Code)
	}
}

func TestDRAutomationControllerLeaseMutualExclusion(t *testing.T) {
	x := setupDRExecutionFixture(t)
	first, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = acquireAutoDRControllerLease(x.ws); err == nil {
		t.Fatal("another controller seized active singleton lease")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal("released lease cannot be reacquired", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDRAutomationNoPromotionFromOutageAloneAndSignedFlow(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	// Healthy source never requests physical fencing.
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "WATCHING_PRIMARY" {
		t.Fatal("healthy cluster detected as failed", state)
	}
	if _, err := os.Lstat(autoDRFenceIntentPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("healthy source issued a fencing request")
	}
	// Simulate loss of DC API; isolated mock does NOT claim physical fencing.
	x.runner.mu.Lock()
	x.runner.sourceDown = true
	x.runner.mu.Unlock()
	for i := 0; i < 3; i++ {
		automaticDRTickFixture(t, x, a, &state)
	}
	if state.State != "AWAITING_INDEPENDENT_FENCE" || state.SourceFailures != 3 {
		t.Fatal("sustained outage did not stop at independent physical fencing gate", state)
	}
	intent, err := readAutoDRFenceIntent(x.ws)
	if err != nil || intent.Direction != "FAILOVER" || intent.MinimumFenceEpoch != 1 {
		t.Fatal("first fencing request not persisted with immutable source/target ID", err, intent)
	}
	if _, err := readDRTransition(x.ws); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outage alone created a second application writer")
	}
	if x.runner.restoreCalls != 0 {
		t.Fatal("outage alone started Kubernetes restore")
	}
	automaticDRTickFixture(t, x, a, &state)
	again, err := readAutoDRFenceIntent(x.ws)
	if err != nil || again.OperationID != intent.OperationID {
		t.Fatal("fencing intent unstable across poll", err)
	}
	// Independent simulated signer attests the *same* nonce after acting.
	x.fence(intent.OperationID, "FAILOVER", nil)
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "RESTORE_REQUESTED" {
		t.Fatalf("qualified simulated failover not submitted: %+v", state)
	}
	job := x.waitRestore(intent.OperationID)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || x.runner.restoreCalls != 2 {
		t.Fatal("Velero restore incorrectly promoted without app/traffic evidence", job)
	}
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "AWAITING_APPLICATION_CUTOVER" {
		t.Fatal("missing independent data/route proof did not block promotion", state)
	}
	x.completion(job, nil)
	automaticDRTickFixture(t, x, a, &state)
	verified, err := readDRTransition(x.ws)
	if err != nil || verified.Status != "VERIFIED" || verified.Direction != "FAILOVER" || state.State != "DR_ACTIVE" {
		t.Fatal("externally signed healthy DR was not committed", err, verified, state)
	}
	// Repaired DC must remain fully healthy for a long enough hold period.
	x.runner.mu.Lock()
	x.runner.sourceDown = false
	x.runner.mu.Unlock()
	for i := 0; i < 3; i++ {
		automaticDRTickFixture(t, x, a, &state)
	}
	if state.State != "WAITING_FOR_STABLE_PRIMARY" {
		t.Fatal("immediate unsafe failback allowed", state)
	}
	state.SourceHealthySince = time.Now().UTC().Add(-time.Duration(a.FailbackHoldSeconds+1) * time.Second)
	automaticDRTickFixture(t, x, a, &state)
	reverse, err := readAutoDRFenceIntent(x.ws)
	if err != nil || reverse.OperationID == intent.OperationID || reverse.Direction != "FAILBACK" ||
		reverse.MinimumFenceEpoch <= verified.FenceEpoch {
		t.Fatal("reverse request missing or same fencing generation", err, reverse)
	}
	if state.State != "AWAITING_INDEPENDENT_FENCE" {
		t.Fatal("unfenced DR writer was skipped", state)
	}
	x.runner.mu.Lock()
	x.runner.backupUID = strings.Repeat("c", 36)
	x.runner.backupStartedAt = verified.UpdatedAt.Add(time.Second) // reverse backup taken after DR became writer
	x.runner.mu.Unlock()
	x.fence(reverse.OperationID, "FAILBACK", nil)
	automaticDRTickFixture(t, x, a, &state)
	reverseJob := x.waitRestore(reverse.OperationID)
	if reverseJob.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" || reverseJob.FenceEpoch <= verified.FenceEpoch {
		t.Fatal("reverse restore did not require newer signed fence and backup", reverseJob)
	}
	x.completion(reverseJob, nil)
	automaticDRTickFixture(t, x, a, &state)
	final, err := readDRTransition(x.ws)
	if err != nil || final.Status != "VERIFIED" || final.Direction != "FAILBACK" || state.State != "DC_ACTIVE" {
		t.Fatal("repaired DC not independently verified single writer", err, final, state)
	}
}

func TestDRAutomationRejectedBadDRAndStaleBackup(t *testing.T) {
	for _, tc := range []string{"dr-api-down", "stale-backup", "wrong-signed-nonce", "missing-signature", "rpo-exceeded"} {
		t.Run(tc, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			state := AutoDRStatus{}
			x.runner.mu.Lock()
			x.runner.sourceDown = true
			if tc == "dr-api-down" {
				x.runner.drDown = true
			}
			if tc == "stale-backup" {
				x.runner.staleBackup = true
			}
			x.runner.mu.Unlock()
			for i := 0; i < 3; i++ {
				automaticDRTickFixture(t, x, a, &state)
			}
			if tc == "dr-api-down" {
				if state.State != "DR_SITE_NOT_HEALTHY" {
					t.Fatal("unhealthy DR cluster passed quorum admission")
				}
				if x.runner.restoreCalls != 0 {
					t.Fatal("unhealthy target performed mutation")
				}
				return
			}
			req, err := readAutoDRFenceIntent(x.ws)
			if err != nil {
				t.Fatal(err)
			}
			if tc != "missing-signature" {
				nonce := req.OperationID
				if tc == "wrong-signed-nonce" {
					nonce = strings.Repeat("z", 32)
				}
				x.fence(nonce, "FAILOVER", nil)
			}
			automaticDRTickFixture(t, x, a, &state)
			if tc == "stale-backup" && state.State != "AWAITING_FRESH_OFFSITE_BACKUPS" {
				t.Fatal("expired application/PVC backup accepted", state)
			}
			if tc == "wrong-signed-nonce" && state.State != "AWAITING_CORRECT_FENCING_EPOCH" {
				t.Fatal("signed different operation ID admitted", state)
			}
			if tc == "missing-signature" && state.State != "AWAITING_INDEPENDENT_FENCE" {
				t.Fatal("no writer-fencing proof admitted", state)
			}
			if tc == "rpo-exceeded" {
				job := x.waitRestore(req.OperationID)
				x.completion(job, func(v *DRCompletionProof) {
					v.MeasuredRPOSeconds = int64(a.MaxRPOSeconds + 1)
					v.LastRecoverableWriteAt = v.FailureObservedAt.Add(-time.Duration(v.MeasuredRPOSeconds) * time.Second)
					syncStatefulDRTestWatermarks(v)
				})
				automaticDRTickFixture(t, x, a, &state)
				if state.State != "RECOVERY_RPO_LIMIT_EXCEEDED" {
					t.Fatal("recovery outside RPO was verified", state)
				}
			} else if x.runner.restoreCalls != 0 {
				t.Fatal("unqualified recovery reached Kubernetes restore")
			}
		})
	}
}

func TestDRReverseTransitionRefusesReusedOriginalBackupUID(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("6", 32)
	x.fence(nonce, "FAILOVER", nil)
	if first := x.begin(nonce, "FAILOVER"); first.Code != 202 {
		t.Fatalf("setup failed: %d %s", first.Code, first.Body.String())
	}
	job := x.waitRestore(nonce)
	x.completion(job, nil)
	finished := portalAdminRequest(t, x.handler, http.MethodPost, "/v1/kubernetes/clusters/cluster-a/dr/complete", "{}", "tenant-a")
	if finished.Code != 200 {
		t.Fatal("signed initial failover not verified", finished.Code)
	}
	// An independent signer using a newer fencing epoch must NOT permit
	// replay of the original backup UID into the original writer site.
	reverse := strings.Repeat("7", 32)
	x.fence(reverse, "FAILBACK", nil)
	rejected := x.begin(reverse, "FAILBACK")
	if rejected.Code != 409 || x.runner.restoreCalls != 2 {
		t.Fatalf("stale reverse backup generation bypassed anti-replay: %d restores=%d", rejected.Code, x.runner.restoreCalls)
	}
}

func TestDRAutomationRestartResetsOldOutageCounters(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	x.runner.mu.Lock()
	x.runner.sourceDown = true
	x.runner.mu.Unlock()
	state := AutoDRStatus{
		ClusterID: x.ws.ClusterID, TargetClusterID: "cluster-dr",
		State: "WATCHING_PRIMARY", SourceFailures: a.SourceFailureChecks,
		TargetHealthy: a.TargetReadyChecks,
		ObservedAt:    time.Now().UTC().Add(-time.Hour),
	}
	automaticDRTickFixture(t, x, a, &state)
	if state.SourceFailures != 1 || state.State != "WATCHING_PRIMARY" {
		t.Fatal("stale outage counters authorized immediate recovery", state)
	}
	if _, err := os.Lstat(autoDRFenceIntentPath(x.ws)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale outage counters generated a fencing request")
	}
}

func TestDRAutomationDurableStateMustRemainWritable(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	x.runner.mu.Lock()
	x.runner.sourceDown = true
	x.runner.mu.Unlock()
	// A DR portal must preserve its *independent local mirror* of original
	// KubeOne workspace/registry state. If the coordinator loses custody
	// of its durable journal, it must not issue a restore command.
	rename := x.ws.Directory + ".removed"
	if err := os.Rename(x.ws.Directory, rename); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(rename, x.ws.Directory)
	target, err := x.portal.Client.Workspace("tenant-a", "cluster-dr")
	if err != nil {
		t.Fatal(err)
	}
	if err = x.portal.automaticDRTick(context.Background(), a, x.ws, target, &state); err == nil {
		t.Fatal("unavailable independent state directory was silently tolerated")
	}
	if x.runner.restoreCalls != 0 {
		t.Fatal("operation continued without auditable storage")
	}
}

func TestDRAutomationLoopRequiresExplicitEnabledSiteAndStops(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	cfg := x.portal.recovery.config
	cfg.DRAutomation = []DRAutomationPolicy{{Tenant: a.Tenant, SourceClusterID: a.SourceClusterID, TargetClusterID: a.TargetClusterID}}
	x.portal.recovery.config = cfg
	if err := x.portal.RunDRAutomation(context.Background(), "cluster-dr"); err == nil {
		t.Fatal("server scheduler started without enabled policy")
	}
	cfg.DRAutomation = []DRAutomationPolicy{a}
	x.portal.recovery.config = cfg
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- x.portal.RunDRAutomation(ctx, "cluster-dr") }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		x.portal.mu.Lock()
		active := x.portal.autoDRRunning
		x.portal.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("monitor did not start under explicit policy")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := x.portal.RunDRAutomation(context.Background(), "cluster-dr"); err == nil {
		t.Fatal("duplicate scheduler started while one was running")
	}
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("cancelled coordinator did not exit safely: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not release lease after cancellation")
	}
}

// Automatic failback: an age-compliant reverse backup with a new UID that was
// started before the failover became VERIFIED cannot hold the DR writer's
// data and must not be restored into the original DC.
func TestDRAutomationFailbackRefusesPreCutoverBackupGeneration(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	state := AutoDRStatus{}
	x.runner.mu.Lock()
	x.runner.sourceDown = true
	x.runner.mu.Unlock()
	for i := 0; i < 3; i++ {
		automaticDRTickFixture(t, x, a, &state)
	}
	intent, err := readAutoDRFenceIntent(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	x.fence(intent.OperationID, "FAILOVER", nil)
	automaticDRTickFixture(t, x, a, &state)
	x.completion(x.waitRestore(intent.OperationID), nil)
	automaticDRTickFixture(t, x, a, &state)
	verified, err := readDRTransition(x.ws)
	if err != nil || verified.Status != "VERIFIED" || state.State != "DR_ACTIVE" {
		t.Fatal("setup failover not verified", err, verified, state)
	}
	x.runner.mu.Lock()
	x.runner.sourceDown = false
	x.runner.mu.Unlock()
	for i := 0; i < 3; i++ {
		automaticDRTickFixture(t, x, a, &state)
	}
	state.SourceHealthySince = time.Now().UTC().Add(-time.Duration(a.FailbackHoldSeconds+1) * time.Second)
	automaticDRTickFixture(t, x, a, &state)
	reverse, err := readAutoDRFenceIntent(x.ws)
	if err != nil || reverse.Direction != "FAILBACK" {
		t.Fatal("reverse fencing request absent", err, reverse)
	}
	x.runner.mu.Lock()
	x.runner.backupUID = strings.Repeat("c", 36)
	x.runner.backupStartedAt = verified.RequestedAt.Add(-time.Minute) // within MaxBackupAge, before cutover
	x.runner.mu.Unlock()
	x.fence(reverse.OperationID, "FAILBACK", nil)
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "AWAITING_FRESH_OFFSITE_BACKUPS" || x.runner.restoreCalls != 2 {
		t.Fatalf("pre-cutover generation auto-restored into DC: %+v restores=%d", state, x.runner.restoreCalls)
	}
	if job, err := readDRTransition(x.ws); err != nil || job.Direction != "FAILOVER" || job.Status != "VERIFIED" {
		t.Fatal("rejected failback mutated the verified journal", err, job)
	}
}
