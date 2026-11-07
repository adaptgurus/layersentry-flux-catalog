package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The automatic coordinator first checks a signed receipt and only later
// enters the finalization lock. Replacing that receipt with another VALIDLY
// signed payload must not pass the original RPO policy as a second writer.
func TestDRAutomationRefusesSignedCompletionReplacementBeforeCommit(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("5", 32)
	x.fence(nonce, "FAILOVER", nil)
	if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
		t.Fatalf("signed source fixture setup failed: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("expected restored-but-not-promoted app", job.Status)
	}
	x.completion(job, nil)
	_, digest, err := verifiedDRCompletion(x.config, job, time.Now().UTC())
	if err != nil {
		t.Fatal("initial signed recovery receipt not independently verifiable", err)
	}
	x.completion(job, func(v *DRCompletionProof) {
		// A fresh valid signature from the same independent verifier,
		// but a DIFFERENT data lineage than the preflight-checked digest.
		v.RecoveryWatermark = "pg:timeline-1:lsn-0A-B3"
		syncStatefulDRTestWatermarks(v)
	})
	if _, err = x.portal.finalizeDRTransitionWithProof(context.Background(), x.ws, digest, 300); err == nil {
		t.Fatal("changed valid signed receipt was promoted under previously checked RPO")
	}
	recorded, err := readDRTransition(x.ws)
	if err != nil || recorded.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatalf("receipt replacement must not advance writer: %+v err=%v", recorded, err)
	}
}

// A signer that simply updates the receipt issue time but reuses the last
// incident's old write/failure pair must never enable automatic promotion.
func TestDRAutomationRejectsPreviouslySignedIncidentTimestampPair(t *testing.T) {
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
	job := x.waitRestore(intent.OperationID)
	x.completion(job, func(v *DRCompletionProof) {
		v.FailureObservedAt = job.RequestedAt.Add(-2 * time.Hour)
		v.LastRecoverableWriteAt = v.FailureObservedAt.Add(-45 * time.Second)
		v.MeasuredRPOSeconds = 45
		syncStatefulDRTestWatermarks(v)
	})
	automaticDRTickFixture(t, x, a, &state)
	if state.State != "RECOVERY_WATERMARK_PENDING" {
		t.Fatalf("old incident pair reused as current despite signed freshness: %+v", state)
	}
	recorded, err := readDRTransition(x.ws)
	if err != nil || recorded.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("stale incident wrote active DR writer", recorded, err)
	}
}

func TestDRAutomationSignedRPOCeilAtPolicyBoundary(t *testing.T) {
	for _, testcase := range []struct {
		name        string
		extra       time.Duration
		wantState   string
		wantJournal string
	}{
		{"exact_300_seconds", 0, "DR_ACTIVE", "VERIFIED"},
		{"one_nanosecond_over_300", time.Nanosecond, "RECOVERY_RPO_LIMIT_EXCEEDED", "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC"},
	} {
		t.Run(testcase.name, func(t *testing.T) {
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
			job := x.waitRestore(intent.OperationID)
			x.completion(job, func(v *DRCompletionProof) {
				v.FailureObservedAt = v.IssuedAt
				v.LastRecoverableWriteAt = v.FailureObservedAt.Add(-300*time.Second - testcase.extra)
				v.MeasuredRPOSeconds = 300
				if testcase.extra != 0 {
					v.MeasuredRPOSeconds = 301
				}
				syncStatefulDRTestWatermarks(v)
			})
			automaticDRTickFixture(t, x, a, &state)
			if state.State != testcase.wantState {
				t.Fatalf("signed policy boundary incorrectly advanced: %+v", state)
			}
			recorded, err := readDRTransition(x.ws)
			if err != nil || recorded.Status != testcase.wantJournal {
				t.Fatal("unexpected journal after signed RPO boundary", recorded, err)
			}
		})
	}
}

// Keep separately signed per-stateful-workload recovery proofs consistent
// with the intended GLOBAL point in these positive/boundary test fixtures.
func syncStatefulDRTestWatermarks(v *DRCompletionProof) {
	for i := range v.Workloads {
		if v.Workloads[i].Kind == "STATEFUL" {
			v.Workloads[i].LastRecoverableWriteAt = v.LastRecoverableWriteAt
			v.Workloads[i].RecoveryWatermark = v.RecoveryWatermark
		}
	}
}
