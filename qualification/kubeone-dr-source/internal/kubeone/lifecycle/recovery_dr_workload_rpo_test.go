package lifecycle

import (
	"strings"
	"testing"
	"time"
)

// Source-only acceptance: one current DB must not mask another DB/PVC that is
// recoverable only from an older committed transaction. The independent
// verifier signs each stateful write reference; worst age wins the group RPO.
func TestDRConservativeStatefulGroupRPO(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := DRCompletionProof{
		Version:                2,
		LastRecoverableWriteAt: now.Add(-45 * time.Second),
		FailureObservedAt:      now,
		IssuedAt:               now,
		RecoveryWatermark:      "pg:db1:lsn-NEW",
		MeasuredRPOSeconds:     45,
		Workloads: []DRCompletedWorkload{
			{Kind: "STATELESS", Namespace: "frontend"},
			{
				Kind: "STATEFUL", Namespace: "db1",
				LastRecoverableWriteAt: now.Add(-45 * time.Second),
				RecoveryWatermark:      "pg:db1:lsn-NEW",
			},
			{
				Kind: "STATEFUL", Namespace: "db2",
				LastRecoverableWriteAt: now.Add(-601 * time.Second),
				RecoveryWatermark:      "pg:db2:lsn-OLD",
			},
		},
	}
	if _, err := measuredDRRecoveryPointRPO(v, now); err != nil {
		t.Fatal("the deliberately misleading global timestamp should pass the old check", err)
	}
	if err := verifyConservativeDRWorkloadRPO(v); err == nil {
		t.Fatal("recent DB1 masked stale DB2 data in signed protection group")
	}
	v.LastRecoverableWriteAt = v.Workloads[2].LastRecoverableWriteAt
	v.RecoveryWatermark = v.Workloads[2].RecoveryWatermark
	v.MeasuredRPOSeconds = 601
	if err := verifyConservativeDRWorkloadRPO(v); err != nil {
		t.Fatal("the conservative worst DB2 timestamp was rejected", err)
	}
	actual, err := measuredDRRecoveryPointRPO(v, now)
	if err != nil || actual != 601 || actual <= 300 {
		t.Fatalf("worst workload must breach 300s policy: actual=%d err=%v", actual, err)
	}

	tests := []struct {
		name  string
		alter func(*DRCompletionProof)
	}{
		{"missing_second_database_write", func(v *DRCompletionProof) { v.Workloads[2].LastRecoverableWriteAt = time.Time{} }},
		{"missing_second_database_watermark", func(v *DRCompletionProof) { v.Workloads[2].RecoveryWatermark = "" }},
		{"oldest_watermark_not_global", func(v *DRCompletionProof) { v.RecoveryWatermark = "pg:db1:lsn-NEW" }},
		{"oldest_timestamp_not_global", func(v *DRCompletionProof) { v.LastRecoverableWriteAt = v.Workloads[1].LastRecoverableWriteAt }},
		{"write_after_failure", func(v *DRCompletionProof) { v.Workloads[2].LastRecoverableWriteAt = now.Add(time.Nanosecond) }},
		{"write_after_verifier_issued", func(v *DRCompletionProof) { v.Workloads[2].LastRecoverableWriteAt = v.IssuedAt.Add(time.Nanosecond) }},
		{"malformed_second_watermark", func(v *DRCompletionProof) { v.Workloads[2].RecoveryWatermark = "lineage\nbroken" }},
		{"stateless_must_not_assert_database_commit", func(v *DRCompletionProof) { v.Workloads[0].RecoveryWatermark = "fabricated" }},
		{"missing_all_stateful_workloads", func(v *DRCompletionProof) { v.Workloads = v.Workloads[:1] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := v
			bad.Workloads = append([]DRCompletedWorkload(nil), v.Workloads...)
			tc.alter(&bad)
			if err := verifyConservativeDRWorkloadRPO(bad); err == nil {
				t.Fatal("missing, stale, divergent or forged workload recovery-point data accepted")
			}
		})
	}
}

func TestDRSignedStatefulRecoveryPointCannotHideStaleDatabase(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("8", 32)
	x.fence(nonce, "FAILOVER", nil)
	if resp := x.begin(nonce, "FAILOVER"); resp.Code != 202 {
		t.Fatalf("signed fixture setup blocked: %d %s", resp.Code, resp.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("expected restored-but-unpromoted DR before signed verification")
	}
	x.completion(job, func(v *DRCompletionProof) {
		for i := range v.Workloads {
			if v.Workloads[i].Kind == "STATEFUL" {
				v.Workloads[i].LastRecoverableWriteAt = v.FailureObservedAt.Add(-601 * time.Second)
				v.Workloads[i].RecoveryWatermark = "pg:db2:lsn-OLD"
			}
		}
		// Malicious/incorrect verifier signs a CURRENT GLOBAL RPO alongside
		// the old per-stateful-workload data.
		v.MeasuredRPOSeconds = 45
	})
	if _, _, err := verifiedDRCompletion(x.config, job, time.Now().UTC()); err == nil {
		t.Fatal("valid signature with misleading group-global RPO admitted")
	}
	if _, err := x.portal.finalizeDRTransitionWithProof(t.Context(), x.ws, "nonempty-prechecked-proof", 300); err == nil {
		t.Fatal("stale stateful data promoted while the global clock looked current")
	}
	observed, err := readDRTransition(x.ws)
	if err != nil || observed.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatalf("invalid signed group proof advanced active writer: %+v err=%v", observed, err)
	}
}
