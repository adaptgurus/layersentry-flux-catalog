package lifecycle

import (
	"testing"
	"time"
)

// The application verifier must sign the RECOVERED data generation and a
// failure/cutover reference, not just assert an arbitrary duration or cite
// a backup-controller completion time. This test is SOURCE_ONLY.
func TestDRRecoveryWatermarkDerivesRPOAndFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sample := DRCompletionProof{
		Version:                2,
		LastRecoverableWriteAt: now.Add(-300 * time.Second),
		FailureObservedAt:      now,
		RecoveryWatermark:      "pg:timeline-1:lsn-0A-B2",
		MeasuredRPOSeconds:     300,
		IssuedAt:               now.Add(time.Second),
	}
	if seconds, err := measuredDRRecoveryPointRPO(sample, now); err != nil || seconds != 300 {
		t.Fatalf("exact RPO boundary rejected: seconds=%d err=%v", seconds, err)
	}

	tests := []struct {
		name   string
		change func(*DRCompletionProof)
	}{
		{"legacy_v1_without_watermark", func(v *DRCompletionProof) { v.Version = 1 }},
		{"missing_watermark", func(v *DRCompletionProof) { v.RecoveryWatermark = "" }},
		{"malformed_watermark", func(v *DRCompletionProof) { v.RecoveryWatermark = "../\nunsafe" }},
		{"missing_commit_timestamp", func(v *DRCompletionProof) { v.LastRecoverableWriteAt = time.Time{} }},
		{"missing_failure_reference", func(v *DRCompletionProof) { v.FailureObservedAt = time.Time{} }},
		{"future_failure", func(v *DRCompletionProof) {
			v.FailureObservedAt = now.Add(20 * time.Second)
			v.IssuedAt = now.Add(25 * time.Second)
		}},
		{"commit_after_failure", func(v *DRCompletionProof) {
			v.LastRecoverableWriteAt = v.FailureObservedAt.Add(time.Nanosecond)
		}},
		{"reported_rpo_understates_loss", func(v *DRCompletionProof) { v.MeasuredRPOSeconds-- }},
		{"duration_over_24_hours", func(v *DRCompletionProof) {
			v.LastRecoverableWriteAt = now.Add(-25 * time.Hour)
			v.MeasuredRPOSeconds = 25 * 3600
		}},
		{"subsecond_loss_rounded_down", func(v *DRCompletionProof) {
			v.LastRecoverableWriteAt = v.LastRecoverableWriteAt.Add(-time.Nanosecond)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := sample
			tc.change(&v)
			if _, err := measuredDRRecoveryPointRPO(v, now); err == nil {
				t.Fatal("missing, forged, non-monotonic or understated recovery watermark accepted")
			}
		})
	}

	subsecond := sample
	subsecond.LastRecoverableWriteAt = subsecond.LastRecoverableWriteAt.Add(time.Nanosecond)
	subsecond.MeasuredRPOSeconds = 300
	if _, err := measuredDRRecoveryPointRPO(subsecond, now); err != nil {
		t.Fatalf("subsecond 299.999s age should conservatively ceil to 300s: %v", err)
	}
}
