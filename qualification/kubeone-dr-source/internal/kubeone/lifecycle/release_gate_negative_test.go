package lifecycle

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Source-only signature-boundary regression. Fixture keys never represent a
// production fencer/verifier; every command uses the existing fake runner.
func TestReleaseGateV2FieldTamperingNeverAdvancesJournal(t *testing.T) {
	for _, field := range []string{"write", "failure", "watermark", "rpo"} {
		t.Run(field, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			nonce := strings.Repeat("c", 32)
			x.fence(nonce, "FAILOVER", nil)
			if r := x.begin(nonce, "FAILOVER"); r.Code != 202 {
				t.Fatal(r.Code, r.Body.String())
			}
			job := x.waitRestore(nonce)
			x.completion(job, nil)
			if _, _, err := verifiedDRCompletion(x.config, job, time.Now().UTC()); err != nil {
				t.Fatal("valid control", err)
			}
			raw, err := os.ReadFile(x.config.RecoveryVerificationFile)
			if err != nil {
				t.Fatal(err)
			}
			var proof DRSignedCompletion
			if err = json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "write":
				proof.Payload.LastRecoverableWriteAt = proof.Payload.LastRecoverableWriteAt.Add(time.Nanosecond)
			case "failure":
				proof.Payload.FailureObservedAt = proof.Payload.FailureObservedAt.Add(-time.Nanosecond)
			case "watermark":
				proof.Payload.RecoveryWatermark = "pg:timeline-2:lsn-0A-B3"
			case "rpo":
				proof.Payload.MeasuredRPOSeconds++
			}
			raw, err = json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(x.config.RecoveryVerificationFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err = verifiedDRCompletion(x.config, job, time.Now().UTC()); err == nil {
				t.Fatal("post-signature field tampering accepted")
			}
			if _, err = x.portal.finalizeDRTransition(context.Background(), x.ws); err == nil {
				t.Fatal("tampered receipt finalized")
			}
			recorded, err := readDRTransition(x.ws)
			if err != nil || recorded.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatal("journal advanced", recorded, err)
			}
		})
	}
}
