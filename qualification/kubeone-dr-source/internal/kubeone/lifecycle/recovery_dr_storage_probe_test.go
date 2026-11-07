package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A signed V2 application and HTTP recovery proof is insufficient to
// promote an existing NFS-backed DR writer when no separate confirmed,
// fsynced write/read of the exact newly recovered target PVC is attested.
// The running Kube API can be healthy while the NFSv4 QEMU file state is not.
func TestDRSignedV2RefusesMissingTargetPVCStorageProbe(t *testing.T) {
	x := setupDRExecutionFixture(t)
	op := strings.Repeat("9", 32)
	x.fence(op, "FAILOVER", nil)
	if r := x.begin(op, "FAILOVER"); r.Code != 202 {
		t.Fatalf("setup failed: %d %s", r.Code, r.Body.String())
	}
	job := x.waitRestore(op)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal(job.Status)
	}
	x.completion(job, func(v *DRCompletionProof) {
		for i := range v.Workloads {
			if v.Workloads[i].Kind == "STATEFUL" {
				v.Workloads[i].StorageProbePVCUID = ""
				v.Workloads[i].StorageProbeCompletedAt = time.Time{}
				v.Workloads[i].StorageProbeReadbackSHA256 = ""
			}
		}
	})
	if _, _, err := verifiedDRCompletion(x.config, job, time.Now().UTC()); err == nil {
		t.Fatal("signed V2 proof without actual recovered-PVC storage fsync/readback was accepted")
	}
}

func TestDRSignedV2RejectsStaleOrForgedStorageProbe(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DRCompletionProof)
	}{
		{"missing_target_pvc_uid", func(v *DRCompletionProof) { v.Workloads[1].StorageProbePVCUID = "" }},
		{"malformed_target_pvc_uid", func(v *DRCompletionProof) { v.Workloads[1].StorageProbePVCUID = "../../15/disk.0" }},
		{"fake_signed_marker_readback", func(v *DRCompletionProof) { v.Workloads[1].StorageProbeReadbackSHA256 = strings.Repeat("0", 64) }},
		{"probe_before_restore_completed", func(v *DRCompletionProof) { v.Workloads[1].StorageProbeCompletedAt = v.IssuedAt.Add(-6 * time.Minute) }},
		{"probe_after_signer_issued", func(v *DRCompletionProof) { v.Workloads[1].StorageProbeCompletedAt = v.IssuedAt.Add(time.Nanosecond) }},
		{"stateless_spoof", func(v *DRCompletionProof) { v.Workloads[0].StorageProbePVCUID = "99999999-9999-4999-8999-999999999999" }},
		{"different_target_pvc", func(v *DRCompletionProof) {
			v.Workloads[1].StorageProbePVCUID = "88888888-8888-4888-8888-888888888888"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			op := strings.Repeat("a", 32)
			x.fence(op, "FAILOVER", nil)
			if r := x.begin(op, "FAILOVER"); r.Code != 202 {
				t.Fatal(r.Code, r.Body.String())
			}
			job := x.waitRestore(op)
			if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatal(job.Status)
			}
			x.completion(job, tc.mutate)
			if _, _, err := verifiedDRCompletion(x.config, job, time.Now().UTC()); err == nil {
				t.Fatal("valid signature with unsafe stale/forged/missing target PVC storage probe accepted")
			}
			observed, err := readDRTransition(x.ws)
			if err != nil || observed.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
				t.Fatal("rejected storage proof advanced writer", err, observed)
			}
		})
	}
}

func TestDRCompletionRefusesCurrentPVCDifferentFromSignedProbeUID(t *testing.T) {
	x := setupDRExecutionFixture(t)
	op := strings.Repeat("b", 32)
	x.fence(op, "FAILOVER", nil)
	if r := x.begin(op, "FAILOVER"); r.Code != 202 {
		t.Fatal(r.Code, r.Body.String())
	}
	job := x.waitRestore(op)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal(job.Status)
	}
	x.completion(job, nil)
	_, digest, err := verifiedDRCompletion(x.config, job, time.Now().UTC())
	if err != nil {
		t.Fatal("valid independent test proof rejected", err)
	}
	// Velero's historical PodVolumeRestore and the live PVC can both point
	// to a different replacement claim, while the signer saw the OLD UID.
	// The finalizer must compare the exact signed UID to the live object.
	foreign := "88888888-8888-4888-8888-888888888888"
	x.runner.mu.Lock()
	x.runner.pvcUID = foreign
	x.runner.pvrPVCUID = foreign
	x.runner.mu.Unlock()
	if _, err := x.portal.finalizeDRTransitionWithProof(context.Background(), x.ws, digest, 300); err == nil {
		t.Fatal("new PVC identity falsely admitted under previous signed fsync probe")
	}
	state, err := readDRTransition(x.ws)
	if err != nil || state.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal("replaced PVC was promoted", err, state)
	}
}

// A probe valid at issuance must not stay fresh for the entire 3-5 minute
// signed envelope while the target filesystem could have lost NFSv4 locks.
func TestDRStorageProbeExpiresBeforeSignedEnvelope(t *testing.T) {
	x := setupDRExecutionFixture(t)
	op := strings.Repeat("c", 32)
	x.fence(op, "FAILOVER", nil)
	if r := x.begin(op, "FAILOVER"); r.Code != 202 {
		t.Fatal(r.Code, r.Body.String())
	}
	job := x.waitRestore(op)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" {
		t.Fatal(job.Status)
	}
	x.completion(job, nil)
	issued := time.Now().UTC()
	if _, _, err := verifiedDRCompletion(x.config, job, issued); err != nil {
		t.Fatal("fresh independently signed target storage proof rejected", err)
	}
	// Signed envelope has not expired, but the separate storage
	// fsync/readback is 120 seconds old and cannot authorize promotion.
	if _, _, err := verifiedDRCompletion(x.config, job, issued.Add(2*time.Minute)); err == nil {
		t.Fatal("120-second stale storage probe accepted under still-valid signed envelope")
	}
}
