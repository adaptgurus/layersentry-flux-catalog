package lifecycle

import (
	"strings"
	"testing"
)

// The actual 7 Nov DC lab verified that restoring a Kopia PVC while retaining
// spec.volumeName silently targeted the source PV and left the new claim
// Pending. A warm DR restore must configure an independent target PVC and
// require Velero to apply an immutable, identity-scoped resource modifier.
func TestDRKopiaRestoreRequiresIndependentTargetPVC(t *testing.T) {
	profile := DRWorkloadProfile{
		Namespace: "app-pg", Kind: "STATEFUL",
		PVCName: "postgres-data", VolumeRecoveryKind: "FSB_KOPIA",
	}
	name := "lsdr-pv-a7f30"
	falseValue := false
	v := nativeVeleroRestore{}
	v.Spec.RestorePVs = &falseValue
	v.Spec.ExcludedResources = []string{"persistentvolumes"}
	v.Spec.ResourceModifier.Kind = "configmap"
	v.Spec.ResourceModifier.Name = drKopiaModifierName(name, profile)
	if !drKopiaRestoreSpecValid(profile, name, v) {
		t.Fatal("qualified Kopia restore with clean target rule was rejected")
	}
	if drKopiaModifierName(name, profile) != drKopiaModifierName(name, profile) {
		t.Fatal("modifier ID must be deterministic for one recovery operation")
	}
	if drKopiaModifierName("lsdr-pv-b3f40", profile) == drKopiaModifierName(name, profile) {
		t.Fatal("different recovery epochs must not reuse a modifier ID")
	}
	if len(v.Spec.ResourceModifier.Name) > 63 || !strings.HasPrefix(v.Spec.ResourceModifier.Name, "lsdr-pvc-") {
		t.Fatalf("modifier must be a bounded Kubernetes DNS label, got %q", v.Spec.ResourceModifier.Name)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*nativeVeleroRestore)
	}{
		{"source_pv_restore_enabled", func(x *nativeVeleroRestore) { yes := true; x.Spec.RestorePVs = &yes }},
		{"unspecified_pv_restore", func(x *nativeVeleroRestore) { x.Spec.RestorePVs = nil }},
		{"missing_persistentvolume_exclusion", func(x *nativeVeleroRestore) { x.Spec.ExcludedResources = nil }},
		{"wrong_pv_exclusion", func(x *nativeVeleroRestore) { x.Spec.ExcludedResources = []string{"events"} }},
		{"wrong_modifier_kind", func(x *nativeVeleroRestore) { x.Spec.ResourceModifier.Kind = "Secret" }},
		{"foreign_api_group", func(x *nativeVeleroRestore) { x.Spec.ResourceModifier.APIGroup = "attacker.io" }},
		{"missing_modifier", func(x *nativeVeleroRestore) { x.Spec.ResourceModifier.Name = "" }},
		{"previous_epoch_modifier", func(x *nativeVeleroRestore) {
			x.Spec.ResourceModifier.Name = drKopiaModifierName("lsdr-pv-b3f40", profile)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := v
			tc.mutate(&bad)
			if drKopiaRestoreSpecValid(profile, name, bad) {
				t.Fatal("unsafe cross-site source PV/CSI identity admitted")
			}
		})
	}
}

// Validate the fixture's native-create workflow now requires a resource
// modifier before the stateful Restore CR is dispatched in either direction.
func TestDRKopiaModifierCreatedBeforeStatefulRestore(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("4", 32)
	x.fence(nonce, "FAILOVER", nil)
	if first := x.begin(nonce, "FAILOVER"); first.Code != 202 {
		t.Fatalf("signed lab fixture admission failed: %d %s", first.Code, first.Body.String())
	}
	job := x.waitRestore(nonce)
	if job.Status != "RESTORE_OBSERVED_PENDING_APP_AND_TRAFFIC" ||
		x.runner.restoreCalls != 2 || x.runner.modifierCalls != 1 {
		t.Fatalf("stateful Kopia restore bypassed or duplicated modifier creation: %+v restores=%d modifiers=%d", job, x.runner.restoreCalls, x.runner.modifierCalls)
	}
}
