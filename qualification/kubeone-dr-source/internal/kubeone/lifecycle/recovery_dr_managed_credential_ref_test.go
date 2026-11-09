package lifecycle

import "testing"

func TestDRExecutionRequiresOpaqueManagedCredentialReference(t *testing.T) {
	x := setupDRExecutionFixture(t)
	cfg := x.portal.recovery.config
	cfg.DRExecutions[0].Workloads[0].ManagedCredentialRef = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("DR execution accepted missing managed credential reference")
	}
}

func TestDRExecutionRequiresSharedManagedCredentialReference(t *testing.T) {
	x := setupDRExecutionFixture(t)
	cfg := x.portal.recovery.config
	cfg.DRExecutions[0].Workloads[1].ManagedCredentialRef = "other-managed-ref"
	if err := cfg.Validate(); err == nil {
		t.Fatal("DR execution accepted mismatched workload credential references")
	}
}
