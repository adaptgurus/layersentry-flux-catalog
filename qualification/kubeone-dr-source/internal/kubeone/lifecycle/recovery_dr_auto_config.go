package lifecycle

import "fmt"

// A policy exists only when a separately registered DR execution and signer
// already exist. Opting into monitoring never grants an infrastructure mutation.
func validateDRAutomation(cfg RecoveryConfig) error {
	seen := make(map[string]bool)
	for _, a := range cfg.DRAutomation {
		key := registryKey(a.Tenant, a.SourceClusterID) + ":" + a.TargetClusterID
		if a.Tenant == "" || !recoveryIDPattern.MatchString(a.SourceClusterID) ||
			!recoveryIDPattern.MatchString(a.TargetClusterID) ||
			a.SourceClusterID == a.TargetClusterID || seen[key] {
			return fmt.Errorf("%w: duplicate or invalid automatic DR pair", ErrValidation)
		}
		seen[key] = true
		if !a.Enabled {
			if a.AutoFailover || a.AutoFailback {
				return fmt.Errorf("%w: disabled DR must not perform transitions", ErrValidation)
			}
			continue
		}
		if (!a.AutoFailover && !a.AutoFailback) ||
			a.ControllerClusterID != a.TargetClusterID ||
			a.PollSeconds < 15 || a.PollSeconds > 300 ||
			a.SourceFailureChecks < 3 || a.SourceFailureChecks > 60 ||
			a.TargetReadyChecks < 2 || a.TargetReadyChecks > 60 ||
			a.FailbackHealthyChecks < 3 || a.FailbackHealthyChecks > 120 ||
			a.FailbackHoldSeconds < 900 || a.FailbackHoldSeconds > 86400 ||
			a.MaxBackupAgeSeconds < 60 || a.MaxBackupAgeSeconds > 86400 ||
			a.MaxRPOSeconds < 1 || a.MaxRPOSeconds > 3600 {
			return fmt.Errorf("%w: invalid DR monitoring hysteresis, controller site or RPO budget", ErrValidation)
		}
		found := false
		for _, e := range cfg.DRExecutions {
			if e.Tenant == a.Tenant && e.SourceClusterID == a.SourceClusterID &&
				e.TargetClusterID == a.TargetClusterID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: automatic DR has no separately authorized signed execution", ErrValidation)
		}
	}
	return nil
}

// ValidateAutoDRControllerSite runs before server startup. The only permitted
// automatic supervisor is an explicitly configured registered DR-side owner.
func (p *Portal) ValidateAutoDRControllerSite(site string) error {
	if p == nil || p.recovery == nil || !recoveryIDPattern.MatchString(site) {
		return fmt.Errorf("%w: automatic DR requires protected server registration", ErrValidation)
	}
	count := 0
	for _, policy := range p.recovery.config.DRAutomation {
		if !policy.Enabled {
			continue
		}
		if policy.ControllerClusterID != site || policy.TargetClusterID != site {
			return fmt.Errorf("%w: configured automatic controller is not the independent DR site", ErrValidation)
		}
		if _, err := p.Client.Workspace(policy.Tenant, policy.SourceClusterID); err != nil {
			return ErrValidation
		}
		if _, err := p.Client.Workspace(policy.Tenant, policy.TargetClusterID); err != nil {
			return ErrValidation
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("%w: no opted-in automatic DR policies", ErrValidation)
	}
	return nil
}
