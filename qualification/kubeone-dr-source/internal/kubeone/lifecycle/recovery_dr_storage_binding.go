package lifecycle

import (
	"context"
	"errors"
	"time"
)

// DRStorageCredentialBinding is an opaque server-to-server admission request,
// not a credential-bearing customer request. RestoreSiteClusterID is the
// cluster that will consume the Velero BackupStorageLocation in this direction.
type DRStorageCredentialBinding struct {
	Tenant                   string
	ProtectedSourceClusterID string
	ProtectedTargetClusterID string
	RestoreSiteClusterID     string
	BackupStorageLocation    string
	ManagedCredentialRef     string
}

// DRStorageCredentialVerifier is an independently registered provider/custody
// adapter. A production implementation MUST resolve the exact opaque custody
// reference, reject revoked/expired identities, check authorization for the
// exact observed native BSL/provider/bucket/endpoint, and prove authenticated
// object access on the intended restore site. It must reject a replaced BSL
// identity and must never accept a mere customer-supplied status or token.
// There is deliberately no default verifier or permissive implementation.
type DRStorageCredentialVerifier interface {
	VerifyBoundStorageCredential(context.Context, DRStorageCredentialBinding) error
}

func (m *RecoveryManager) verifyDRStorageCredentialBindings(ctx context.Context,
	profile DRExecutionProfile, restoreSite Workspace) error {
	if m == nil || m.storageBindingVerifier == nil || len(profile.Workloads) != 2 ||
		profile.Tenant == "" || restoreSite.Tenant != profile.Tenant ||
		(restoreSite.ClusterID != profile.TargetClusterID && restoreSite.ClusterID != profile.SourceClusterID) {
		return ErrValidation
	}
	if profile.Workloads[0].ManagedCredentialRef == "" ||
		profile.Workloads[1].ManagedCredentialRef != profile.Workloads[0].ManagedCredentialRef {
		return ErrValidation
	}
	for _, workload := range profile.Workloads {
		if !recoveryIDPattern.MatchString(workload.ManagedCredentialRef) ||
			!recoveryIDPattern.MatchString(workload.StorageLocation) {
			return ErrValidation
		}
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := m.storageBindingVerifier.VerifyBoundStorageCredential(checkCtx, DRStorageCredentialBinding{
			Tenant:                   profile.Tenant,
			ProtectedSourceClusterID: profile.SourceClusterID,
			ProtectedTargetClusterID: profile.TargetClusterID,
			RestoreSiteClusterID:     restoreSite.ClusterID,
			BackupStorageLocation:    workload.StorageLocation,
			ManagedCredentialRef:     workload.ManagedCredentialRef,
		})
		cancel()
		if err != nil {
			// Never return underlying provider/custody/BSL errors; they may
			// contain protected endpoints, identities, or credential material.
			return errors.Join(ErrValidation, errors.New("managed DR storage credential binding unavailable"))
		}
	}
	return nil
}
