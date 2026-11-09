package buckets

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrCredentialProviderUnavailable = errors.New("managed storage credential provider unavailable")
	ErrCredentialCustodyUnavailable  = errors.New("managed storage credential custody unavailable")
	ErrCredentialVerificationFailed  = errors.New("managed storage credential verification failed")
)

// IssuedCredential is provider-returned secret material. It is deliberately
// confined to the server-side credential controller and must never be exposed
// through customer-facing API/status objects. Callers should treat Secret as
// ephemeral and allow Rotate to zero it after custody accepts or rejects it.
type IssuedCredential struct {
	ProviderCredentialID string
	AccessKeyID          string
	Secret               []byte
	ExpiresAt            time.Time
}

// CredentialReference is the only durable value the recovery layer needs.
// It contains no access key or secret value.
type CredentialReference struct {
	ID                   string
	ProviderCredentialID string
	ExpiresAt            time.Time
}

type CredentialProvider interface {
	IssueCredential(context.Context, string, time.Duration) (IssuedCredential, error)
	RevokeCredential(context.Context, string) error
}

type CredentialCustody interface {
	StoreCredential(context.Context, string, IssuedCredential) (CredentialReference, error)
	VerifyCredential(context.Context, CredentialReference) error
	DeleteCredential(context.Context, CredentialReference) error
}

type ManagedCredentialController struct {
	Provider CredentialProvider
	Custody  CredentialCustody
	TTL      time.Duration
}

func (c ManagedCredentialController) validate() error {
	if c.Provider == nil {
		return ErrCredentialProviderUnavailable
	}
	if c.Custody == nil || c.TTL <= 0 {
		return ErrCredentialCustodyUnavailable
	}
	return nil
}

func wipeCredential(v *IssuedCredential) {
	if v == nil {
		return
	}
	for i := range v.Secret {
		v.Secret[i] = 0
	}
	v.Secret = nil
	v.AccessKeyID = ""
}

// Issue stores a new provider identity in protected custody and verifies it
// before returning an opaque reference. Provider/custody errors are replaced
// with fixed errors so secret-bearing diagnostics cannot escape this boundary.
func (c ManagedCredentialController) Issue(ctx context.Context, bucket string) (CredentialReference, error) {
	if err := c.validate(); err != nil || bucket == "" {
		if err != nil {
			return CredentialReference{}, err
		}
		return CredentialReference{}, ErrCredentialProviderUnavailable
	}
	material, err := c.Provider.IssueCredential(ctx, bucket, c.TTL)
	if err != nil || material.ProviderCredentialID == "" || len(material.Secret) < 24 || material.ExpiresAt.IsZero() {
		wipeCredential(&material)
		return CredentialReference{}, ErrCredentialProviderUnavailable
	}
	defer wipeCredential(&material)
	ref, err := c.Custody.StoreCredential(ctx, bucket, material)
	if err != nil || ref.ID == "" || ref.ProviderCredentialID != material.ProviderCredentialID || ref.ExpiresAt.IsZero() {
		_ = c.Provider.RevokeCredential(context.WithoutCancel(ctx), material.ProviderCredentialID)
		return CredentialReference{}, ErrCredentialCustodyUnavailable
	}
	if err := c.Custody.VerifyCredential(ctx, ref); err != nil {
		_ = c.Custody.DeleteCredential(context.WithoutCancel(ctx), ref)
		_ = c.Provider.RevokeCredential(context.WithoutCancel(ctx), material.ProviderCredentialID)
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	return ref, nil
}

// Rotate uses create-verify-switch-retire ordering. The previous provider
// identity is revoked only after the new credential has passed custody
// verification. This keeps existing repository access available on failure.
func (c ManagedCredentialController) Rotate(ctx context.Context, bucket string, previous CredentialReference) (CredentialReference, error) {
	if previous.ID == "" || previous.ProviderCredentialID == "" {
		return CredentialReference{}, fmt.Errorf("%w: previous credential reference missing", ErrCredentialVerificationFailed)
	}
	next, err := c.Issue(ctx, bucket)
	if err != nil {
		return CredentialReference{}, err
	}
	if err := c.Provider.RevokeCredential(ctx, previous.ProviderCredentialID); err != nil {
		_ = c.Custody.DeleteCredential(context.WithoutCancel(ctx), next)
		_ = c.Provider.RevokeCredential(context.WithoutCancel(ctx), next.ProviderCredentialID)
		return CredentialReference{}, ErrCredentialProviderUnavailable
	}
	if err := c.Custody.DeleteCredential(ctx, previous); err != nil {
		// New provider identity is already active and old provider identity is
		// revoked. Retain the new reference and surface a fixed reconciliation
		// error rather than exposing provider/custody diagnostics.
		return next, ErrCredentialCustodyUnavailable
	}
	return next, nil
}

func (c ManagedCredentialController) Revoke(ctx context.Context, ref CredentialReference) error {
	if err := c.validate(); err != nil {
		return err
	}
	if ref.ID == "" || ref.ProviderCredentialID == "" {
		return ErrCredentialVerificationFailed
	}
	if err := c.Provider.RevokeCredential(ctx, ref.ProviderCredentialID); err != nil {
		return ErrCredentialProviderUnavailable
	}
	if err := c.Custody.DeleteCredential(ctx, ref); err != nil {
		return ErrCredentialCustodyUnavailable
	}
	return nil
}
