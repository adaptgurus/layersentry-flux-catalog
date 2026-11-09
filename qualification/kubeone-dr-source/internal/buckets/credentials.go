package buckets

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrCredentialProviderUnavailable    = errors.New("managed storage credential provider unavailable")
	ErrCredentialCustodyUnavailable     = errors.New("managed storage credential custody unavailable")
	ErrCredentialVerificationFailed     = errors.New("managed storage credential verification failed")
	ErrCredentialReconciliationRequired = errors.New("managed storage credential identity requires reconciliation")
)

// IssuedCredential is provider-returned secret material. It is deliberately
// confined to the server-side credential controller and must never be exposed
// through customer-facing API/status objects. Callers should treat Secret as
// ephemeral and allow Issue to zero it after custody accepts or rejects it.
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

// CredentialAccessVerifier must prove authenticated object access using the
// candidate identity (not only read its stored bytes). Implementations are
// independent storage adapters, never the browser or an untrusted status flag.
type CredentialAccessVerifier interface {
	VerifyObjectAccess(context.Context, string, CredentialReference) error
}

// CredentialActivator must atomically and durably switch the configured active
// storage identity; an uncertain return leaves both identities for reconciliation.
type CredentialActivator interface {
	ActivateCredential(context.Context, string, CredentialReference, CredentialReference) error
}

// CredentialRevocationIntent binds the exact durable pre-mutation record.
// It never contains secret material or authorizes a blind replay.
type CredentialRevocationIntent struct {
	JournalID string
	Reference CredentialReference
}

// CredentialRevocationJournal must durably and atomically admit each exact
// reference at most once before provider mutation. An existing/uncertain
// record MUST fail closed, never replay. Complete records the confirmed final
// state after provider and custody operations have both succeeded.
type CredentialRevocationJournal interface {
	BeginRevocation(context.Context, CredentialReference) (CredentialRevocationIntent, error)
	CompleteRevocation(context.Context, CredentialRevocationIntent) error
}

type ManagedCredentialController struct {
	Provider    CredentialProvider
	Custody     CredentialCustody
	Access      CredentialAccessVerifier
	Activator   CredentialActivator
	Revocations CredentialRevocationJournal
	TTL         time.Duration
}

const credentialHandoffMargin = 5 * time.Minute
const credentialCleanupTimeout = 5 * time.Second

func (c ManagedCredentialController) validate() error {
	if c.Provider == nil {
		return ErrCredentialProviderUnavailable
	}
	if c.Custody == nil || c.TTL <= credentialHandoffMargin {
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

// cleanupProviderIdentity is one bounded best-effort revocation. An unknown
// outcome is never treated as completed cleanup or as a safe next rotation.
func (c ManagedCredentialController) cleanupProviderIdentity(ctx context.Context, providerID string) error {
	if providerID == "" {
		return ErrCredentialReconciliationRequired
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialCleanupTimeout)
	defer cancel()
	if err := c.Provider.RevokeCredential(cleanup, providerID); err != nil {
		return ErrCredentialReconciliationRequired
	}
	return nil
}

// abortUnactivatedCredential is valid only before durable activation. It
// performs bounded cleanup without inheriting the canceled caller context;
// either uncertain cleanup makes the identity require reconciliation.
func (c ManagedCredentialController) abortUnactivatedCredential(ctx context.Context, ref CredentialReference) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialCleanupTimeout)
	custodyErr := c.Custody.DeleteCredential(cleanup, ref)
	cancel()
	providerErr := c.cleanupProviderIdentity(ctx, ref.ProviderCredentialID)
	if custodyErr != nil || providerErr != nil {
		return ErrCredentialReconciliationRequired
	}
	return ErrCredentialVerificationFailed
}

// Issue stores a new provider identity in protected custody and verifies it
// before returning an opaque reference. It is NOT yet proof of authenticated
// object access, and must not by itself activate or retire an existing writer.
func (c ManagedCredentialController) Issue(ctx context.Context, bucket string) (CredentialReference, error) {
	return c.issueExcluding(ctx, bucket, "")
}

// issueExcluding is used by rotation so a provider that reuses the current
// active identity can never cause that identity to be revoked by validation
// cleanup. Such an issuer response is ambiguous and requires reconciliation.
func (c ManagedCredentialController) issueExcluding(ctx context.Context, bucket, activeProviderID string) (CredentialReference, error) {
	if ctx == nil || ctx.Err() != nil {
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	if err := c.validate(); err != nil {
		return CredentialReference{}, err
	}
	if strings.TrimSpace(bucket) == "" {
		return CredentialReference{}, ErrCredentialProviderUnavailable
	}
	material, providerErr := c.Provider.IssueCredential(ctx, bucket, c.TTL)
	defer wipeCredential(&material)
	if activeProviderID != "" && material.ProviderCredentialID == activeProviderID {
		return CredentialReference{}, ErrCredentialReconciliationRequired
	}
	// The issuer may have mutated provider state before returning even when
	// it ignores cancellation. Never persist the returned material from a
	// canceled request; a missing identity cannot be safely reconciled.
	if ctx.Err() != nil {
		if material.ProviderCredentialID == "" {
			return CredentialReference{}, ErrCredentialReconciliationRequired
		}
		if err := c.cleanupProviderIdentity(ctx, material.ProviderCredentialID); err != nil {
			return CredentialReference{}, err
		}
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	now := time.Now()
	// Reject unusable/near-expired credentials before custody or any rotation
	// cutover. A provider returning material plus an error may already have
	// issued a key: do not silently abandon a known provider identity.
	invalid := providerErr != nil || material.ProviderCredentialID == "" ||
		strings.TrimSpace(material.AccessKeyID) == "" ||
		len(material.AccessKeyID) > 128 || strings.ContainsAny(material.AccessKeyID, "\r\n\x00") ||
		len(material.Secret) < 24 || len(material.Secret) > 4096 ||
		!material.ExpiresAt.After(now.Add(credentialHandoffMargin)) ||
		material.ExpiresAt.After(now.Add(c.TTL+time.Minute))
	if invalid {
		if material.ProviderCredentialID != "" {
			if err := c.cleanupProviderIdentity(ctx, material.ProviderCredentialID); err != nil {
				return CredentialReference{}, err
			}
		}
		return CredentialReference{}, ErrCredentialProviderUnavailable
	}
	ref, err := c.Custody.StoreCredential(ctx, bucket, material)
	if err != nil || ref.ID == "" || ref.ProviderCredentialID != material.ProviderCredentialID ||
		!ref.ExpiresAt.Equal(material.ExpiresAt) {
		// The custody effect may have partially completed. Invalidate the
		// provider key first; if that is uncertain, report reconciliation.
		if cleanupErr := c.cleanupProviderIdentity(ctx, material.ProviderCredentialID); cleanupErr != nil {
			return CredentialReference{}, cleanupErr
		}
		return CredentialReference{}, ErrCredentialCustodyUnavailable
	}
	if ctx.Err() != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, ref)
	}
	if err := c.Custody.VerifyCredential(ctx, ref); err != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, ref)
	}
	if ctx.Err() != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, ref)
	}
	return ref, nil
}

// Rotate requires BOTH authenticated object access and a durable active-ref
// cutover before revoking the previous provider identity. A custody-only
// check is insufficient. With no real verifier/activator, it fails before
// creating a credential; the current lab has no enabled provider adapter.
func (c ManagedCredentialController) Rotate(ctx context.Context, bucket string, previous CredentialReference) (CredentialReference, error) {
	if ctx == nil || ctx.Err() != nil {
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	if err := c.validate(); err != nil {
		return CredentialReference{}, err
	}
	if c.Access == nil || c.Activator == nil {
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	if previous.ID == "" || previous.ProviderCredentialID == "" {
		return CredentialReference{}, ErrCredentialVerificationFailed
	}
	next, err := c.issueExcluding(ctx, bucket, previous.ProviderCredentialID)
	if err != nil {
		return CredentialReference{}, err
	}
	if next.ProviderCredentialID == previous.ProviderCredentialID || next.ID == previous.ID {
		// The provider may have updated the existing identity in place. Do
		// NOT revoke or delete either reference from this ambiguous state.
		return next, ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, next)
	}
	if err := c.Access.VerifyObjectAccess(ctx, bucket, next); err != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, next)
	}
	// Fail closed even if the access adapter ignored cancellation. We may
	// still safely clean the candidate because activation has not started.
	if ctx.Err() != nil {
		return CredentialReference{}, c.abortUnactivatedCredential(ctx, next)
	}
	if err := c.Activator.ActivateCredential(ctx, bucket, previous, next); err != nil {
		// The durable cutover outcome may be unknown. Keep both for explicit
		// reconciliation rather than revoking a possibly active identity.
		return next, ErrCredentialReconciliationRequired
	}
	// Activation might already be committed; never attempt rollback on a
	// canceled context, and never retire the previous key without proof.
	if ctx.Err() != nil {
		return next, ErrCredentialReconciliationRequired
	}
	if err := c.Access.VerifyObjectAccess(ctx, bucket, next); err != nil {
		return next, ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return next, ErrCredentialReconciliationRequired
	}
	if err := c.Provider.RevokeCredential(ctx, previous.ProviderCredentialID); err != nil {
		return next, ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return next, ErrCredentialReconciliationRequired
	}
	if err := c.Custody.DeleteCredential(ctx, previous); err != nil {
		return next, ErrCredentialCustodyUnavailable
	}
	if ctx.Err() != nil {
		return next, ErrCredentialReconciliationRequired
	}
	return next, nil
}

// Revoke requires a durable, single-use intent before any provider effect.
// Context cancellation before admission has no effects. Every ambiguous
// provider/custody result leaves the pre-admitted intent UNKNOWN, blocking
// blind retries until independently reconciled. Journal errors are redacted.
func (c ManagedCredentialController) Revoke(ctx context.Context, ref CredentialReference) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrCredentialVerificationFailed
	}
	if err := c.validate(); err != nil {
		return err
	}
	if c.Revocations == nil {
		return ErrCredentialReconciliationRequired
	}
	if ref.ID == "" || ref.ProviderCredentialID == "" || ref.ExpiresAt.IsZero() {
		return ErrCredentialVerificationFailed
	}
	intent, err := c.Revocations.BeginRevocation(ctx, ref)
	if err != nil || intent.JournalID == "" || !sameCredentialReference(intent.Reference, ref) {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	if err := c.Provider.RevokeCredential(ctx, ref.ProviderCredentialID); err != nil {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	if err := c.Custody.DeleteCredential(ctx, ref); err != nil {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	if err := c.Revocations.CompleteRevocation(ctx, intent); err != nil {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	return nil
}
