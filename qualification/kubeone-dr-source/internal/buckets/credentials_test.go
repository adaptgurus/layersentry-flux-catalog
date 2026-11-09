package buckets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const credentialCanary = "SYNTHETIC-CREDENTIAL-SECRET-CANARY-1234567890"

type credentialProviderFixture struct {
	issueErr, revokeErr error
	issued, revoked     []string
	materialOverride    func(*IssuedCredential)
	issuePartial        bool
	onRevoke            func(string)
	onIssue             func()
}

func (p *credentialProviderFixture) IssueCredential(_ context.Context, bucket string, ttl time.Duration) (IssuedCredential, error) {
	if p.issueErr != nil && !p.issuePartial {
		return IssuedCredential{}, p.issueErr
	}
	id := "provider-" + bucket
	p.issued = append(p.issued, id)
	material := IssuedCredential{ProviderCredentialID: id, AccessKeyID: "AKIA-SYNTHETIC", Secret: []byte(credentialCanary), ExpiresAt: time.Now().Add(ttl)}
	if p.materialOverride != nil {
		p.materialOverride(&material)
	}
	if p.onIssue != nil {
		p.onIssue()
	}
	return material, p.issueErr
}
func (p *credentialProviderFixture) RevokeCredential(_ context.Context, id string) error {
	p.revoked = append(p.revoked, id)
	if p.onRevoke != nil {
		p.onRevoke(id)
	}
	return p.revokeErr
}

type credentialCustodyFixture struct {
	storeErr, verifyErr, deleteErr error
	stored, verified, deleted      []CredentialReference
	secretObserved                 string
	onStore                        func()
	onVerify                       func()
}

func (c *credentialCustodyFixture) StoreCredential(_ context.Context, bucket string, material IssuedCredential) (CredentialReference, error) {
	if c.onStore != nil {
		c.onStore()
	}
	c.secretObserved = string(material.Secret)
	if c.storeErr != nil {
		return CredentialReference{}, c.storeErr
	}
	ref := CredentialReference{ID: "custody-" + bucket, ProviderCredentialID: material.ProviderCredentialID, ExpiresAt: material.ExpiresAt}
	c.stored = append(c.stored, ref)
	return ref, nil
}
func (c *credentialCustodyFixture) VerifyCredential(_ context.Context, ref CredentialReference) error {
	if c.onVerify != nil {
		c.onVerify()
	}
	c.verified = append(c.verified, ref)
	return c.verifyErr
}
func (c *credentialCustodyFixture) DeleteCredential(_ context.Context, ref CredentialReference) error {
	c.deleted = append(c.deleted, ref)
	return c.deleteErr
}

type credentialAccessFixture struct {
	calls      int
	failOnCall int
	err        error
	onCall     func(int)
}

func (a *credentialAccessFixture) VerifyObjectAccess(_ context.Context, _ string, _ CredentialReference) error {
	a.calls++
	if a.onCall != nil {
		a.onCall(a.calls)
	}
	if a.failOnCall == a.calls {
		return a.err
	}
	return nil
}

type credentialActivatorFixture struct {
	calls      int
	err        error
	onActivate func()
}

func (a *credentialActivatorFixture) ActivateCredential(_ context.Context, _ string, _, _ CredentialReference) error {
	a.calls++
	if a.onActivate != nil {
		a.onActivate()
	}
	return a.err
}

func credentialControllerFixture() (*credentialProviderFixture, *credentialCustodyFixture, ManagedCredentialController) {
	p := &credentialProviderFixture{}
	s := &credentialCustodyFixture{}
	return p, s, ManagedCredentialController{Provider: p, Custody: s, Access: &credentialAccessFixture{}, Activator: &credentialActivatorFixture{}, TTL: time.Hour}
}

func TestManagedCredentialIssueReturnsOpaqueReference(t *testing.T) {
	p, s, c := credentialControllerFixture()
	ref, err := c.Issue(context.Background(), "dr-backups")
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID == "" || ref.ProviderCredentialID == "" || ref.ExpiresAt.IsZero() {
		t.Fatal("opaque reference incomplete", ref)
	}
	if s.secretObserved != credentialCanary || len(p.issued) != 1 || len(s.verified) != 1 {
		t.Fatal("provider/custody flow incomplete")
	}
	if strings.Contains(ref.ID, credentialCanary) || strings.Contains(ref.ProviderCredentialID, credentialCanary) {
		t.Fatal("secret leaked into reference")
	}
}

func TestManagedCredentialIssueRedactsProviderAndCustodyErrors(t *testing.T) {
	cases := []struct {
		name     string
		provider bool
		custody  bool
		verify   bool
		want     error
	}{
		{"provider", true, false, false, ErrCredentialProviderUnavailable},
		{"custody", false, true, false, ErrCredentialCustodyUnavailable},
		{"verify", false, false, true, ErrCredentialVerificationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, s, c := credentialControllerFixture()
			secretErr := errors.New("backend failure " + credentialCanary)
			if tc.provider {
				p.issueErr = secretErr
			}
			if tc.custody {
				s.storeErr = secretErr
			}
			if tc.verify {
				s.verifyErr = secretErr
			}
			_, err := c.Issue(context.Background(), "dr-backups")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), credentialCanary) {
				t.Fatal("secret-bearing backend error escaped")
			}
		})
	}
}

func TestManagedCredentialRotationVerifiesBeforeRetiringPrevious(t *testing.T) {
	p, s, c := credentialControllerFixture()
	previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
	next, err := c.Rotate(context.Background(), "dr-backups", previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.verified) != 1 || len(p.revoked) != 1 || p.revoked[0] != "provider-old" || len(s.deleted) != 1 || s.deleted[0].ID != "custody-old" {
		t.Fatal("rotation ordering/effects incorrect", p.revoked, s.verified, s.deleted)
	}
	if next.ProviderCredentialID == previous.ProviderCredentialID {
		t.Fatal("rotation reused provider identity")
	}
}

func TestManagedCredentialRotationFailurePreservesPreviousIdentity(t *testing.T) {
	p, s, c := credentialControllerFixture()
	previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
	s.verifyErr = errors.New("verify " + credentialCanary)
	_, err := c.Rotate(context.Background(), "dr-backups", previous)
	if !errors.Is(err, ErrCredentialVerificationFailed) {
		t.Fatal(err)
	}
	for _, id := range p.revoked {
		if id == previous.ProviderCredentialID {
			t.Fatal("previous identity revoked before replacement verified")
		}
	}
	if len(p.revoked) != 1 || p.revoked[0] != "provider-dr-backups" {
		t.Fatal("failed replacement was not revoked", p.revoked)
	}
}

func TestManagedCredentialRevokeUsesFixedErrors(t *testing.T) {
	p, s, c := credentialControllerFixture()
	ref := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
	p.revokeErr = errors.New("provider " + credentialCanary)
	err := c.Revoke(context.Background(), ref)
	if !errors.Is(err, ErrCredentialProviderUnavailable) || strings.Contains(err.Error(), credentialCanary) {
		t.Fatal(err)
	}
	p.revokeErr = nil
	s.deleteErr = errors.New("custody " + credentialCanary)
	err = c.Revoke(context.Background(), ref)
	if !errors.Is(err, ErrCredentialCustodyUnavailable) || strings.Contains(err.Error(), credentialCanary) {
		t.Fatal(err)
	}
}

func TestManagedCredentialIssueRejectsUnusableMaterialBeforeCustody(t *testing.T) {
	tests := []struct {
		name   string
		change func(*IssuedCredential)
	}{
		{"missing_access_key", func(m *IssuedCredential) { m.AccessKeyID = "" }},
		{"blank_access_key", func(m *IssuedCredential) { m.AccessKeyID = " \t" }},
		{"expired", func(m *IssuedCredential) { m.ExpiresAt = time.Now().Add(-time.Hour) }},
		{"near_expiry", func(m *IssuedCredential) { m.ExpiresAt = time.Now().Add(time.Minute) }},
		{"overlong_lifetime", func(m *IssuedCredential) { m.ExpiresAt = time.Now().Add(2 * time.Hour) }},
		{"short_secret", func(m *IssuedCredential) { m.Secret = []byte("tiny") }},
		{"empty_id", func(m *IssuedCredential) { m.ProviderCredentialID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, s, c := credentialControllerFixture()
			p.materialOverride = tc.change
			_, err := c.Issue(context.Background(), "dr-backups")
			if !errors.Is(err, ErrCredentialProviderUnavailable) {
				t.Fatalf("unusable provider material accepted: %v", err)
			}
			if len(s.stored) != 0 || len(s.verified) != 0 {
				t.Fatal("bad key reached protected custody")
			}
			if tc.name != "empty_id" && (len(p.revoked) != 1 || p.revoked[0] != "provider-dr-backups") {
				t.Fatal("bad credential not revoked", p.revoked)
			}
			if tc.name == "empty_id" && len(p.revoked) != 0 {
				t.Fatal("blank provider identity revoked")
			}
		})
	}
}

func TestManagedCredentialPartialIssueAndUncertainCleanupFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		revokeErr bool
		want      error
	}{
		{"revocation_confirmed", false, ErrCredentialProviderUnavailable},
		{"revocation_uncertain", true, ErrCredentialReconciliationRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s, c := credentialControllerFixture()
			p.issueErr = errors.New("partial issue " + credentialCanary)
			p.issuePartial = true
			if tc.revokeErr {
				p.revokeErr = errors.New("revoke uncertain " + credentialCanary)
			}
			_, err := c.Issue(context.Background(), "dr-backups")
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), credentialCanary) {
				t.Fatal("partial issue not redacted/reconciled", err)
			}
			if len(p.revoked) != 1 || len(s.stored) != 0 {
				t.Fatal("partial issue cleanup/state invalid", p.revoked, s.stored)
			}
		})
	}
}

func TestManagedCredentialRotationRequiresObjectVerifierAndDurableActivator(t *testing.T) {
	for _, tc := range []struct {
		name          string
		missingAccess bool
	}{
		{"missing_access", true}, {"missing_activator", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, c := credentialControllerFixture()
			if tc.missingAccess {
				c.Access = nil
			} else {
				c.Activator = nil
			}
			previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
			_, err := c.Rotate(context.Background(), "dr-backups", previous)
			if !errors.Is(err, ErrCredentialVerificationFailed) || len(p.issued) != 0 || len(p.revoked) != 0 {
				t.Fatal("rotation without independent proof reached provider", err, p.issued, p.revoked)
			}
		})
	}
}

func TestManagedCredentialRotationAuthenticatesBeforeRetiringOldIdentity(t *testing.T) {
	p, _, c := credentialControllerFixture()
	access := c.Access.(*credentialAccessFixture)
	activator := c.Activator.(*credentialActivatorFixture)
	p.onRevoke = func(id string) {
		if id == "provider-old" && (access.calls != 2 || activator.calls != 1) {
			t.Errorf("old identity retired without authenticated cutover")
		}
	}
	previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
	_, err := c.Rotate(context.Background(), "dr-backups", previous)
	if err != nil || access.calls != 2 || activator.calls != 1 {
		t.Fatal("authenticated switch not verified", err, access.calls, activator.calls)
	}
}

func TestManagedCredentialRotationDoesNotRetireOnUncertainCutover(t *testing.T) {
	for _, tc := range []struct {
		name         string
		accessFailAt int
		activateFail bool
		want         error
	}{
		{"pre_cutover_probe", 1, false, ErrCredentialVerificationFailed},
		{"activation_uncertain", 0, true, ErrCredentialReconciliationRequired},
		{"post_cutover_probe", 2, false, ErrCredentialReconciliationRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, c := credentialControllerFixture()
			access := c.Access.(*credentialAccessFixture)
			if tc.accessFailAt > 0 {
				access.failOnCall = tc.accessFailAt
				access.err = errors.New("probe " + credentialCanary)
			}
			if tc.activateFail {
				c.Activator.(*credentialActivatorFixture).err = errors.New("switch " + credentialCanary)
			}
			previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
			_, err := c.Rotate(context.Background(), "dr-backups", previous)
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), credentialCanary) {
				t.Fatal("ambiguous cutover not rejected", err)
			}
			for _, id := range p.revoked {
				if id == previous.ProviderCredentialID {
					t.Fatal("old key revoked despite failed cutover")
				}
			}
		})
	}
}

func TestManagedCredentialRotationRejectsReusedProviderIdentity(t *testing.T) {
	p, _, c := credentialControllerFixture()
	previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-dr-backups", ExpiresAt: time.Now().Add(time.Hour)}
	_, err := c.Rotate(context.Background(), "dr-backups", previous)
	if !errors.Is(err, ErrCredentialReconciliationRequired) || len(p.revoked) != 0 {
		t.Fatal("reused provider identity was revoked", err, p.revoked)
	}
}

// Even an INVALID replacement with the same provider ID must never invoke
// cleanup against the currently active provider identity.
func TestManagedCredentialRotationDoesNotRevokeActiveIDOnInvalidReusedMaterial(t *testing.T) {
	p, s, c := credentialControllerFixture()
	p.materialOverride = func(m *IssuedCredential) {
		m.ProviderCredentialID = "provider-old"
		m.AccessKeyID = ""
		m.ExpiresAt = time.Now().Add(-time.Minute)
	}
	previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
	_, err := c.Rotate(context.Background(), "dr-backups", previous)
	if !errors.Is(err, ErrCredentialReconciliationRequired) || len(p.revoked) != 0 || len(s.stored) != 0 {
		t.Fatal("invalid reused provider identity revoked current writer", err, p.revoked, s.stored)
	}
}

// All these fixtures deliberately ignore context cancellation and can return
// successful calls after the owner has canceled. The controller must supply
// the admission gates; adapters alone cannot be trusted to honor ctx.
func TestManagedCredentialIssueCancellationGates(t *testing.T) {
	for _, stage := range []string{"entry", "after_issue", "after_custody_store", "after_custody_verify"} {
		t.Run(stage, func(t *testing.T) {
			p, custody, c := credentialControllerFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "entry":
				cancel()
			case "after_issue":
				p.onIssue = cancel
			case "after_custody_store":
				custody.onStore = cancel
			case "after_custody_verify":
				custody.onVerify = cancel
			}
			_, err := c.Issue(ctx, "dr-backups")
			if !errors.Is(err, ErrCredentialVerificationFailed) {
				t.Fatalf("canceled issue was accepted or improperly labeled: %v", err)
			}
			if stage == "entry" {
				if len(p.issued) != 0 || len(p.revoked) != 0 || len(custody.stored) != 0 {
					t.Fatal("pre-canceled request reached provider/custody")
				}
				return
			}
			if len(p.revoked) != 1 || p.revoked[0] != "provider-dr-backups" {
				t.Fatal("canceled issue left the new key active", p.revoked)
			}
			if stage != "after_issue" && len(custody.deleted) != 1 {
				t.Fatal("canceled stored credential not deleted")
			}
		})
	}
}

func TestManagedCredentialRotationCancellationGates(t *testing.T) {
	stages := []string{"entry", "after_issue", "after_custody_verify", "after_first_access", "during_activation", "after_second_access", "during_old_key_retirement"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			p, custody, c := credentialControllerFixture()
			access := c.Access.(*credentialAccessFixture)
			activator := c.Activator.(*credentialActivatorFixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "entry":
				cancel()
			case "after_issue":
				p.onIssue = cancel
			case "after_custody_verify":
				custody.onVerify = cancel
			case "after_first_access":
				access.onCall = func(n int) {
					if n == 1 {
						cancel()
					}
				}
			case "during_activation":
				activator.onActivate = cancel
			case "after_second_access":
				access.onCall = func(n int) {
					if n == 2 {
						cancel()
					}
				}
			case "during_old_key_retirement":
				p.onRevoke = func(id string) {
					if id == "provider-old" {
						cancel()
					}
				}
			}
			previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
			next, err := c.Rotate(ctx, "dr-backups", previous)
			if err == nil {
				t.Fatal("canceled rotation returned success")
			}
			if stage == "entry" {
				if len(p.issued) != 0 || len(p.revoked) != 0 || activator.calls != 0 {
					t.Fatal("pre-canceled rotation mutated provider")
				}
				if !errors.Is(err, ErrCredentialVerificationFailed) {
					t.Fatalf("bad entry error: %v", err)
				}
				return
			}
			for _, id := range p.revoked {
				if id == "provider-old" && stage != "during_old_key_retirement" {
					t.Fatal("canceled rotation retired previous key", stage, p.revoked)
				}
			}
			if stage == "during_activation" || stage == "after_second_access" || stage == "during_old_key_retirement" {
				if !errors.Is(err, ErrCredentialReconciliationRequired) || next.ID == "" {
					t.Fatalf("ambiguous cutover was not retained for reconciliation: %v %+v", err, next)
				}
				if len(custody.deleted) != 0 {
					t.Fatal("ambiguous cutover destroyed custody evidence")
				}
			} else {
				if !errors.Is(err, ErrCredentialVerificationFailed) {
					t.Fatalf("pre-activation cancellation not safely rejected: %v", err)
				}
				if len(p.revoked) != 1 || p.revoked[0] != "provider-dr-backups" {
					t.Fatal("pre-activation candidate not retired", p.revoked)
				}
				if stage == "after_first_access" && activator.calls != 0 {
					t.Fatal("activation was called after cancellation")
				}
			}
		})
	}
}

func TestManagedCredentialCancellationCleanupUncertainRequiresReconciliation(t *testing.T) {
	p, custody, c := credentialControllerFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	custody.onVerify = cancel
	p.revokeErr = errors.New("secret-bearing synthetic cleanup failure: " + credentialCanary)
	_, err := c.Issue(ctx, "dr-backups")
	if !errors.Is(err, ErrCredentialReconciliationRequired) || strings.Contains(err.Error(), credentialCanary) {
		t.Fatalf("uncertain canceled identity cleanup was silently accepted or leaked: %v", err)
	}
	if len(p.revoked) != 1 || len(custody.deleted) != 1 {
		t.Fatal("cancellation cleanup not attempted exactly once")
	}
}
