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
}

func (p *credentialProviderFixture) IssueCredential(_ context.Context, bucket string, ttl time.Duration) (IssuedCredential, error) {
	if p.issueErr != nil {
		return IssuedCredential{}, p.issueErr
	}
	id := "provider-" + bucket
	p.issued = append(p.issued, id)
	return IssuedCredential{ProviderCredentialID: id, AccessKeyID: "AKIA-SYNTHETIC", Secret: []byte(credentialCanary), ExpiresAt: time.Now().Add(ttl)}, nil
}
func (p *credentialProviderFixture) RevokeCredential(_ context.Context, id string) error {
	p.revoked = append(p.revoked, id)
	return p.revokeErr
}

type credentialCustodyFixture struct {
	storeErr, verifyErr, deleteErr error
	stored, verified, deleted      []CredentialReference
	secretObserved                 string
}

func (c *credentialCustodyFixture) StoreCredential(_ context.Context, bucket string, material IssuedCredential) (CredentialReference, error) {
	c.secretObserved = string(material.Secret)
	if c.storeErr != nil {
		return CredentialReference{}, c.storeErr
	}
	ref := CredentialReference{ID: "custody-" + bucket, ProviderCredentialID: material.ProviderCredentialID, ExpiresAt: material.ExpiresAt}
	c.stored = append(c.stored, ref)
	return ref, nil
}
func (c *credentialCustodyFixture) VerifyCredential(_ context.Context, ref CredentialReference) error {
	c.verified = append(c.verified, ref)
	return c.verifyErr
}
func (c *credentialCustodyFixture) DeleteCredential(_ context.Context, ref CredentialReference) error {
	c.deleted = append(c.deleted, ref)
	return c.deleteErr
}

func credentialControllerFixture() (*credentialProviderFixture, *credentialCustodyFixture, ManagedCredentialController) {
	p := &credentialProviderFixture{}
	s := &credentialCustodyFixture{}
	return p, s, ManagedCredentialController{Provider: p, Custody: s, TTL: time.Hour}
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
