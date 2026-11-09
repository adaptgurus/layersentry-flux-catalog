package buckets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func revocationTestReference() CredentialReference {
	return CredentialReference{ID: "custody-original", ProviderCredentialID: "provider-original", ExpiresAt: time.Now().Add(time.Hour)}
}

func TestFileRevocationJournalDurableIntentAndCompletion(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j := FileCredentialRevocationJournal{Directory: dir}
	ref := revocationTestReference()
	intent, err := j.BeginRevocation(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	// A different journal instance (simulating process restart) must observe
	// the existing intent and refuse to authorize a second provider effect.
	restarted := FileCredentialRevocationJournal{Directory: dir}
	if _, err := restarted.BeginRevocation(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("duplicate intent admitted", err)
	}
	changed := ref
	changed.ProviderCredentialID = "different-provider"
	if _, err := restarted.BeginRevocation(context.Background(), changed); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("same custody ID with a different provider admitted", err)
	}
	if err := restarted.CompleteRevocation(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.BeginRevocation(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("completed ID replayed", err)
	}
	if err := restarted.CompleteRevocation(context.Background(), intent); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("duplicate completion silently accepted", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("expected intent+completion only: %v %v", files, err)
	}
	for _, f := range files {
		p := filepath.Join(dir, f.Name())
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("revocation evidence not private", f.Name(), err)
		}
		raw, err := os.ReadFile(p)
		if err != nil || strings.Contains(string(raw), credentialCanary) {
			t.Fatal("secret leaked into revocation record")
		}
	}
}

func TestFileRevocationJournalFailClosedOnUnsafePathOrCancel(t *testing.T) {
	good := t.TempDir()
	if err := os.Chmod(good, 0700); err != nil {
		t.Fatal(err)
	}
	bad := t.TempDir()
	if err := os.Chmod(bad, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	ref := revocationTestReference()
	for _, tc := range []struct{ name, path string }{
		{"world_exposed_dir", bad},
		{"symlink_dir", link},
		{"relative_dir", "relative"},
		{"missing_dir", filepath.Join(t.TempDir(), "missing")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := FileCredentialRevocationJournal{Directory: tc.path}
			if _, err := j.BeginRevocation(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
				t.Fatal("unsafe journal directory accepted", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j := FileCredentialRevocationJournal{Directory: good}
	if _, err := j.BeginRevocation(ctx, ref); !errors.Is(err, ErrCredentialVerificationFailed) {
		t.Fatal("pre-canceled journal write accepted", err)
	}
	entries, _ := os.ReadDir(good)
	if len(entries) != 0 {
		t.Fatal("pre-canceled write left a file")
	}
}

func TestFileRevocationJournalInvalidOrModifiedEvidenceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j := FileCredentialRevocationJournal{Directory: dir}
	ref := revocationTestReference()
	intent, err := j.BeginRevocation(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	other := intent
	other.Reference.ProviderCredentialID = "wrong-provider"
	if err := j.CompleteRevocation(context.Background(), other); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("mismatched journal identity accepted", err)
	}
	other = intent
	other.JournalID = "wrong-digest"
	if err := j.CompleteRevocation(context.Background(), other); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("wrong journal ID accepted", err)
	}
	pending := filepath.Join(dir, intent.JournalID+".intent")
	if err := os.Chmod(pending, 0644); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteRevocation(context.Background(), intent); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("loosened journal permissions accepted", err)
	}
	if err := os.Chmod(pending, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", pending); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteRevocation(context.Background(), intent); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("symlinked journal accepted", err)
	}
}

func TestManagedRevokeWithRealFileJournalAvoidsBlindRetry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p, s, c := credentialControllerFixture()
	c.Revocations = FileCredentialRevocationJournal{Directory: dir}
	ref := revocationTestReference()
	p.revokeErr = errors.New("provider may have revoked " + credentialCanary)
	if err := c.Revoke(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("ambiguous provider returned non-reconciliation error", err)
	}
	if len(p.revoked) != 1 || len(s.deleted) != 0 {
		t.Fatal("provider outcome misrepresented")
	}
	p.revokeErr = nil
	if err := c.Revoke(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) || len(p.revoked) != 1 {
		t.Fatal("second controller call replayed provider mutation", err)
	}
}
