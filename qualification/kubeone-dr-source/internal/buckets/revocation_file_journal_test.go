package buckets

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func revocationTestReference() CredentialReference {
	return CredentialReference{ID: "custody-original", ProviderCredentialID: "provider-original", ExpiresAt: time.Now().Add(time.Hour)}
}

// A successful fsync on tmpfs does not guarantee reboot persistence. This
// synthetic check and a real /dev/shm-mounted private directory both fail.
func TestRevocationJournalRejectsVolatileFilesystem(t *testing.T) {
	const (
		xfsMagic     uint64 = 0x58465342
		tmpfsMagic   uint64 = 0x01021994
		ramfsMagic   uint64 = 0x858458f6
		overlayMagic uint64 = 0x794c7630
		nfsMagic     uint64 = 0x6969
	)
	for _, tc := range []struct {
		name   string
		fs     uint64
		accept bool
	}{
		{"xfs_persistent", xfsMagic, true},
		{"ext4_persistent", uint64(unix.EXT4_SUPER_MAGIC), true},
		{"btrfs_persistent", uint64(unix.BTRFS_SUPER_MAGIC), true},
		{"tmpfs_volatile", tmpfsMagic, false},
		{"ramfs_volatile", ramfsMagic, false},
		{"overlay_unknown", overlayMagic, false},
		{"nfs_remote", nfsMagic, false},
		{"unknown", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialJournalPersistentFSType(tc.fs); got != tc.accept {
				t.Fatalf("filesystem allowlist: got %v, want %v", got, tc.accept)
			}
		})
	}
	// /dev/shm is Linux tmpfs on the native and hosted test runners.
	// An unavailable/unwritable mount is a test-environment limitation,
	// never evidence of qualified volatile storage.
	fs := unix.Statfs_t{}
	if err := unix.Statfs("/dev/shm", &fs); err != nil || uint64(fs.Type) != tmpfsMagic {
		t.Skip("real tmpfs /dev/shm unavailable; synthetic type test remains")
	}
	dir, err := os.MkdirTemp("/dev/shm", "ls-credential-volatile-test-")
	if err != nil {
		t.Skipf("cannot create disposable owned tmpfs test directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	journal := FileCredentialRevocationJournal{Directory: dir}
	ref := revocationTestReference()
	if _, err := journal.BeginRevocation(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("tmpfs journal admitted a revocation despite volatile backing", err)
	}
	if err := journal.CheckNotAdmitted(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("tmpfs journal permitted replay preflight", err)
	}
	items, err := os.ReadDir(dir)
	if err != nil || len(items) != 0 {
		t.Fatal("volatile rejected journal wrote files", err, items)
	}
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

func TestFileRevocationJournalPreflightBlocksPreviouslyAdmittedIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	journal := FileCredentialRevocationJournal{Directory: dir}
	ref := revocationTestReference()
	if err := journal.CheckNotAdmitted(context.Background(), ref); err != nil {
		t.Fatal("fresh credential blocked", err)
	}
	intent, err := journal.BeginRevocation(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	newProcess := FileCredentialRevocationJournal{Directory: dir}
	if err := newProcess.CheckNotAdmitted(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("existing intent allowed another rotation", err)
	}
	changed := ref
	changed.ProviderCredentialID = "provider-replaced"
	if err := newProcess.CheckNotAdmitted(context.Background(), changed); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("changed provider ID evaded custody admission", err)
	}
	if err := journal.CompleteRevocation(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := newProcess.CheckNotAdmitted(context.Background(), ref); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("completed revocation permitted replay", err)
	}
	fresh := ref
	fresh.ID = "distinct-custody-key"
	if err := newProcess.CheckNotAdmitted(context.Background(), fresh); err != nil {
		t.Fatal("unrelated custody identity blocked", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newProcess.CheckNotAdmitted(ctx, fresh); !errors.Is(err, ErrCredentialReconciliationRequired) {
		t.Fatal("canceled preflight succeeded", err)
	}
}

func TestManagedRotationRetirementJournalBlocksReplayAfterUncertainEffect(t *testing.T) {
	cases := []string{"provider_revoked_then_error", "custody_deleted_then_error", "canceled_after_provider", "completed_then_repeated"}
	for _, stage := range cases {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			p, custody, c := credentialControllerFixture()
			c.Revocations = FileCredentialRevocationJournal{Directory: dir}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "provider_revoked_then_error":
				p.revokeErr = errors.New("provider state changed but result unknown " + credentialCanary)
			case "custody_deleted_then_error":
				custody.deleteErr = errors.New("custody effect may have committed " + credentialCanary)
			case "canceled_after_provider":
				p.onRevoke = func(id string) {
					if id == "provider-old" {
						cancel()
					}
				}
			}
			previous := CredentialReference{ID: "custody-old", ProviderCredentialID: "provider-old", ExpiresAt: time.Now().Add(time.Hour)}
			next, err := c.Rotate(ctx, "dr-backups", previous)
			if stage == "completed_then_repeated" {
				if err != nil {
					t.Fatal("clean rotation did not complete", err)
				}
			} else if !errors.Is(err, ErrCredentialReconciliationRequired) || strings.Contains(err.Error(), credentialCanary) || next.ID == "" {
				t.Fatal("ambiguous retirement was not retained and redacted", err, next)
			}
			if len(p.issued) != 1 || len(p.revoked) != 1 || p.revoked[0] != "provider-old" {
				t.Fatal("unexpected provider mutation before replay", p.issued, p.revoked)
			}
			// A new journal instance emulates a restart: it must block BEFORE
			// issuing another candidate or reaching the provider for old key.
			c.Revocations = FileCredentialRevocationJournal{Directory: dir}
			beforeActivation := c.Activator.(*credentialActivatorFixture).calls
			_, err = c.Rotate(context.Background(), "dr-backups", previous)
			if !errors.Is(err, ErrCredentialReconciliationRequired) || len(p.issued) != 1 || len(p.revoked) != 1 || c.Activator.(*credentialActivatorFixture).calls != beforeActivation {
				t.Fatal("repeated rotation changed provider or active reference", err, p.issued, p.revoked)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if stage == "completed_then_repeated" {
				want = 2
			}
			if len(entries) != want {
				t.Fatal("durable retirement evidence missing", len(entries), want)
			}
		})
	}
}
