package buckets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FileCredentialRevocationJournal is a local, service-private durable
// admission ledger for credential revocation. It never carries key material.
// The directory must be a pre-existing private real directory owned by the
// service; a missing/unsafe filesystem or any uncertain write fails closed.
// This is not an independent HA journal and is not proof of object storage.
type FileCredentialRevocationJournal struct {
	Directory string
}

type fileRevocationRecord struct {
	JournalID  string              `json:"journal_id"`
	Reference  CredentialReference `json:"reference"`
	State      string              `json:"state"`
	RecordedAt time.Time           `json:"recorded_at"`
}

func (j FileCredentialRevocationJournal) openPrivateDir() (*os.File, error) {
	if j.Directory == "" || !filepath.IsAbs(j.Directory) || filepath.Clean(j.Directory) != j.Directory {
		return nil, ErrCredentialReconciliationRequired
	}
	original, err := os.Lstat(j.Directory)
	if err != nil || !original.IsDir() || original.Mode().Perm() != 0700 {
		return nil, ErrCredentialReconciliationRequired
	}
	native, ok := original.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		return nil, ErrCredentialReconciliationRequired
	}
	if resolved, err := filepath.EvalSymlinks(j.Directory); err != nil || resolved != j.Directory {
		return nil, ErrCredentialReconciliationRequired
	}
	dir, err := os.Open(j.Directory)
	if err != nil {
		return nil, ErrCredentialReconciliationRequired
	}
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(original, opened) || opened.Mode().Perm() != 0700 {
		dir.Close()
		return nil, ErrCredentialReconciliationRequired
	}
	// Durability is a positive assertion, not "anything other than NFS".
	// tmpfs/ramfs lose fsynced records after reboot; overlay/FUSE/remote
	// filesystems may not provide the expected local persistent custody.
	// Only explicitly reviewed local disk filesystems qualify here.
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &filesystem); err != nil ||
		!credentialJournalPersistentFSType(uint64(filesystem.Type)) {
		dir.Close()
		return nil, ErrCredentialReconciliationRequired
	}
	return dir, nil
}

// This allowlist is deliberately narrow. Even an allowed filesystem is not
// evidence of survival across power loss, so real reboot/replay admission and
// journal ownership tests remain required before production use.
func credentialJournalPersistentFSType(kind uint64) bool {
	const xfsSuperMagic uint64 = 0x58465342 // Linux XFS_SUPER_MAGIC
	switch kind {
	case xfsSuperMagic, uint64(unix.EXT4_SUPER_MAGIC), uint64(unix.BTRFS_SUPER_MAGIC):
		return true
	default:
		return false
	}
}

func sameCredentialReference(a, b CredentialReference) bool {
	return a.ID == b.ID && a.ProviderCredentialID == b.ProviderCredentialID && a.ExpiresAt.Equal(b.ExpiresAt)
}

func revokeIdentity(ref CredentialReference) (string, error) {
	if len(ref.ID) == 0 || len(ref.ID) > 128 ||
		len(ref.ProviderCredentialID) == 0 || len(ref.ProviderCredentialID) > 128 ||
		strings.ContainsAny(ref.ID+ref.ProviderCredentialID, "\x00\r\n") || ref.ExpiresAt.IsZero() {
		return "", ErrCredentialVerificationFailed
	}
	// Deliberately bind the journal key to the CUSTODY ID only. A changed
	// provider ID or expiry cannot admit a second revocation for that ID.
	digest := sha256.Sum256([]byte("managed-revocation-v1:" + ref.ID))
	return hex.EncodeToString(digest[:]), nil
}

func writeRevocationRecord(dir *os.File, filename string, record fileRevocationRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return ErrCredentialReconciliationRequired
	}
	raw = append(raw, '\n')
	fd, err := unix.Openat(int(dir.Fd()), filename, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrCredentialReconciliationRequired
	}
	f := os.NewFile(uintptr(fd), filename)
	count, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	dirSyncErr := dir.Sync()
	if writeErr != nil || count != len(raw) || syncErr != nil || closeErr != nil || dirSyncErr != nil {
		// The file may already exist or be partially durable. Leave it in
		// place for explicit reconciliation; never retry the provider effect.
		return ErrCredentialReconciliationRequired
	}
	return nil
}

func readRevocationRecord(dir *os.File, filename string) (fileRevocationRecord, error) {
	fd, err := unix.Openat(int(dir.Fd()), filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fileRevocationRecord{}, ErrCredentialReconciliationRequired
	}
	f := os.NewFile(uintptr(fd), filename)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() == 0 || info.Size() > 4096 {
		return fileRevocationRecord{}, ErrCredentialReconciliationRequired
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return fileRevocationRecord{}, ErrCredentialReconciliationRequired
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	var record fileRevocationRecord
	if decoder.Decode(&record) != nil {
		return fileRevocationRecord{}, ErrCredentialReconciliationRequired
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return fileRevocationRecord{}, ErrCredentialReconciliationRequired
	}
	return record, nil
}

// CheckNotAdmitted proves the absence of any prior single-use journal entry
// for this exact custody identity before rotation may issue a replacement.
// A malformed/permission-denied/symlinked entry is ambiguous and fails closed.
// It never clears or rewrites a previously recorded intent.
func (j FileCredentialRevocationJournal) CheckNotAdmitted(ctx context.Context, ref CredentialReference) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	key, err := revokeIdentity(ref)
	if err != nil {
		return ErrCredentialReconciliationRequired
	}
	dir, err := j.openPrivateDir()
	if err != nil {
		return ErrCredentialReconciliationRequired
	}
	defer dir.Close()
	for _, extension := range []string{".intent", ".complete"} {
		fd, openErr := unix.Openat(int(dir.Fd()), key+extension, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == nil {
			unix.Close(fd)
			return ErrCredentialReconciliationRequired
		}
		if !errors.Is(openErr, unix.ENOENT) {
			return ErrCredentialReconciliationRequired
		}
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	return nil
}

// BeginRevocation writes and fsyncs a unique PENDING record before any
// provider effect. A second call for the same custody ID fails closed even
// after completion; an operator must independently reconcile the ledger.
func (j FileCredentialRevocationJournal) BeginRevocation(ctx context.Context, ref CredentialReference) (CredentialRevocationIntent, error) {
	if ctx == nil || ctx.Err() != nil {
		return CredentialRevocationIntent{}, ErrCredentialVerificationFailed
	}
	key, err := revokeIdentity(ref)
	if err != nil {
		return CredentialRevocationIntent{}, err
	}
	dir, err := j.openPrivateDir()
	if err != nil {
		return CredentialRevocationIntent{}, err
	}
	defer dir.Close()
	intent := CredentialRevocationIntent{JournalID: key, Reference: ref}
	record := fileRevocationRecord{JournalID: key, Reference: ref, State: "UNKNOWN", RecordedAt: time.Now().UTC()}
	if err := writeRevocationRecord(dir, key+".intent", record); err != nil {
		return CredentialRevocationIntent{}, ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return CredentialRevocationIntent{}, ErrCredentialReconciliationRequired
	}
	return intent, nil
}

// CompleteRevocation records a distinct fsynced completion receipt ONLY after
// provider revocation and custody deletion are both confirmed by the owner.
func (j FileCredentialRevocationJournal) CompleteRevocation(ctx context.Context, intent CredentialRevocationIntent) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	key, err := revokeIdentity(intent.Reference)
	if err != nil || key != intent.JournalID {
		return ErrCredentialReconciliationRequired
	}
	dir, err := j.openPrivateDir()
	if err != nil {
		return err
	}
	defer dir.Close()
	pending, err := readRevocationRecord(dir, key+".intent")
	if err != nil || pending.JournalID != key || !sameCredentialReference(pending.Reference, intent.Reference) || pending.State != "UNKNOWN" || pending.RecordedAt.IsZero() {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	done := fileRevocationRecord{JournalID: key, Reference: intent.Reference, State: "COMPLETE", RecordedAt: time.Now().UTC()}
	if err := writeRevocationRecord(dir, key+".complete", done); err != nil {
		return ErrCredentialReconciliationRequired
	}
	if ctx.Err() != nil {
		return ErrCredentialReconciliationRequired
	}
	return nil
}
