//go:build linux

package lifecycle

import (
	"encoding/json"
	"fmt"
	"github.com/layersentry/layersentry-platform/internal/kubeone/workspaceproof"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Synthetic protocol data is used only for state-machine unit tests. It is not
// a native observation and is never emitted as qualification evidence.
func workspaceSuccessorReceiptFixture(t *testing.T) (*workspaceSuccessor, workspaceSuccessorReceipt) {
	t.Helper()
	now := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	sha := strings.Repeat("a", 64)
	expected := workspaceproof.Expected{ProfileSHA256: sha, SourceCommit: strings.Repeat("b", 40), ExecutableSHA256: sha, HostUUID: "0b5e029f-7b48-413a-b817-7654aae7e350", BootID: "21641f4a-b458-4ad9-9f6c-51e76b84743b", ManifestSHA256: sha, JobSHA256: sha, PrivateKeySHA256: sha, NativeAdmissionSHA256: sha}
	for i := range expected.Guests {
		expected.Guests[i] = workspaceproof.GuestIdentity{NativeID: 6 + i, DomainUUID: fmt.Sprintf("40724bd9-32ac-4671-b10d-%012d", i+1), GuestBootID: expected.BootID, OwnerSHA256: sha, HostKeySHA256: fmt.Sprintf("%064x", i+1), HypervisorUUID: expected.HostUUID, HypervisorBootID: expected.BootID}
	}
	request, e := workspaceproof.NewRequest(sha, workspaceproof.Prepublication)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(request)
	response := workspaceproof.Response{Version: 1, RequestSHA256: workspaceproof.Digest(raw), Nonce: request.Nonce, ProfileSHA256: sha, SourceCommit: expected.SourceCommit, ExecutableSHA256: sha, HostUUID: expected.HostUUID, BootID: expected.BootID, ManifestSHA256: sha, JobSHA256: sha, PrivateKeySHA256: sha, NativeAdmissionSHA256: sha, NativeProofSHA256: sha, NativeStartedAt: now.Add(-time.Second), NativeCheckedAt: now, WorkspaceStartedAt: now.Add(-time.Second), WorkspaceCheckedAt: now}
	for i, g := range expected.Guests {
		response.Guests[i] = workspaceproof.GuestObservation{Identity: g, StartedAt: now.Add(-time.Second), CheckedAt: now, EvidenceSHA256: sha}
	}
	s := &workspaceSuccessor{admission: workspaceSuccessorAdmission{ID: strings.Repeat("c", 32), Expected: expected, Manifest: workspaceproof.ManifestBinding{OriginalSHA256: sha}}, raw: []byte("unit-test-private-admission"), desired: []byte("unit-test-desired")}
	r := workspaceSuccessorReceipt{Version: 1, AdmissionSHA256: workspaceproof.Digest(s.raw), IntentID: s.admission.ID, OriginalSHA256: sha, DesiredSHA256: workspaceproof.Digest(s.desired), OriginalJobSHA256: sha, State: "PREPARED", Dispatches: []workspaceSuccessorDispatch{}, OriginalDevice: 1, OriginalInode: 2, PreparedAt: now, UpdatedAt: now, Request: request, Observation: response, Scope: workspaceSuccessorScope}
	if s.validateReceipt(r) != nil {
		t.Fatal("fixture")
	}
	return s, r
}

func TestWorkspaceSuccessorArchiveAheadRejectsForkOrLostHistory(t *testing.T) {
	_, initial := workspaceSuccessorReceiptFixture(t)
	pending := initial
	pending.State, pending.Attempt = "PUBLISHING", 1
	pending.UpdatedAt = initial.UpdatedAt.Add(time.Second)
	pending.Dispatches = []workspaceSuccessorDispatch{{initial.Request, initial.Observation, pending.UpdatedAt}}
	next, e := workspaceSuccessorArchiveAhead(initial, []workspaceSuccessorReceipt{pending, initial})
	if e != nil || next == nil || next.Attempt != 1 || !next.UpdatedAt.Equal(pending.UpdatedAt) {
		t.Fatal("durable proposal not retained exactly", e)
	}
	reconciled := pending
	reconciled.State = "ORIGINAL_RECONCILED"
	reconciled.UpdatedAt = pending.UpdatedAt.Add(time.Second)
	for _, tc := range []struct {
		name string
		rows []workspaceSuccessorReceipt
	}{
		{"missing-current", []workspaceSuccessorReceipt{pending}},
		{"multiple-ahead", []workspaceSuccessorReceipt{initial, pending, reconciled}},
		{"duplicate", []workspaceSuccessorReceipt{initial, pending, pending}},
		{"branch", []workspaceSuccessorReceipt{initial, pending, func() workspaceSuccessorReceipt { r := pending; r.UpdatedAt = r.UpdatedAt.Add(time.Second); return r }()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := workspaceSuccessorArchiveAhead(initial, tc.rows); e == nil {
				t.Fatal("ambiguous archive adopted")
			}
		})
	}
	if next, e := workspaceSuccessorArchiveAhead(reconciled, []workspaceSuccessorReceipt{initial, pending, reconciled}); e != nil || next != nil {
		t.Fatal("complete immutable history rejected", e)
	}
}

// Exercise actual fsynced owner files under the real oneadmin credential, not
// a relaxed filesystem test seam. The archive-first crash is injected by
// stopping after the existing exclusive archive writer, before journal rename.
func TestWorkspaceSuccessorArchiveAheadFilesystemCrash(t *testing.T) {
	if root := os.Getenv("LS_TEST_SUCCESSOR_ARCHIVE_CHILD"); root != "" {
		s, initial := workspaceSuccessorReceiptFixture(t)
		d, e := os.Open(root)
		if e != nil {
			t.Fatal(e)
		}
		defer d.Close()
		if e = s.saveReceipt(d, initial, false); e != nil {
			t.Fatal(e)
		}
		original, e := os.ReadFile(filepath.Join(root, workspaceSuccessorJournal))
		if e != nil {
			t.Fatal(e)
		}
		pending := initial
		pending.State, pending.Attempt = "PUBLISHING", 1
		pending.UpdatedAt = initial.UpdatedAt.Add(time.Second)
		pending.Dispatches = []workspaceSuccessorDispatch{{initial.Request, initial.Observation, pending.UpdatedAt}}
		raw, _ := json.Marshal(pending)
		name := workspaceSuccessorArchiveName(raw)
		if e = writeWorkspaceSuccessorFile(d, name, raw, false); e != nil {
			t.Fatal(e)
		}
		if e = writeWorkspaceSuccessorFile(d, ".layersentry-workspace-successor-attempt-1.yaml", s.desired, false); e != nil {
			t.Fatal(e)
		}
		current, e := s.readReceipt(d)
		if e != nil || current == nil || current.State != "PREPARED" {
			t.Fatal("current changed before rename", e)
		}
		ahead, e := s.archivedAdvance(d, *current)
		if e != nil || ahead == nil {
			t.Fatal("lost durable proposal", e)
		}
		before, _ := os.ReadFile(filepath.Join(root, workspaceSuccessorJournal))
		if string(before) != string(original) {
			t.Fatal("read-only classification mutated current")
		}
		if e = s.saveReceipt(d, *ahead, true); e != nil {
			t.Fatal(e)
		}
		after, _ := os.ReadFile(filepath.Join(root, workspaceSuccessorJournal))
		preserved, _ := os.ReadFile(filepath.Join(root, name))
		if string(after) != string(raw) || string(preserved) != string(raw) {
			t.Fatal("proposal rebound or restamped")
		}
		if _, e = os.Stat(filepath.Join(root, ".layersentry-workspace-successor-attempt-1.yaml")); e != nil {
			t.Fatal("orphan proposal erased")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires isolated oneadmin child credentials")
	}
	root, e := os.MkdirTemp("", "workspace-successor-crash-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	if e = os.Chown(root, workspaceproof.CallerID, workspaceproof.CallerID); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(root, "test-owner")
	raw, e := os.ReadFile(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(binary, raw, 0755); e != nil {
		t.Fatal(e)
	}
	// The child runs as the scoped unprivileged owner; umask must not
	// remove its execute permission from this test-only binary.
	if e = os.Chmod(binary, 0755); e != nil {
		t.Fatal(e)
	}
	c := exec.Command(binary, "-test.run=^TestWorkspaceSuccessorArchiveAheadFilesystemCrash$", "-test.v")
	c.Env = append(os.Environ(), "LS_TEST_SUCCESSOR_ARCHIVE_CHILD="+root)
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: workspaceproof.CallerID, Gid: workspaceproof.CallerID, Groups: []uint32{}}}
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("child: %v\n%s", e, out)
	}
}
func TestWorkspaceSuccessorReceiptRejectsReboundAndFalseDispatch(t *testing.T) {
	s, r := workspaceSuccessorReceiptFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*workspaceSuccessorReceipt)
	}{
		{"source", func(r *workspaceSuccessorReceipt) { r.AdmissionSHA256 = strings.Repeat("f", 64) }},
		{"job", func(r *workspaceSuccessorReceipt) { r.OriginalJobSHA256 = strings.Repeat("f", 64) }},
		{"owner", func(r *workspaceSuccessorReceipt) {
			r.Observation.Guests[0].Identity.DomainUUID = r.Observation.Guests[1].Identity.DomainUUID
		}},
		{"stale-nested-native", func(r *workspaceSuccessorReceipt) { r.Observation.NativeStartedAt = r.UpdatedAt.Add(-21 * time.Second) }},
		{"restamped-prepared", func(r *workspaceSuccessorReceipt) { r.UpdatedAt = r.UpdatedAt.Add(time.Second) }},
		{"dispatch-without-intent", func(r *workspaceSuccessorReceipt) { r.State = "PUBLISHING" }},
		{"verified-without-dispatch", func(r *workspaceSuccessorReceipt) { r.State = "VERIFIED" }},
		{"nil-history", func(r *workspaceSuccessorReceipt) { r.Dispatches = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := r
			tc.change(&x)
			if s.validateReceipt(x) == nil {
				t.Fatal("accepted")
			}
		})
	}
	publishing := r
	publishing.State = "PUBLISHING"
	publishing.Attempt = 1
	publishing.Dispatches = []workspaceSuccessorDispatch{{r.Request, r.Observation, r.UpdatedAt}}
	if s.validateReceipt(publishing) != nil || validateWorkspaceSuccessorAdvance(r, publishing) != nil {
		t.Fatal("exact genuine dispatch")
	}
	altered := publishing
	altered.Dispatches = append([]workspaceSuccessorDispatch{}, publishing.Dispatches...)
	altered.Dispatches[0].Request.Nonce = strings.Repeat("1", 64)
	if s.validateReceipt(altered) == nil {
		t.Fatal("altered dispatch evidence")
	}
}
func TestWorkspaceSuccessorTransitionsRequireSeparateReconciliation(t *testing.T) {
	_, ready := workspaceSuccessorReceiptFixture(t)
	dispatched := ready
	dispatched.State = "PUBLISHING"
	dispatched.Attempt = 1
	dispatched.Dispatches = []workspaceSuccessorDispatch{{ready.Request, ready.Observation, ready.UpdatedAt}}
	reconciled := dispatched
	reconciled.State = "ORIGINAL_RECONCILED"
	if validateWorkspaceSuccessorAdvance(dispatched, reconciled) != nil {
		t.Fatal("read-only original reconciliation")
	}
	again := dispatched
	again.Attempt = 2
	again.Dispatches = append(append([]workspaceSuccessorDispatch{}, dispatched.Dispatches...), dispatched.Dispatches[0])
	if validateWorkspaceSuccessorAdvance(dispatched, again) == nil {
		t.Fatal("direct uncertain redispatch")
	}
	if validateWorkspaceSuccessorAdvance(reconciled, again) != nil {
		t.Fatal("explicit new action after reconciliation")
	}
	bad := reconciled
	bad.OriginalInode++
	if validateWorkspaceSuccessorAdvance(dispatched, bad) == nil {
		t.Fatal("new original inode adopted")
	}
	bad = reconciled
	bad.Dispatches = nil
	bad.Attempt = 0
	if validateWorkspaceSuccessorAdvance(dispatched, bad) == nil {
		t.Fatal("dispatch history erased")
	}
	bad = reconciled
	bad.State = "PREPARED"
	if validateWorkspaceSuccessorAdvance(dispatched, bad) == nil {
		t.Fatal("reset intent")
	}
}
