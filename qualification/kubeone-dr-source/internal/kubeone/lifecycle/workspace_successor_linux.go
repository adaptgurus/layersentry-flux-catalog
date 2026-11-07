//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/layersentry/layersentry-platform/internal/kubeone/workspaceproof"
	"golang.org/x/sys/unix"
)

const workspaceSuccessorAdmissionPath = "/etc/layersentry/kubeone-workspace-successor/admission.json"
const workspaceSuccessorJournal = ".layersentry-workspace-successor.json"
const workspaceSuccessorScope = "NATIVE_V1BETA2_ORIGINAL_DC_SSH_BASTION_SUCCESSOR_NOT_PROVISION"

// This is independently published root admission, not an HTTP request or a
// producer assertion. The original job and full-wire bindings stay immutable.
type workspaceSuccessorAdmission struct {
	Version          int                               `json:"version"`
	ID               string                            `json:"id"`
	OriginalManifest []byte                            `json:"original_manifest"`
	Manifest         workspaceproof.ManifestBinding    `json:"manifest"`
	OriginalJobID    string                            `json:"original_job_id"`
	Expected         workspaceproof.Expected           `json:"expected"`
	Server           workspaceproof.ExecutablePeer     `json:"server"`
	Deployment       workspaceproof.DeploymentIdentity `json:"deployment"`
}

func (a workspaceSuccessorAdmission) validate() ([]byte, error) {
	id, e := hex.DecodeString(a.ID)
	job, je := hex.DecodeString(a.OriginalJobID)
	if e != nil || len(id) != 16 || hex.EncodeToString(id) != a.ID || je != nil || len(job) != 16 || hex.EncodeToString(job) != a.OriginalJobID || a.Version != 1 || a.Expected.Validate() != nil || a.Expected.ManifestSHA256 != a.Manifest.OriginalSHA256 || workspaceproof.Digest(a.OriginalManifest) != a.Manifest.OriginalSHA256 || a.Server.UID != 0 || a.Server.GID != 0 || a.Server.Path != workspaceproof.ObserverExecutable || a.Server.SHA256 != a.Expected.ExecutableSHA256 || a.Deployment.SourceCommit != a.Expected.SourceCommit || a.Deployment.HostUUID != a.Expected.HostUUID || a.Deployment.BootID != a.Expected.BootID {
		return nil, workspaceproof.ErrAdmission
	}
	return workspaceproof.TransformManifest(a.OriginalManifest, a.Manifest)
}
func readWorkspaceSuccessorAdmission() ([]byte, error) {
	d, e := workspaceproof.OpenDirectory(filepath.Dir(workspaceSuccessorAdmissionPath), 0, workspaceproof.CallerID, 0750)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	raw, e := workspaceproof.ReadAtDirectory(d, filepath.Base(workspaceSuccessorAdmissionPath), 0, workspaceproof.CallerID, 0640, workspaceproof.MaxProtocolBytes)
	if e != nil || workspaceproof.DirectoryStillNamed(d, filepath.Dir(workspaceSuccessorAdmissionPath), 0, workspaceproof.CallerID, 0750) != nil {
		return nil, workspaceproof.ErrAdmission
	}
	return raw, nil
}

type workspaceSuccessor struct {
	admission    workspaceSuccessorAdmission
	raw, desired []byte
	client       workspaceproof.Client
}

// There is no injectable production observer or boolean readiness switch.
// The concrete authenticated local native provider is mandatory.
func loadWorkspaceSuccessor() (*workspaceSuccessor, error) {
	raw, e := readWorkspaceSuccessorAdmission()
	if e != nil {
		return nil, e
	}
	var a workspaceSuccessorAdmission
	if workspaceproof.DecodeCanonical(raw, &a) != nil {
		return nil, workspaceproof.ErrAdmission
	}
	desired, e := a.validate()
	if e != nil {
		return nil, e
	}
	return &workspaceSuccessor{a, raw, desired, workspaceproof.Client{Server: a.Server, Deployment: a.Deployment}}, nil
}
func (s *workspaceSuccessor) checkAdmission() error {
	if s == nil {
		return workspaceproof.ErrAdmission
	}
	raw, e := readWorkspaceSuccessorAdmission()
	if e != nil || !bytes.Equal(raw, s.raw) {
		return workspaceproof.ErrAdmission
	}
	return nil
}
func (s *workspaceSuccessor) observe(ctx context.Context, purpose string) (workspaceproof.Request, workspaceproof.Response, error) {
	if s == nil || s.checkAdmission() != nil {
		return workspaceproof.Request{}, workspaceproof.Response{}, workspaceproof.ErrAdmission
	}
	r, e := workspaceproof.NewRequest(s.admission.Expected.ProfileSHA256, purpose)
	if e != nil {
		return r, workspaceproof.Response{}, e
	}
	expected := s.admission.Expected
	if purpose == workspaceproof.Postpublication {
		expected.ManifestSHA256 = workspaceproof.Digest(s.desired)
	}
	response, e := s.client.Observe(ctx, r, expected)
	return r, response, e
}
func (s *workspaceSuccessor) fresh(r workspaceproof.Request, p workspaceproof.Response) error {
	if s == nil {
		return workspaceproof.ErrAdmission
	}
	expected := s.admission.Expected
	if r.Purpose == workspaceproof.Postpublication {
		expected.ManifestSHA256 = workspaceproof.Digest(s.desired)
	}
	return workspaceproof.ValidateResponse(r, p, expected, time.Now().UTC())
}

// A receipt records native publication attempts before the atomic replacement.
// PUBLISHING never becomes redispatch authority. Explicit read-only reconcile
// must prove exact original inode or desired bytes before a separate continuation.
type workspaceSuccessorDispatch struct {
	Request      workspaceproof.Request  `json:"request"`
	Observation  workspaceproof.Response `json:"observation"`
	DispatchedAt time.Time               `json:"dispatched_at"`
}

type workspaceSuccessorReceipt struct {
	Version           int                          `json:"version"`
	AdmissionSHA256   string                       `json:"admission_sha256"`
	IntentID          string                       `json:"intent_id"`
	OriginalSHA256    string                       `json:"original_sha256"`
	DesiredSHA256     string                       `json:"desired_sha256"`
	OriginalJobSHA256 string                       `json:"original_job_sha256"`
	State             string                       `json:"state"`
	Attempt           int                          `json:"attempt"`
	Dispatches        []workspaceSuccessorDispatch `json:"dispatches"`
	OriginalDevice    uint64                       `json:"original_device"`
	OriginalInode     uint64                       `json:"original_inode"`
	PreparedAt        time.Time                    `json:"prepared_at"`
	UpdatedAt         time.Time                    `json:"updated_at"`
	Request           workspaceproof.Request       `json:"request"`
	Observation       workspaceproof.Response      `json:"observation"`
	Scope             string                       `json:"scope"`
}

func (s *workspaceSuccessor) validateReceipt(r workspaceSuccessorReceipt) error {
	if s == nil || r.Version != 1 || r.AdmissionSHA256 != workspaceproof.Digest(s.raw) || r.IntentID != s.admission.ID || r.OriginalSHA256 != s.admission.Manifest.OriginalSHA256 || r.DesiredSHA256 != workspaceproof.Digest(s.desired) || r.OriginalJobSHA256 != s.admission.Expected.JobSHA256 || r.OriginalDevice == 0 || r.OriginalInode == 0 || r.PreparedAt.IsZero() || r.UpdatedAt.Before(r.PreparedAt) || r.Attempt < 0 || r.Attempt > 4 || r.Scope != workspaceSuccessorScope {
		return workspaceproof.ErrAdmission
	}
	if r.Dispatches == nil || len(r.Dispatches) != r.Attempt {
		return workspaceproof.ErrAdmission
	}
	last := r.PreparedAt
	for _, dispatch := range r.Dispatches {
		if dispatch.Request.Purpose != workspaceproof.Prepublication || dispatch.DispatchedAt.Before(last) || dispatch.DispatchedAt.After(r.UpdatedAt) || workspaceproof.ValidateResponse(dispatch.Request, dispatch.Observation, s.admission.Expected, dispatch.DispatchedAt) != nil {
			return workspaceproof.ErrAdmission
		}
		last = dispatch.DispatchedAt
	}
	expected := s.admission.Expected
	switch r.State {
	case "PREPARED", "PUBLISHING", "ORIGINAL_RECONCILED":
		if r.Request.Purpose != workspaceproof.Prepublication {
			return workspaceproof.ErrAdmission
		}
		if r.State == "PREPARED" && (r.Attempt != 0 || !r.PreparedAt.Equal(r.UpdatedAt)) {
			return workspaceproof.ErrAdmission
		}
		if r.State == "PUBLISHING" && (r.Attempt == 0 || !r.Dispatches[r.Attempt-1].DispatchedAt.Equal(r.UpdatedAt) || !reflect.DeepEqual(r.Dispatches[r.Attempt-1].Request, r.Request) || !reflect.DeepEqual(r.Dispatches[r.Attempt-1].Observation, r.Observation)) {
			return workspaceproof.ErrAdmission
		}
	case "VERIFIED":
		if r.Request.Purpose != workspaceproof.Postpublication || r.Attempt == 0 {
			return workspaceproof.ErrAdmission
		}
		expected.ManifestSHA256 = workspaceproof.Digest(s.desired)
	default:
		return workspaceproof.ErrAdmission
	}
	// A historical receipt is checked against its actual publication time, never
	// renewed to now. Current effects require a separately fresh observation.
	if workspaceproof.ValidateResponse(r.Request, r.Observation, expected, r.UpdatedAt) != nil {
		return workspaceproof.ErrAdmission
	}
	return nil
}

// All writes are below the held workspace directory and existing operation
// flock. Immutable preservation accepts only identical bytes after ambiguity.
// Atomic replacement tempfiles are intentionally retained on failure; a caller
// must reconcile authoritative state, never clean up or retry an uncertain write.
func writeWorkspaceSuccessorFile(d *os.File, name string, raw []byte, replace bool) error {
	if d == nil || os.Geteuid() != workspaceproof.CallerID || os.Getegid() != workspaceproof.CallerID || name == "" || filepath.Base(name) != name || name == "." || name == ".." || len(raw) == 0 || len(raw) > workspaceproof.MaxManifestBytes*2 {
		return workspaceproof.ErrAdmission
	}
	var directory unix.Stat_t
	if unix.Fstat(int(d.Fd()), &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != workspaceproof.CallerID || directory.Gid != workspaceproof.CallerID || directory.Mode&07777 != 0700 {
		return workspaceproof.ErrAdmission
	}
	target := name
	if replace {
		nonce := make([]byte, 16)
		if _, e := rand.Read(nonce); e != nil {
			return e
		}
		target = ".layersentry-workspace-successor-" + hex.EncodeToString(nonce) + ".tmp"
	}
	fd, e := unix.Openat(int(d.Fd()), target, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e == unix.EEXIST && !replace {
		old, re := workspaceproof.ReadAtDirectory(d, target, workspaceproof.CallerID, workspaceproof.CallerID, 0600, int64(len(raw)))
		if re == nil && bytes.Equal(old, raw) {
			return nil
		}
		return workspaceproof.ErrAdmission
	}
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), target)
	var created unix.Stat_t
	if unix.Fstat(fd, &created) != nil || created.Mode&unix.S_IFMT != unix.S_IFREG || created.Mode&07777 != 0600 || created.Uid != workspaceproof.CallerID || created.Gid != workspaceproof.CallerID || created.Nlink != 1 || created.Size != 0 {
		f.Close()
		return workspaceproof.ErrAdmission
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = d.Sync(); e != nil {
		return e
	}
	verified, e := workspaceproof.ReadAtDirectory(d, target, workspaceproof.CallerID, workspaceproof.CallerID, 0600, int64(len(raw)))
	var named unix.Stat_t
	if e != nil || !bytes.Equal(verified, raw) || unix.Fstatat(int(d.Fd()), target, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != created.Dev || named.Ino != created.Ino {
		return workspaceproof.ErrAdmission
	}
	if replace {
		if e = unix.Renameat(int(d.Fd()), target, int(d.Fd()), name); e != nil {
			return e
		}
		return d.Sync()
	}
	return nil
}
func (s *workspaceSuccessor) readReceipt(d *os.File) (*workspaceSuccessorReceipt, error) {
	var st unix.Stat_t
	e := unix.Fstatat(int(d.Fd()), workspaceSuccessorJournal, &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == unix.ENOENT {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	raw, e := workspaceproof.ReadAtDirectory(d, workspaceSuccessorJournal, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
	if e != nil {
		return nil, e
	}
	var r workspaceSuccessorReceipt
	if workspaceproof.DecodeCanonical(raw, &r) != nil || s.validateReceipt(r) != nil {
		return nil, workspaceproof.ErrAdmission
	}
	archive, e := workspaceproof.ReadAtDirectory(d, workspaceSuccessorArchiveName(raw), workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
	if e != nil || !bytes.Equal(archive, raw) {
		return nil, workspaceproof.ErrAdmission
	}
	return &r, nil
}

// The first archive can be durable while the exclusive current-journal write
// failed. Only an explicit reconcile may restore that exact PREPARED record;
// it cannot run manifest publication in the same invocation.
func (s *workspaceSuccessor) initialArchive(d *os.File) (*workspaceSuccessorReceipt, error) {
	fd, e := unix.Openat(int(d.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, workspaceproof.ErrAdmission
	}
	f := os.NewFile(uintptr(fd), "held-workspace")
	defer f.Close()
	entries, e := f.ReadDir(129)
	if e != nil && e != io.EOF || len(entries) > 128 {
		return nil, workspaceproof.ErrAdmission
	}
	var result *workspaceSuccessorReceipt
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".layersentry-workspace-successor-") {
			continue
		}
		// A null current journal with any other attempted publication is not an
		// initial archive seam and supplies no reconstruction authority.
		if !strings.HasPrefix(name, ".layersentry-workspace-successor-receipt-") || !strings.HasSuffix(name, ".json") || result != nil {
			return nil, workspaceproof.ErrAdmission
		}
		raw, e := workspaceproof.ReadAtDirectory(d, name, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
		var r workspaceSuccessorReceipt
		if e != nil || workspaceSuccessorArchiveName(raw) != name || workspaceproof.DecodeCanonical(raw, &r) != nil || s.validateReceipt(r) != nil || r.State != "PREPARED" || r.Attempt != 0 {
			return nil, workspaceproof.ErrAdmission
		}
		result = &r
	}
	return result, nil
}
func (s *workspaceSuccessor) saveReceipt(d *os.File, r workspaceSuccessorReceipt, replace bool) error {
	if s.validateReceipt(r) != nil {
		return workspaceproof.ErrAdmission
	}
	var previous []byte
	if replace {
		var e error
		previous, e = workspaceproof.ReadAtDirectory(d, workspaceSuccessorJournal, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
		var prior workspaceSuccessorReceipt
		if e != nil || workspaceproof.DecodeCanonical(previous, &prior) != nil || s.validateReceipt(prior) != nil || validateWorkspaceSuccessorAdvance(prior, r) != nil {
			return workspaceproof.ErrAdmission
		}
		// Preserve the exact current receipt even when its earlier archive write
		// had an ambiguous outcome. No newly observed time is substituted here.
		if e = writeWorkspaceSuccessorFile(d, workspaceSuccessorArchiveName(previous), previous, false); e != nil {
			return e
		}
	} else if r.State != "PREPARED" {
		return workspaceproof.ErrAdmission
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if e = writeWorkspaceSuccessorFile(d, workspaceSuccessorArchiveName(raw), raw, false); e != nil {
		return e
	}
	if replace {
		current, e := workspaceproof.ReadAtDirectory(d, workspaceSuccessorJournal, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
		if e != nil || !bytes.Equal(previous, current) {
			return workspaceproof.ErrAdmission
		}
	}
	return writeWorkspaceSuccessorFile(d, workspaceSuccessorJournal, raw, replace)
}

func workspaceSuccessorArchiveName(raw []byte) string {
	return ".layersentry-workspace-successor-receipt-" + workspaceproof.Digest(raw) + ".json"
}

// Archives form one complete immutable history. A crash may leave exactly one
// next receipt archived before the current-journal rename. It is not authority
// to dispatch again: only explicit reconciliation can restore those same bytes.
func workspaceSuccessorArchiveAhead(current workspaceSuccessorReceipt, archives []workspaceSuccessorReceipt) (*workspaceSuccessorReceipt, error) {
	if len(archives) == 0 || len(archives) > 16 {
		return nil, workspaceproof.ErrAdmission
	}
	ordered := append([]workspaceSuccessorReceipt(nil), archives...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].UpdatedAt.Before(ordered[j].UpdatedAt) })
	index := -1
	for i, r := range ordered {
		if i == 0 {
			if r.State != "PREPARED" || r.Attempt != 0 {
				return nil, workspaceproof.ErrAdmission
			}
		} else if !ordered[i-1].UpdatedAt.Before(r.UpdatedAt) || validateWorkspaceSuccessorAdvance(ordered[i-1], r) != nil {
			return nil, workspaceproof.ErrAdmission
		}
		if reflect.DeepEqual(current, r) {
			index = i
		}
	}
	if index < 0 || index < len(ordered)-2 {
		return nil, workspaceproof.ErrAdmission
	}
	if index == len(ordered)-1 {
		return nil, nil
	}
	next := ordered[index+1]
	return &next, nil
}

func (s *workspaceSuccessor) archivedAdvance(d *os.File, current workspaceSuccessorReceipt) (*workspaceSuccessorReceipt, error) {
	fd, e := unix.Openat(int(d.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, workspaceproof.ErrAdmission
	}
	f := os.NewFile(uintptr(fd), "held-workspace-archives")
	defer f.Close()
	entries, e := f.ReadDir(129)
	if e != nil && e != io.EOF || len(entries) > 128 {
		return nil, workspaceproof.ErrAdmission
	}
	var archives []workspaceSuccessorReceipt
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".layersentry-workspace-successor-receipt-") {
			continue
		}
		raw, e := workspaceproof.ReadAtDirectory(d, name, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxProtocolBytes)
		var r workspaceSuccessorReceipt
		if e != nil || workspaceSuccessorArchiveName(raw) != name || workspaceproof.DecodeCanonical(raw, &r) != nil || s.validateReceipt(r) != nil {
			return nil, workspaceproof.ErrAdmission
		}
		archives = append(archives, r)
	}
	return workspaceSuccessorArchiveAhead(current, archives)
}

func validateWorkspaceSuccessorAdvance(before, after workspaceSuccessorReceipt) error {
	if before.Version != after.Version || before.AdmissionSHA256 != after.AdmissionSHA256 || before.IntentID != after.IntentID || before.OriginalSHA256 != after.OriginalSHA256 || before.DesiredSHA256 != after.DesiredSHA256 || before.OriginalJobSHA256 != after.OriginalJobSHA256 || before.OriginalDevice != after.OriginalDevice || before.OriginalInode != after.OriginalInode || !before.PreparedAt.Equal(after.PreparedAt) || before.Scope != after.Scope || after.UpdatedAt.Before(before.UpdatedAt) || len(after.Dispatches) < len(before.Dispatches) || !reflect.DeepEqual(before.Dispatches, after.Dispatches[:len(before.Dispatches)]) {
		return workspaceproof.ErrAdmission
	}
	switch {
	case (before.State == "PREPARED" || before.State == "ORIGINAL_RECONCILED") && after.State == "PUBLISHING":
		if after.Attempt == before.Attempt+1 && len(after.Dispatches) == len(before.Dispatches)+1 {
			return nil
		}
	case (before.State == "PREPARED" || before.State == "PUBLISHING") && after.State == "ORIGINAL_RECONCILED", before.State == "PUBLISHING" && after.State == "VERIFIED":
		if after.Attempt == before.Attempt && len(after.Dispatches) == len(before.Dispatches) {
			return nil
		}
	}
	return workspaceproof.ErrAdmission
}

func (s *workspaceSuccessor) files(d *os.File, desired bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	var before unix.Stat_t
	if d == nil || unix.Fstatat(int(d.Fd()), "kubeone.yaml", &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return st, workspaceproof.ErrAdmission
	}
	expected := s.admission.Manifest.OriginalSHA256
	if desired {
		expected = workspaceproof.Digest(s.desired)
	}
	raw, e := workspaceproof.ReadAtDirectory(d, "kubeone.yaml", workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxManifestBytes)
	if e != nil || workspaceproof.Digest(raw) != expected || unix.Fstatat(int(d.Fd()), "kubeone.yaml", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !workspaceSuccessorSameFile(before, st) {
		return st, workspaceproof.ErrAdmission
	}
	job, e := workspaceproof.ReadAtDirectory(d, ".layersentry-provision.json", workspaceproof.CallerID, workspaceproof.CallerID, 0600, 8192)
	if e != nil || workspaceproof.Digest(job) != s.admission.Expected.JobSHA256 {
		return st, workspaceproof.ErrAdmission
	}
	var j ProvisionJob
	if json.Unmarshal(job, &j) != nil || j.ID != s.admission.OriginalJobID || !retryableProvisionJob(j, Workspace{ClusterID: "kubeone-dc", ExpectedNodes: 4}) {
		return st, workspaceproof.ErrAdmission
	}
	var absent unix.Stat_t
	if unix.Fstatat(int(d.Fd()), "kubeconfig", &absent, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return st, workspaceproof.ErrAdmission
	}
	if workspaceproof.DirectoryStillNamed(d, workspaceSuccessorRoot, workspaceproof.CallerID, workspaceproof.CallerID, 0700) != nil || s.checkAdmission() != nil {
		return st, workspaceproof.ErrAdmission
	}
	return st, nil
}

func workspaceSuccessorSameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (s *workspaceSuccessor) preservation(d *os.File, write bool) error {
	for name, raw := range map[string][]byte{".layersentry-workspace-successor-original.yaml": s.admission.OriginalManifest, ".layersentry-workspace-successor-desired.yaml": s.desired} {
		if write {
			if e := writeWorkspaceSuccessorFile(d, name, raw, false); e != nil {
				return e
			}
		}
		current, e := workspaceproof.ReadAtDirectory(d, name, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxManifestBytes)
		if e != nil || !bytes.Equal(raw, current) {
			return workspaceproof.ErrAdmission
		}
	}
	return nil
}
func (s *workspaceSuccessor) originalStillHeld(d *os.File, r workspaceSuccessorReceipt) error {
	st, e := s.files(d, false)
	if e != nil || st.Dev != r.OriginalDevice || st.Ino != r.OriginalInode {
		return workspaceproof.ErrAdmission
	}
	return nil
}

// The only manifest mutation. Its dispatch was durably attributed already.
// The actual old inode, job and root admission are re-read AFTER temp fsync and
// the observation is checked immediately before atomic rename. Failed writes
// preserve PUBLISHING and all original artifacts, with no automatic replay.
func (s *workspaceSuccessor) publishManifest(d *os.File, r workspaceSuccessorReceipt) error {
	name := ".layersentry-workspace-successor-attempt-" + strconv.Itoa(r.Attempt) + ".yaml"
	if e := writeWorkspaceSuccessorFile(d, name, s.desired, false); e != nil {
		return e
	}
	if e := s.originalStillHeld(d, r); e != nil {
		return e
	}
	if e := s.preservation(d, false); e != nil {
		return e
	}
	// Hold and re-read the exact proposed inode immediately before rename;
	// writing it earlier does not authorize a subsequently replaced entry.
	var before, after unix.Stat_t
	if unix.Fstatat(int(d.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return workspaceproof.ErrAdmission
	}
	raw, e := workspaceproof.ReadAtDirectory(d, name, workspaceproof.CallerID, workspaceproof.CallerID, 0600, workspaceproof.MaxManifestBytes)
	if e != nil || !bytes.Equal(raw, s.desired) || unix.Fstatat(int(d.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !workspaceSuccessorSameFile(before, after) {
		return workspaceproof.ErrAdmission
	}
	if s.fresh(r.Request, r.Observation) != nil {
		return workspaceproof.ErrAdmission
	}
	if e := unix.Renameat(int(d.Fd()), name, int(d.Fd()), "kubeone.yaml"); e != nil {
		return e
	}
	return d.Sync()
}
func (s *workspaceSuccessor) verifyDesired(ctx context.Context, d *os.File, r workspaceSuccessorReceipt) (workspaceSuccessorReceipt, error) {
	if _, e := s.files(d, true); e != nil {
		return r, e
	}
	if e := s.preservation(d, false); e != nil {
		return r, e
	}
	request, proof, e := s.observe(ctx, workspaceproof.Postpublication)
	if e != nil {
		return r, e
	}
	if _, e = s.files(d, true); e != nil {
		return r, e
	}
	if s.fresh(request, proof) != nil {
		return r, workspaceproof.ErrAdmission
	}
	r.State = "VERIFIED"
	r.Request = request
	r.Observation = proof
	r.UpdatedAt = time.Now().UTC()
	if e = s.saveReceipt(d, r, true); e != nil {
		return r, e
	}
	return r, nil
}
func (s *workspaceSuccessor) dispatch(ctx context.Context, d *os.File, r workspaceSuccessorReceipt) (workspaceSuccessorReceipt, error) {
	if (r.State != "PREPARED" && r.State != "ORIGINAL_RECONCILED") || r.Attempt >= 4 || s.originalStillHeld(d, r) != nil || s.preservation(d, false) != nil {
		return r, workspaceproof.ErrAdmission
	}
	// Continue receives a new observation. It never renews an old response.
	request, proof, e := s.observe(ctx, workspaceproof.Prepublication)
	if e != nil {
		return r, e
	}
	if s.originalStillHeld(d, r) != nil || s.fresh(request, proof) != nil {
		return r, workspaceproof.ErrAdmission
	}
	now := time.Now().UTC()
	r.State = "PUBLISHING"
	r.Attempt++
	r.Request = request
	r.Observation = proof
	r.UpdatedAt = now
	r.Dispatches = append(r.Dispatches, workspaceSuccessorDispatch{request, proof, now})
	if e = s.saveReceipt(d, r, true); e != nil {
		return r, e
	}
	if e = s.publishManifest(d, r); e != nil {
		return r, e
	}
	return s.verifyDesired(ctx, d, r)
}

// The caller holds the shared workspace operation flock and Portal mutex.
// Reconcile never writes the manifest; continue is a separate explicit action
// after exact original inode/no-publication reconciliation. Missing pieces are
// only immutable metadata repair, never a native provisioning side effect.
func (s *workspaceSuccessor) runLocked(ctx context.Context, d *os.File, action string) (workspaceSuccessorReceipt, error) {
	var zero workspaceSuccessorReceipt
	if s == nil || d == nil || (action != "publish" && action != "reconcile" && action != "continue") || s.checkAdmission() != nil {
		return zero, workspaceproof.ErrAdmission
	}
	r, e := s.readReceipt(d)
	if e != nil {
		return zero, e
	}
	if r == nil {
		archive, e := s.initialArchive(d)
		if e != nil {
			return zero, e
		}
		if archive != nil {
			if action != "reconcile" || s.originalStillHeld(d, *archive) != nil {
				return *archive, workspaceproof.ErrAdmission
			}
			request, proof, e := s.observe(ctx, workspaceproof.Prepublication)
			if e != nil || s.originalStillHeld(d, *archive) != nil || s.fresh(request, proof) != nil {
				return *archive, workspaceproof.ErrAdmission
			}
			// Re-publish the original recorded bytes, not a fresh PREPARED intent.
			if e = s.saveReceipt(d, *archive, false); e != nil {
				return *archive, e
			}
			if e = s.preservation(d, true); e != nil {
				return *archive, e
			}
			archive.State = "ORIGINAL_RECONCILED"
			archive.Request, archive.Observation, archive.UpdatedAt = request, proof, time.Now().UTC()
			if s.fresh(request, proof) != nil {
				return *archive, workspaceproof.ErrAdmission
			}
			return *archive, s.saveReceipt(d, *archive, true)
		}
		if action != "publish" {
			return zero, workspaceproof.ErrAdmission
		}
		for _, name := range []string{".layersentry-workspace-successor-original.yaml", ".layersentry-workspace-successor-desired.yaml"} {
			var st unix.Stat_t
			if unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
				return zero, workspaceproof.ErrAdmission
			}
		}
		st, e := s.files(d, false)
		if e != nil {
			return zero, e
		}
		request, proof, e := s.observe(ctx, workspaceproof.Prepublication)
		if e != nil {
			return zero, e
		}
		again, e := s.files(d, false)
		if e != nil || st.Dev != again.Dev || st.Ino != again.Ino || s.fresh(request, proof) != nil {
			return zero, workspaceproof.ErrAdmission
		}
		now := time.Now().UTC()
		next := workspaceSuccessorReceipt{Version: 1, AdmissionSHA256: workspaceproof.Digest(s.raw), IntentID: s.admission.ID, OriginalSHA256: s.admission.Manifest.OriginalSHA256, DesiredSHA256: workspaceproof.Digest(s.desired), OriginalJobSHA256: s.admission.Expected.JobSHA256, State: "PREPARED", Attempt: 0, Dispatches: []workspaceSuccessorDispatch{}, OriginalDevice: st.Dev, OriginalInode: st.Ino, PreparedAt: now, UpdatedAt: now, Request: request, Observation: proof, Scope: workspaceSuccessorScope}
		if e = s.saveReceipt(d, next, false); e != nil {
			return next, e
		}
		if e = s.preservation(d, true); e != nil {
			return next, e
		}
		return s.dispatch(ctx, d, next)
	}
	archive, e := s.archivedAdvance(d, *r)
	if e != nil {
		return *r, e
	}
	if archive != nil {
		if action != "reconcile" {
			return *r, workspaceproof.ErrAdmission
		}
		purpose := workspaceproof.Prepublication
		checkFiles := func() error { return s.originalStillHeld(d, *r) }
		if archive.State == "VERIFIED" {
			purpose = workspaceproof.Postpublication
			checkFiles = func() error { _, e := s.files(d, true); return e }
		}
		if checkFiles() != nil || s.preservation(d, false) != nil {
			return *r, workspaceproof.ErrAdmission
		}
		request, proof, e := s.observe(ctx, purpose)
		if e != nil || checkFiles() != nil || s.fresh(request, proof) != nil {
			return *r, workspaceproof.ErrAdmission
		}
		// This call repairs only the current metadata pointer to an already
		// durable receipt. It never refreshes its time or publishes a manifest.
		if e = s.saveReceipt(d, *archive, true); e != nil {
			return *r, e
		}
		return *archive, nil
	}
	if action == "publish" {
		return *r, workspaceproof.ErrAdmission
	}
	if action == "continue" {
		if r.State != "ORIGINAL_RECONCILED" {
			return *r, workspaceproof.ErrAdmission
		}
		return s.dispatch(ctx, d, *r)
	}
	if r.State == "VERIFIED" {
		if _, e = s.files(d, true); e != nil {
			return *r, e
		}
		if e = s.preservation(d, false); e != nil {
			return *r, e
		}
		return *r, nil
	}
	if r.State == "PUBLISHING" {
		if _, e = s.files(d, true); e == nil {
			return s.verifyDesired(ctx, d, *r)
		}
	}
	if s.originalStillHeld(d, *r) != nil {
		return *r, workspaceproof.ErrAdmission
	}
	request, proof, e := s.observe(ctx, workspaceproof.Prepublication)
	if e != nil {
		return *r, e
	}
	if s.originalStillHeld(d, *r) != nil || s.fresh(request, proof) != nil {
		return *r, workspaceproof.ErrAdmission
	}
	if e = s.preservation(d, true); e != nil {
		return *r, e
	}
	if r.State == "ORIGINAL_RECONCILED" {
		return *r, nil
	}
	r.State = "ORIGINAL_RECONCILED"
	r.Request = request
	r.Observation = proof
	r.UpdatedAt = time.Now().UTC()
	if e = s.saveReceipt(d, *r, true); e != nil {
		return *r, e
	}
	return *r, nil
}
