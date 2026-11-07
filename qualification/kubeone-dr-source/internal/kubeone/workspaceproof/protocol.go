package workspaceproof

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

const (
	ProtocolVersion  = 1
	ObservationTTL   = 20 * time.Second
	MaxProtocolBytes = 32 << 10
	Prepublication   = "PREPUBLICATION"
	Postpublication  = "POSTPUBLICATION"
)

type Request struct {
	Version       int    `json:"version"`
	ProfileSHA256 string `json:"profile_sha256"`
	Nonce         string `json:"nonce"`
	Purpose       string `json:"purpose"`
}

type GuestIdentity struct {
	NativeID         int    `json:"native_id"`
	DomainUUID       string `json:"domain_uuid"`
	GuestBootID      string `json:"guest_boot_id"`
	OwnerSHA256      string `json:"owner_sha256"`
	HostKeySHA256    string `json:"host_key_sha256"`
	HypervisorUUID   string `json:"hypervisor_uuid"`
	HypervisorBootID string `json:"hypervisor_boot_id"`
}

// Observation intervals refer to the actual reads, never the later time at
// which a response is encoded. All identity fields are compared to admission.
type GuestObservation struct {
	Identity       GuestIdentity `json:"identity"`
	StartedAt      time.Time     `json:"started_at"`
	CheckedAt      time.Time     `json:"checked_at"`
	EvidenceSHA256 string        `json:"evidence_sha256"`
}

type Response struct {
	Version               int                 `json:"version"`
	RequestSHA256         string              `json:"request_sha256"`
	Nonce                 string              `json:"nonce"`
	ProfileSHA256         string              `json:"profile_sha256"`
	SourceCommit          string              `json:"source_commit"`
	ExecutableSHA256      string              `json:"executable_sha256"`
	HostUUID              string              `json:"host_uuid"`
	BootID                string              `json:"boot_id"`
	ManifestSHA256        string              `json:"manifest_sha256"`
	JobSHA256             string              `json:"job_sha256"`
	PrivateKeySHA256      string              `json:"private_key_sha256"`
	NativeAdmissionSHA256 string              `json:"native_admission_sha256"`
	NativeProofSHA256     string              `json:"native_proof_sha256"`
	NativeStartedAt       time.Time           `json:"native_started_at"`
	NativeCheckedAt       time.Time           `json:"native_checked_at"`
	Guests                [6]GuestObservation `json:"guests"`
	WorkspaceCheckedAt    time.Time           `json:"workspace_checked_at"`
	WorkspaceStartedAt    time.Time           `json:"workspace_started_at"`
}

// Expected is supplied by the protected admission, not by an HTTP caller or
// by a producer response. A successful transport alone proves no readiness.
type Expected struct {
	ProfileSHA256         string
	SourceCommit          string
	ExecutableSHA256      string
	HostUUID              string
	BootID                string
	ManifestSHA256        string
	JobSHA256             string
	PrivateKeySHA256      string
	NativeAdmissionSHA256 string
	Guests                [6]GuestIdentity
}

func canonicalHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	raw, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(raw) == s
}

func canonicalUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	raw := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	return canonicalHex(raw, 32) && raw != "00000000000000000000000000000000"
}

func NewRequest(profile, purpose string) (Request, error) {
	nonce := make([]byte, 32)
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		return Request{}, ErrAdmission
	}
	r := Request{ProtocolVersion, profile, hex.EncodeToString(nonce), purpose}
	return r, r.Validate()
}

func (r Request) Validate() error {
	if r.Version != ProtocolVersion || !canonicalHex(r.ProfileSHA256, 64) || !canonicalHex(r.Nonce, 64) || (r.Purpose != Prepublication && r.Purpose != Postpublication) {
		return ErrAdmission
	}
	return nil
}

// DecodeCanonical rejects duplicate keys, omitted fields, alternate raw forms
// and trailing data by requiring the exact typed canonical protocol encoding.
// The protocol is private and both ends emit this same encoding.
func DecodeCanonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxProtocolBytes {
		return ErrAdmission
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrAdmission
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrAdmission
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(canonical, raw) {
		return ErrAdmission
	}
	return nil
}

func freshInterval(start, end, now time.Time) bool {
	return !start.IsZero() && !end.Before(start) && !end.After(now) && now.Sub(start) <= ObservationTTL
}

func (e Expected) Validate() error {
	if !canonicalHex(e.ProfileSHA256, 64) || !canonicalHex(e.SourceCommit, 40) || !canonicalHex(e.ExecutableSHA256, 64) || !canonicalHex(e.ManifestSHA256, 64) || !canonicalHex(e.JobSHA256, 64) || !canonicalHex(e.PrivateKeySHA256, 64) || !canonicalHex(e.NativeAdmissionSHA256, 64) || !canonicalUUID(e.HostUUID) || !canonicalUUID(e.BootID) {
		return ErrAdmission
	}
	domains := map[string]bool{}
	keys := map[string]bool{}
	for i, g := range e.Guests {
		if g.NativeID != 6+i || !canonicalUUID(g.DomainUUID) || !canonicalUUID(g.GuestBootID) || !canonicalUUID(g.HypervisorUUID) || !canonicalUUID(g.HypervisorBootID) || !canonicalHex(g.OwnerSHA256, 64) || !canonicalHex(g.HostKeySHA256, 64) || domains[g.DomainUUID] || keys[g.HostKeySHA256] {
			return ErrAdmission
		}
		domains[g.DomainUUID] = true
		keys[g.HostKeySHA256] = true
	}
	return nil
}

func ValidateResponse(r Request, p Response, e Expected, now time.Time) error {
	if r.Validate() != nil || e.Validate() != nil {
		return ErrAdmission
	}
	raw, _ := json.Marshal(r)
	if p.Version != ProtocolVersion || p.RequestSHA256 != Digest(raw) || p.Nonce != r.Nonce || p.ProfileSHA256 != r.ProfileSHA256 || p.ProfileSHA256 != e.ProfileSHA256 || p.SourceCommit != e.SourceCommit || p.ExecutableSHA256 != e.ExecutableSHA256 || p.HostUUID != e.HostUUID || p.BootID != e.BootID || p.ManifestSHA256 != e.ManifestSHA256 || p.JobSHA256 != e.JobSHA256 || p.PrivateKeySHA256 != e.PrivateKeySHA256 || p.NativeAdmissionSHA256 != e.NativeAdmissionSHA256 || !canonicalHex(p.NativeProofSHA256, 64) || !freshInterval(p.NativeStartedAt, p.NativeCheckedAt, now) || !freshInterval(p.WorkspaceStartedAt, p.WorkspaceCheckedAt, now) {
		return ErrAdmission
	}
	for i, g := range p.Guests {
		if g.Identity != e.Guests[i] || !canonicalHex(g.EvidenceSHA256, 64) || !freshInterval(g.StartedAt, g.CheckedAt, now) || p.WorkspaceCheckedAt.Before(g.CheckedAt) {
			return ErrAdmission
		}
	}
	if p.WorkspaceCheckedAt.Before(p.NativeCheckedAt) {
		return ErrAdmission
	}
	return nil
}
