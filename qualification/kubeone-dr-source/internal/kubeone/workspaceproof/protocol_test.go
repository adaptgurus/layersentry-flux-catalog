package workspaceproof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func protocolFixture(t *testing.T) (Request, Response, Expected, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	sha := strings.Repeat("a", 64)
	e := Expected{ProfileSHA256: sha, SourceCommit: strings.Repeat("b", 40), ExecutableSHA256: sha, HostUUID: "0b5e029f-7b48-413a-b817-7654aae7e350", BootID: "21641f4a-b458-4ad9-9f6c-51e76b84743b", ManifestSHA256: sha, JobSHA256: sha, PrivateKeySHA256: sha, NativeAdmissionSHA256: sha}
	for i := range e.Guests {
		e.Guests[i] = GuestIdentity{NativeID: 6 + i, DomainUUID: fmt.Sprintf("40724bd9-32ac-4671-b10d-%012d", i+1), GuestBootID: e.BootID, OwnerSHA256: sha, HostKeySHA256: fmt.Sprintf("%064x", i+1), HypervisorUUID: e.HostUUID, HypervisorBootID: e.BootID}
	}
	r, err := NewRequest(sha, Prepublication)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	p := Response{Version: ProtocolVersion, RequestSHA256: Digest(raw), Nonce: r.Nonce, ProfileSHA256: sha, SourceCommit: e.SourceCommit, ExecutableSHA256: sha, HostUUID: e.HostUUID, BootID: e.BootID, ManifestSHA256: sha, JobSHA256: sha, PrivateKeySHA256: sha, NativeAdmissionSHA256: sha, NativeProofSHA256: sha, NativeStartedAt: now.Add(-time.Second), NativeCheckedAt: now, WorkspaceStartedAt: now, WorkspaceCheckedAt: now}
	for i, g := range e.Guests {
		p.Guests[i] = GuestObservation{Identity: g, StartedAt: now.Add(-time.Second), CheckedAt: now, EvidenceSHA256: sha}
	}
	return r, p, e, now
}

func TestResponseRejectsRestampedStaleAndWrongOwnerEvidence(t *testing.T) {
	r, p, e, now := protocolFixture(t)
	if err := ValidateResponse(r, p, e, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Response)
	}{
		{"old-guest-new-response", func(p *Response) {
			p.Guests[0].StartedAt = now.Add(-21 * time.Second)
			p.Guests[0].CheckedAt = now.Add(-20 * time.Second)
		}},
		{"long-native-read-new-completion", func(p *Response) { p.NativeStartedAt = now.Add(-21 * time.Second) }},
		{"future", func(p *Response) { p.Guests[0].CheckedAt = now.Add(time.Millisecond) }},
		{"swapped-guest", func(p *Response) { p.Guests[0], p.Guests[1] = p.Guests[1], p.Guests[0] }},
		{"new-key", func(p *Response) { p.Guests[0].Identity.HostKeySHA256 = p.Guests[1].Identity.HostKeySHA256 }},
		{"replayed-nonce", func(p *Response) { p.Nonce = strings.Repeat("0", 64) }},
		{"other-request", func(p *Response) { p.RequestSHA256 = strings.Repeat("0", 64) }},
		{"unqualified-root-executable", func(p *Response) { p.ExecutableSHA256 = strings.Repeat("0", 64) }},
		{"workspace-read-before-guest", func(p *Response) { p.WorkspaceCheckedAt = now.Add(-time.Millisecond) }},
		{"missing-native-admission", func(p *Response) { p.NativeAdmissionSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := p
			tc.change(&bad)
			if ValidateResponse(r, bad, e, now) == nil {
				t.Fatal("accepted")
			}
		})
	}
	if ValidateResponse(r, p, e, now.Add(ObservationTTL)) == nil {
		t.Fatal("late publication accepted")
	}
}

func TestProtocolRejectsAmbiguousWireEncoding(t *testing.T) {
	r, _, _, _ := protocolFixture(t)
	raw, _ := json.Marshal(r)
	var decoded Request
	if DecodeCanonical(raw, &decoded) != nil || decoded != r {
		t.Fatal("canonical request rejected")
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), '\n'), []byte(strings.Replace(string(raw), "{", "{\"version\":1,", 1)), []byte(strings.Replace(string(raw), "}", ",\"path\":\"/root/key\"}", 1)), append(append([]byte{}, raw...), raw...), []byte("{}"), []byte("null")} {
		if DecodeCanonical(bad, &decoded) == nil {
			t.Fatal("ambiguous wire accepted")
		}
	}
}
