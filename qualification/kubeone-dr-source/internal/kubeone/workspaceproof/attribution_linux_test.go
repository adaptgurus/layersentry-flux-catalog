//go:build linux

package workspaceproof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func attributionFixture() (ObserverAttribution, ExecutablePeer, DeploymentIdentity) {
	d := DeploymentIdentity{strings.Repeat("a", 40), strings.Repeat("b", 64), strings.Repeat("c", 64), "0b5e029f-7b48-413a-b817-7654aae7e350", "21641f4a-b458-4ad9-9f6c-51e76b84743b"}
	p := ExecutablePeer{0, 0, ObserverExecutable, strings.Repeat("d", 64)}
	a := ObserverAttribution{Version: 1, ProfileSHA256: strings.Repeat("e", 64), SourceCommit: d.SourceCommit, BuildIdentitySHA256: d.BuildIdentitySHA256, ExecutableSHA256: p.SHA256, ExecutablePath: p.Path, PID: 1234, StartTicks: "12345", SocketDevice: 2, SocketInode: 3, HostUUID: d.HostUUID, BootID: d.BootID, StartupNonce: strings.Repeat("f", 64), StartedAt: time.Now().UTC().Add(-time.Second)}
	return a, p, d
}
func TestAttributionRejectsUnqualifiedDeploymentAndAmbiguousReceipt(t *testing.T) {
	a, p, d := attributionFixture()
	now := time.Now().UTC()
	if validateAttribution(a, p, d, a.ProfileSHA256, now) != nil {
		t.Fatal("exact attribution")
	}
	for name, change := range map[string]func(*ObserverAttribution){
		"source":          func(x *ObserverAttribution) { x.SourceCommit = strings.Repeat("1", 40) },
		"build":           func(x *ObserverAttribution) { x.BuildIdentitySHA256 = strings.Repeat("1", 64) },
		"executable":      func(x *ObserverAttribution) { x.ExecutableSHA256 = strings.Repeat("1", 64) },
		"path":            func(x *ObserverAttribution) { x.ExecutablePath = "/tmp/observer" },
		"pid":             func(x *ObserverAttribution) { x.PID = 1 },
		"birth zero":      func(x *ObserverAttribution) { x.StartTicks = "0" },
		"birth alternate": func(x *ObserverAttribution) { x.StartTicks = "0123" },
		"socket":          func(x *ObserverAttribution) { x.SocketInode = 0 },
		"boot":            func(x *ObserverAttribution) { x.BootID = "5543f5ca-04f2-448b-b471-eae3e3da9c8d" },
		"nonce":           func(x *ObserverAttribution) { x.StartupNonce = "" },
		"future":          func(x *ObserverAttribution) { x.StartedAt = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			x := a
			change(&x)
			if validateAttribution(x, p, d, a.ProfileSHA256, now) == nil {
				t.Fatal("accepted")
			}
		})
	}
	raw, _ := json.Marshal(a)
	var got ObserverAttribution
	if DecodeCanonical(raw, &got) != nil || got != a {
		t.Fatal("canonical")
	}
	for _, bad := range [][]byte{append([]byte(" "), raw...), []byte(strings.Replace(string(raw), `"pid":1234`, `"pid":1234,"pid":1234`, 1)), []byte(strings.Replace(string(raw), `"start_ticks":"12345"`, `"start_ticks":null`, 1))} {
		if DecodeCanonical(bad, &got) == nil {
			t.Fatal("ambiguous receipt")
		}
	}
}
