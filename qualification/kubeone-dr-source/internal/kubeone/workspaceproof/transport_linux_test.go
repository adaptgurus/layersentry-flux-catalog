//go:build linux

package workspaceproof

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFramingRejectsTruncationAndOversize(t *testing.T) {
	r, _, _, _ := protocolFixture(t)
	var b bytes.Buffer
	if writeFrame(&b, r) != nil {
		t.Fatal("write")
	}
	raw := b.Bytes()
	var out Request
	if readFrame(bytes.NewReader(raw), &out) != nil || out != r {
		t.Fatal("valid framing")
	}
	for _, bad := range [][]byte{raw[:2], raw[:len(raw)-1], {0xff, 0xff, 0xff, 0xff}, {0, 0, 0, 0}} {
		if readFrame(bytes.NewReader(bad), &out) == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestRealUnixPeerBindsKernelPIDAndExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned qualification executable custody requires root fixture")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	p := ExecutablePeer{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Path: exe, SHA256: Digest(raw)}
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() { c, _ := listener.AcceptUnix(); accepted <- c }()
	client, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept")
	}
	defer server.Close()
	sample, e := checkPeer(client, p)
	if e != nil || int(sample.pid) != os.Getpid() || sample.ticks == "" {
		t.Fatal("actual peer failed", e)
	}
	for _, mutate := range []func(*ExecutablePeer){func(p *ExecutablePeer) { p.UID++ }, func(p *ExecutablePeer) { p.GID++ }, func(p *ExecutablePeer) { p.Path += ".other" }, func(p *ExecutablePeer) { p.SHA256 = Digest([]byte("different executable")) }} {
		bad := p
		mutate(&bad)
		if _, e := checkPeer(client, bad); e == nil {
			t.Fatal("foreign peer accepted")
		}
	}
}

func TestNoImplicitSocketParentOrExistingPathAdoption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "observer.sock")
	if socketCustody(path, false) == nil {
		t.Fatal("missing parent admitted")
	}
	if _, e := os.Lstat(filepath.Dir(path)); !os.IsNotExist(e) {
		t.Fatal("read-only custody created path")
	}
	if socketCustody(filepath.Join(t.TempDir(), "observer.sock"), false) == nil {
		t.Fatal("unprotected /tmp ancestor admitted")
	}
}

func TestActualObserverResponseFrameBindsStartupAndRejectsPostObservationDrift(t *testing.T) {
	_, observation, _, _ := protocolFixture(t)
	attribution, _, _ := attributionFixture()
	// Exercise the product response writer over a real duplex stream, decoded
	// using the exact client frame type. The former raw Response cannot decode.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	result := make(chan error, 1)
	checked := make(chan struct{}, 1)
	go func() {
		result <- writeAttributedObservation(server, attribution, observation, func() error { checked <- struct{}{}; return nil })
	}()
	var frame attributedResponse
	if readFrame(client, &frame) != nil || frame.StartupNonce != attribution.StartupNonce || frame.Observation != observation {
		t.Fatal("actual attributed response was not client-readable")
	}
	if e := <-result; e != nil {
		t.Fatal(e)
	}
	<-checked
	var rejected bytes.Buffer
	if writeAttributedObservation(&rejected, attribution, observation, func() error { return ErrAdmission }) == nil || rejected.Len() != 0 {
		t.Fatal("changed post-observation attribution emitted proof")
	}
	if writeAttributedObservation(&rejected, attribution, observation, nil) == nil || rejected.Len() != 0 {
		t.Fatal("missing custody admitted")
	}
}
