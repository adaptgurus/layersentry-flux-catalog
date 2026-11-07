package apirelay

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var testCredential = Credentials{Username: strings.Repeat("u", 32), Password: strings.Repeat("p", 32)}

type fakeTransport struct {
	mu                          sync.Mutex
	probes, opens, destinations []string
	badPath                     string
	failStream                  bool
	blocked                     chan struct{}
	payload                     chan string
}

func (f *fakeTransport) Probe(ctx context.Context, peer, destination string) error {
	f.mu.Lock()
	f.probes = append(f.probes, peer)
	f.destinations = append(f.destinations, destination)
	f.mu.Unlock()
	if f.blocked != nil {
		close(f.blocked)
		<-ctx.Done()
		return ctx.Err()
	}
	if peer == f.badPath {
		return errors.New("SSH works but workload TCP path is down")
	}
	return nil
}
func (f *fakeTransport) Open(_ context.Context, peer, destination string) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	f.opens = append(f.opens, peer)
	f.destinations = append(f.destinations, destination)
	f.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if f.failStream && peer == "10.254.60.97" {
			b := make([]byte, 128)
			n, _ := server.Read(b)
			if f.payload != nil {
				f.payload <- string(b[:n])
			}
			return
		}
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}
func (f *fakeTransport) snapshot() ([]string, []string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.probes...), append([]string{}, f.opens...), append([]string{}, f.destinations...)
}

func relayFixture(t *testing.T, transport transport) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, err := profileFor("dc")
	if err != nil {
		t.Fatal(err)
	}
	p.listen = listener.Addr().String()
	s := &Server{profile: p, credentials: testCredential, transport: transport}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay shutdown leaked a connection")
		}
	})
	return listener.Addr().String(), cancel, done
}

func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func exchange(t *testing.T, c net.Conn, request []byte, length int) []byte {
	t.Helper()
	if _, err := c.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(c, response); err != nil {
		t.Fatal(err)
	}
	return response
}
func authenticate(t *testing.T, c net.Conn, credential Credentials) []byte {
	t.Helper()
	if got := exchange(t, c, []byte{5, 2, 0, 2}, 2); !reflect.DeepEqual(got, []byte{5, 2}) {
		t.Fatalf("method response %v", got)
	}
	req := append([]byte{1, byte(len(credential.Username))}, []byte(credential.Username)...)
	req = append(req, byte(len(credential.Password)))
	req = append(req, []byte(credential.Password)...)
	return exchange(t, c, req, 2)
}
func connectRequest() []byte { return []byte{5, 1, 0, 1, 10, 254, 200, 10, 0x19, 0x2b} }

func TestRejectsUnauthenticatedAndWrongCredentialWithoutSSH(t *testing.T) {
	f := &fakeTransport{}
	address, _, _ := relayFixture(t, f)
	c := dial(t, address)
	if got := exchange(t, c, []byte{5, 1, 0}, 2); !reflect.DeepEqual(got, []byte{5, 255}) {
		t.Fatalf("no-auth accepted: %v", got)
	}
	c.Close()
	c = dial(t, address)
	if got := authenticate(t, c, Credentials{Username: testCredential.Username, Password: strings.Repeat("x", 32)}); !reflect.DeepEqual(got, []byte{1, 1}) {
		t.Fatalf("wrong credential accepted: %v", got)
	}
	probes, opens, _ := f.snapshot()
	if len(probes)+len(opens) != 0 {
		t.Fatal("unauthorized client invoked SSH")
	}
}

func TestRejectsForeignDestinationAndCommandsBeforeSSH(t *testing.T) {
	for name, request := range map[string][]byte{
		"foreign IPv4": {5, 1, 0, 1, 10, 254, 60, 1, 0x19, 0x2b},
		"foreign port": {5, 1, 0, 1, 10, 254, 200, 10, 0, 22},
		"domain":       {5, 1, 0, 3, 3, 'a', 'p', 'i', 0x19, 0x2b},
		"IPv6":         {5, 1, 0, 4}, "BIND": {5, 2, 0, 1}, "UDP": {5, 3, 0, 1}, "reserved": {5, 1, 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeTransport{}
			address, _, _ := relayFixture(t, f)
			c := dial(t, address)
			if got := authenticate(t, c, testCredential); got[1] != 0 {
				t.Fatal("valid auth denied")
			}
			if got := exchange(t, c, request, 10); got[1] == 0 {
				t.Fatal("foreign request accepted")
			}
			probes, opens, _ := f.snapshot()
			if len(probes)+len(opens) != 0 {
				t.Fatal("foreign destination invoked SSH")
			}
		})
	}
}

func TestManagementHealthyWorkloadFailureSelectsSecondLB(t *testing.T) {
	f := &fakeTransport{badPath: "10.254.60.97"}
	address, _, _ := relayFixture(t, f)
	c := dial(t, address)
	if authenticate(t, c, testCredential)[1] != 0 {
		t.Fatal("auth failed")
	}
	if exchange(t, c, connectRequest(), 10)[1] != 0 {
		t.Fatal("second LB unavailable")
	}
	payload := []byte("opaque TLS bytes stay unchanged")
	if got := exchange(t, c, payload, len(payload)); string(got) != string(payload) {
		t.Fatal("relay changed stream")
	}
	probes, opens, destinations := f.snapshot()
	if !reflect.DeepEqual(probes, []string{"10.254.60.97", "10.254.60.98"}) || !reflect.DeepEqual(opens, []string{"10.254.60.98"}) {
		t.Fatalf("wrong selection: probes=%v opens=%v", probes, opens)
	}
	for _, dest := range destinations {
		if dest != "10.254.200.10:6443" {
			t.Fatal("non-profile destination forwarded")
		}
	}
}

func TestFailureAfterForwardingNeverReplaysOnOtherLB(t *testing.T) {
	f := &fakeTransport{failStream: true, payload: make(chan string, 1)}
	address, _, _ := relayFixture(t, f)
	c := dial(t, address)
	if authenticate(t, c, testCredential)[1] != 0 || exchange(t, c, connectRequest(), 10)[1] != 0 {
		t.Fatal("connect failed")
	}
	if _, err := c.Write([]byte("mutation must not replay")); err != nil {
		t.Fatal(err)
	}
	if got := <-f.payload; got != "mutation must not replay" {
		t.Fatal("unexpected upstream bytes")
	}
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("failed upstream did not close: %d %v", n, err)
	}
	probes, opens, _ := f.snapshot()
	if len(probes) != 1 || len(opens) != 1 || opens[0] != "10.254.60.97" {
		t.Fatalf("failed stream replayed: %v %v", probes, opens)
	}
	// A fresh caller connection can select the other peer. The failed payload
	// itself is never sent again, even when opening passed its TCP preflight.
	next := dial(t, address)
	if authenticate(t, next, testCredential)[1] != 0 || exchange(t, next, connectRequest(), 10)[1] != 0 {
		t.Fatal("replacement connection failed")
	}
	if got := exchange(t, next, []byte("new connection"), 14); string(got) != "new connection" {
		t.Fatal("replacement stream differs")
	}
	_, opens, _ = f.snapshot()
	if !reflect.DeepEqual(opens, []string{"10.254.60.97", "10.254.60.98"}) {
		t.Fatalf("failed peer retained: %v", opens)
	}
}

func TestShutdownCancelsBlockedPreflightWithoutOpeningSSHStream(t *testing.T) {
	f := &fakeTransport{blocked: make(chan struct{})}
	address, cancel, _ := relayFixture(t, f)
	c := dial(t, address)
	if authenticate(t, c, testCredential)[1] != 0 {
		t.Fatal("auth failed")
	}
	if _, err := c.Write(connectRequest()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.blocked:
	case <-time.After(time.Second):
		t.Fatal("preflight never started")
	}
	cancel()
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("shutdown left client open")
	}
	_, opens, _ := f.snapshot()
	if len(opens) != 0 {
		t.Fatal("shutdown opened a stream")
	}
}
