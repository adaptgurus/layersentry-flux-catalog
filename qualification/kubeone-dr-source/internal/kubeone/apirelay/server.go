package apirelay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const maxConnections = 32

type transport interface {
	Probe(context.Context, string, string) error
	Open(context.Context, string, string) (io.ReadWriteCloser, error)
}

type Server struct {
	profile     siteProfile
	credentials Credentials
	transport   transport
	peerMu      sync.Mutex
	avoidPeer   string
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.profile.destination == "" || !privateToken(cfg.credentials.Username) || !privateToken(cfg.credentials.Password) {
		return nil, errors.New("relay configuration was not admitted")
	}
	return &Server{profile: cfg.profile, credentials: cfg.credentials, transport: &sshTransport{key: cfg.SSHPrivateKey, pins: cfg.KnownHosts}}, nil
}

func (s *Server) peerOrder() []string {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	peers := append([]string{}, s.profile.peers...)
	if len(peers) == 2 && peers[0] == s.avoidPeer {
		peers[0], peers[1] = peers[1], peers[0]
	}
	return peers
}

func (s *Server) failedPeer(peer string) {
	s.peerMu.Lock()
	s.avoidPeer = peer
	s.peerMu.Unlock()
}

// Serve accepts only the admitted loopback listener. Each connection owns at
// most one SSH child at a time. Shutdown cancels and reaps all active children.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener.Addr().String() != s.profile.listen {
		return errors.New("relay listener differs from admitted address")
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("relay listener failed")
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-slots }(); s.handle(ctx, conn) }()
		default:
			conn.Close()
		}
	}
}

func exactToken(got, want string) int {
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:])
}

func reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func (s *Server) authorize(conn net.Conn) bool {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 5 || head[1] == 0 {
		return false
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	selected := byte(255)
	for _, method := range methods {
		if method == 2 {
			selected = 2
		}
	}
	if _, err := conn.Write([]byte{5, selected}); err != nil || selected != 2 {
		return false
	}
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 1 || head[1] == 0 {
		return false
	}
	username := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}
	var size [1]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil || size[0] == 0 {
		return false
	}
	password := make([]byte, int(size[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}
	valid := exactToken(string(username), s.credentials.Username) & exactToken(string(password), s.credentials.Password)
	status := byte(1)
	if valid == 1 {
		status = 0
	}
	_, err := conn.Write([]byte{1, status})
	return err == nil && valid == 1
}

func (s *Server) request(conn net.Conn) bool {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return false
	}
	if head != [4]byte{5, 1, 0, 1} {
		_ = reply(conn, 2)
		return false
	}
	var address [6]byte
	if _, err := io.ReadFull(conn, address[:]); err != nil {
		return false
	}
	host, _, _ := net.SplitHostPort(s.profile.destination)
	if !net.IP(address[:4]).Equal(net.ParseIP(host)) || binary.BigEndian.Uint16(address[4:]) != 6443 {
		_ = reply(conn, 2)
		return false
	}
	return true
}

func (s *Server) handle(parent context.Context, conn net.Conn) {
	// Long watches reconnect normally at this bounded lifetime. Authentication,
	// opening, and the first upstream response have much shorter independent bounds.
	ctx, cancel := context.WithTimeout(parent, time.Hour)
	defer cancel()
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if !s.authorize(conn) || !s.request(conn) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var upstream io.ReadWriteCloser
	var selected string
	for _, peer := range s.peerOrder() {
		probeCtx, stop := context.WithTimeout(ctx, 7*time.Second)
		err := s.transport.Probe(probeCtx, peer, s.profile.destination)
		stop()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			continue
		}
		upstream, err = s.transport.Open(ctx, peer, s.profile.destination)
		if err == nil {
			selected = peer
			break
		}
		upstream = nil
	}
	if upstream == nil {
		_ = reply(conn, 4)
		return
	}
	defer upstream.Close()
	if reply(conn, 0) != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	// From this point client bytes may reach Kubernetes. NEVER replay this
	// connection on another peer, including a failure before its first response.
	var responded atomic.Bool
	firstResponse := time.AfterFunc(12*time.Second, func() { s.failedPeer(selected); conn.Close(); upstream.Close() })
	defer firstResponse.Stop()
	finished := make(chan struct{}, 2)
	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); _, _ = io.Copy(upstream, conn); finished <- struct{}{} }()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(conn, &firstRead{Reader: upstream, observed: func() { responded.Store(true); firstResponse.Stop() }})
		finished <- struct{}{}
	}()
	select {
	case <-finished:
	case <-ctx.Done():
	}
	if !responded.Load() && ctx.Err() == nil {
		s.failedPeer(selected)
	}
	conn.Close()
	upstream.Close()
	copies.Wait()
}

type firstRead struct {
	io.Reader
	once     sync.Once
	observed func()
}

func (r *firstRead) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.once.Do(r.observed)
	}
	return n, err
}
