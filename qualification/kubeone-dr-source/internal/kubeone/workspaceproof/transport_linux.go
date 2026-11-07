//go:build linux

package workspaceproof

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const SocketPath = "/run/layersentry-kubeone-workspace-observer/observer.sock"
const CallerID = 9869

// ExecutablePeer is independently configured on the other side of the socket.
// Root credentials alone do not establish the admitted executable identity.
type ExecutablePeer struct {
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func (p ExecutablePeer) validate() error {
	if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || !canonicalHex(p.SHA256, 64) {
		return ErrAdmission
	}
	return nil
}

type peerSample struct {
	pid   int32
	ticks string
}

func processBirth(pid int32) (string, error) {
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if e != nil || len(raw) > 8192 {
		return "", ErrAdmission
	}
	i := strings.LastIndexByte(string(raw), ')')
	if i < 0 {
		return "", ErrAdmission
	}
	fields := strings.Fields(string(raw[i+1:]))
	if len(fields) < 20 {
		return "", ErrAdmission
	}
	n, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil || n == 0 {
		return "", ErrAdmission
	}
	return fields[19], nil
}

func executableCustody(pid int32, p ExecutablePeer) (peerSample, error) {
	if p.validate() != nil || pid < 2 {
		return peerSample{}, ErrAdmission
	}
	birth, e := processBirth(pid)
	if e != nil {
		return peerSample{}, e
	}
	path := "/proc/" + strconv.Itoa(int(pid)) + "/exe"
	name, e := os.Readlink(path)
	if e != nil || name != p.Path {
		return peerSample{}, ErrAdmission
	}
	f, e := os.Open(path)
	if e != nil {
		return peerSample{}, ErrAdmission
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Size < 1 || st.Size > 128<<20 {
		return peerSample{}, ErrAdmission
	}
	raw, e := io.ReadAll(io.LimitReader(f, 128<<20+1))
	if e != nil || int64(len(raw)) != st.Size || Digest(raw) != p.SHA256 {
		return peerSample{}, ErrAdmission
	}
	var after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &after) != nil || st.Dev != after.Dev || st.Ino != after.Ino || st.Mode != after.Mode || st.Uid != after.Uid || st.Gid != after.Gid || st.Nlink != after.Nlink || st.Size != after.Size || st.Mtim != after.Mtim || st.Ctim != after.Ctim {
		return peerSample{}, ErrAdmission
	}
	current, e := processBirth(pid)
	if e != nil || current != birth {
		return peerSample{}, ErrAdmission
	}
	return peerSample{pid, birth}, nil
}

func checkPeer(c *net.UnixConn, p ExecutablePeer) (peerSample, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return peerSample{}, ErrAdmission
	}
	var cred *unix.Ucred
	var failure error
	if raw.Control(func(fd uintptr) { cred, failure = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || failure != nil || cred == nil || cred.Uid != p.UID || cred.Gid != p.GID {
		return peerSample{}, ErrAdmission
	}
	return executableCustody(cred.Pid, p)
}

// socketCustody requires explicit prior owner setup. It never creates parents,
// follows a symlink, replaces a stale socket, or changes ancestor permissions.
func socketCustody(path string, present bool) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, e := os.Lstat(dir)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrAdmission
		}
		var stat unix.Stat_t
		if unix.Lstat(dir, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
			return ErrAdmission
		}
		if dir == filepath.Dir(path) && (stat.Gid != CallerID || stat.Mode&07777 != 0750) {
			return ErrAdmission
		}
		if dir == "/" {
			break
		}
	}
	var st unix.Stat_t
	e := unix.Lstat(path, &st)
	if !present {
		if e == unix.ENOENT {
			return nil
		}
		return ErrAdmission
	}
	if e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 || st.Gid != CallerID || st.Mode&07777 != 0660 || st.Nlink != 1 {
		return ErrAdmission
	}
	return nil
}

func writeFrame(w io.Writer, v any) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > MaxProtocolBytes {
		return ErrAdmission
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
	for _, b := range [][]byte{length[:], raw} {
		for len(b) > 0 {
			n, e := w.Write(b)
			if e != nil || n == 0 {
				return ErrAdmission
			}
			b = b[n:]
		}
	}
	return nil
}

func readFrame(r io.Reader, v any) error {
	var length [4]byte
	if _, e := io.ReadFull(r, length[:]); e != nil {
		return ErrAdmission
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > MaxProtocolBytes {
		return ErrAdmission
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return ErrAdmission
	}
	return DecodeCanonical(raw, v)
}

type Client struct {
	Server     ExecutablePeer
	Deployment DeploymentIdentity
}

// Observe performs only authenticated local read-only observation. Callers must
// validate the returned response again at the actual publication boundary.
func (c Client) Observe(ctx context.Context, r Request, e Expected) (Response, error) {
	if c.Server.UID != 0 || c.Server.GID != 0 || c.Server.validate() != nil || r.Validate() != nil || e.Validate() != nil || c.Server.SHA256 != e.ExecutableSHA256 || c.Deployment.SourceCommit != e.SourceCommit || c.Deployment.HostUUID != e.HostUUID || c.Deployment.BootID != e.BootID || checkInstalledAttribution(c.Server, c.Deployment) != nil || socketCustody(SocketPath, true) != nil {
		return Response{}, ErrAdmission
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return Response{}, ErrAdmission
	}
	defer conn.Close()
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return Response{}, ErrAdmission
	}
	deadline := time.Now().Add(120 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	if u.SetDeadline(deadline) != nil {
		return Response{}, ErrAdmission
	}
	before, err := readObserverAttribution(c.Server, c.Deployment, r.ProfileSHA256)
	if err != nil || checkAttributedPeer(u, before.receipt) != nil {
		return Response{}, ErrAdmission
	}
	if writeFrame(u, r) != nil {
		return Response{}, ErrAdmission
	}
	var frame attributedResponse
	if readFrame(u, &frame) != nil {
		return Response{}, ErrAdmission
	}
	after, err := readObserverAttribution(c.Server, c.Deployment, r.ProfileSHA256)
	if err != nil || before.receipt != after.receipt || before.rawSHA != after.rawSHA || !sameFileCustody(before.stat, after.stat) || frame.StartupNonce != before.receipt.StartupNonce || checkAttributedPeer(u, after.receipt) != nil || checkInstalledAttribution(c.Server, c.Deployment) != nil || ValidateResponse(r, frame.Observation, e, time.Now().UTC()) != nil {
		return Response{}, ErrAdmission
	}
	return frame.Observation, nil
}

type Observer interface {
	ObserveWorkspace(context.Context, Request) (Response, error)
}

type Server struct {
	Caller        ExecutablePeer
	Self          ExecutablePeer
	ProfileSHA256 string
	Observer      Observer
	Deployment    DeploymentIdentity
}

// Serve is the explicit privileged readonly qualification mode. No native or
// workspace lifecycle requests are accepted. Existing socket custody is never
// adopted or unlinked, including after shutdown.
func (s Server) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 || s.Observer == nil || s.Caller.UID != CallerID || s.Caller.GID != CallerID || s.Caller.validate() != nil || s.Self.UID != 0 || s.Self.GID != 0 || !canonicalHex(s.ProfileSHA256, 64) {
		return ErrAdmission
	}
	if _, e := executableCustody(int32(os.Getpid()), s.Self); e != nil {
		return e
	}
	if checkInstalledAttribution(s.Self, s.Deployment) != nil || socketCustody(SocketPath, false) != nil {
		return ErrAdmission
	}
	if _, e := os.Lstat(AttributionPath); !os.IsNotExist(e) {
		return ErrAdmission
	}
	host, e := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if e != nil || strings.TrimSpace(string(host)) != s.Deployment.HostUUID {
		return ErrAdmission
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != s.Deployment.BootID {
		return ErrAdmission
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if e != nil {
		return ErrAdmission
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if os.Chown(SocketPath, 0, CallerID) != nil || os.Chmod(SocketPath, 0660) != nil || socketCustody(SocketPath, true) != nil {
		return ErrAdmission
	}
	sample, e := executableCustody(int32(os.Getpid()), s.Self)
	if e != nil {
		return e
	}
	var sock unix.Stat_t
	if unix.Lstat(SocketPath, &sock) != nil {
		return ErrAdmission
	}
	nonce, e := NewRequest(s.ProfileSHA256, Prepublication)
	if e != nil {
		return e
	}
	attribution := ObserverAttribution{Version: 1, ProfileSHA256: s.ProfileSHA256, SourceCommit: s.Deployment.SourceCommit, BuildIdentitySHA256: s.Deployment.BuildIdentitySHA256, ExecutableSHA256: s.Self.SHA256, ExecutablePath: s.Self.Path, PID: sample.pid, StartTicks: sample.ticks, SocketDevice: uint64(sock.Dev), SocketInode: sock.Ino, HostUUID: s.Deployment.HostUUID, BootID: s.Deployment.BootID, StartupNonce: nonce.Nonce, StartedAt: time.Now().UTC()}
	if validateAttribution(attribution, s.Self, s.Deployment, s.ProfileSHA256, time.Now().UTC()) != nil || publishObserverAttribution(attribution) != nil {
		return ErrAdmission
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		c, e := listener.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrAdmission
		}
		// Serial requests bound privileged resource use and prevent overlapping
		// QGA observations from this owner. Rejections contain no native errors.
		_ = s.serveConnection(ctx, c, attribution)
		_ = c.Close()
	}
}

func (s Server) serveConnection(parent context.Context, c *net.UnixConn, a ObserverAttribution) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if c.SetDeadline(deadline) != nil {
		return ErrAdmission
	}
	if e := s.checkSelfAttribution(a); e != nil {
		return e
	}
	before, e := checkPeer(c, s.Caller)
	if e != nil || workspaceOperationHeldBy(before.pid) != nil {
		return ErrAdmission
	}
	var r Request
	if readFrame(c, &r) != nil || r.Validate() != nil || r.ProfileSHA256 != s.ProfileSHA256 {
		return ErrAdmission
	}
	response, e := s.Observer.ObserveWorkspace(ctx, r)
	if e != nil {
		return ErrAdmission
	}
	after, e := checkPeer(c, s.Caller)
	if e != nil || after != before || workspaceOperationHeldBy(after.pid) != nil {
		return ErrAdmission
	}
	return writeAttributedObservation(c, a, response, func() error { return s.checkSelfAttribution(a) })
}

// The response belongs to the same protected startup attribution observed
// before the request. Recheck its full socket/receipt/artifact custody after
// the potentially lengthy native observation and before emitting any frame.
func writeAttributedObservation(w io.Writer, a ObserverAttribution, response Response, current func() error) error {
	if current == nil || current() != nil {
		return ErrAdmission
	}
	return writeFrame(w, attributedResponse{StartupNonce: a.StartupNonce, Observation: response})
}

func (s Server) checkSelfAttribution(a ObserverAttribution) error {
	p, e := executableCustody(int32(os.Getpid()), s.Self)
	if e != nil || p.pid != a.PID || p.ticks != a.StartTicks || checkInstalledAttribution(s.Self, s.Deployment) != nil {
		return ErrAdmission
	}
	x, e := readObserverAttribution(s.Self, s.Deployment, s.ProfileSHA256)
	if e != nil || x.receipt != a || socketCustody(SocketPath, true) != nil {
		return ErrAdmission
	}
	var st unix.Stat_t
	if unix.Lstat(SocketPath, &st) != nil || uint64(st.Dev) != a.SocketDevice || st.Ino != a.SocketInode {
		return ErrAdmission
	}
	return nil
}
