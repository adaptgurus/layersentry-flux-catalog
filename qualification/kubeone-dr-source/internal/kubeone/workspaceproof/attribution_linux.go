//go:build linux

package workspaceproof

import (
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

const AttributionPath = "/run/layersentry-kubeone-workspace-observer/observer.json"
const ObserverExecutable = "/usr/local/libexec/layersentry-native-qualification"
const ObserverBuildPath = ObserverExecutable + ".build.json"

// DeploymentIdentity is supplied by independently reviewed protected deployment
// configuration. The observer does not invent or enroll its own build identity.
type DeploymentIdentity struct {
	SourceCommit        string `json:"source_commit"`
	BuildIdentitySHA256 string `json:"build_identity_sha256"`
	SidecarSHA256       string `json:"sidecar_sha256"`
	HostUUID            string `json:"host_uuid"`
	BootID              string `json:"boot_id"`
}

type BuildAttribution struct {
	Version             int    `json:"version"`
	SourceCommit        string `json:"source_commit"`
	BuildIdentitySHA256 string `json:"build_identity_sha256"`
	ExecutableSHA256    string `json:"executable_sha256"`
}

type ObserverAttribution struct {
	Version             int       `json:"version"`
	ProfileSHA256       string    `json:"observer_profile_sha256"`
	SourceCommit        string    `json:"source_commit"`
	BuildIdentitySHA256 string    `json:"build_identity_sha256"`
	ExecutableSHA256    string    `json:"executable_sha256"`
	ExecutablePath      string    `json:"executable_path"`
	PID                 int32     `json:"pid"`
	StartTicks          string    `json:"start_ticks"`
	SocketDevice        uint64    `json:"socket_device"`
	SocketInode         uint64    `json:"socket_inode"`
	HostUUID            string    `json:"host_uuid"`
	BootID              string    `json:"boot_id"`
	StartupNonce        string    `json:"startup_nonce"`
	StartedAt           time.Time `json:"started_at"`
}

type attributedResponse struct {
	StartupNonce string   `json:"startup_nonce"`
	Observation  Response `json:"observation"`
}

type attributionSample struct {
	receipt ObserverAttribution
	rawSHA  string
	stat    unix.Stat_t
}

func (d DeploymentIdentity) validate() error {
	if !canonicalHex(d.SourceCommit, 40) || !canonicalHex(d.BuildIdentitySHA256, 64) || !canonicalHex(d.SidecarSHA256, 64) || !canonicalUUID(d.HostUUID) || !canonicalUUID(d.BootID) {
		return ErrAdmission
	}
	return nil
}

// Root-owned executable and build sidecar are public metadata. This held-fd
// walk never follows a link and rejects writable/special-bit ancestors.
func readInstalledPublic(path string, mode uint32, max int64) ([]byte, error) {
	if path != ObserverExecutable && path != ObserverBuildPath {
		return nil, ErrAdmission
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdmission
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for _, name := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&07022 != 0 {
			unix.Close(fd)
			return nil, ErrAdmission
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, ErrAdmission
		}
		fd = next
	}
	defer unix.Close(fd)
	var parent unix.Stat_t
	if unix.Fstat(fd, &parent) != nil || parent.Uid != 0 || parent.Gid != 0 || parent.Mode&07022 != 0 {
		return nil, ErrAdmission
	}
	leaf := filepath.Base(path)
	fno, e := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdmission
	}
	f := os.NewFile(uintptr(fno), path)
	defer f.Close()
	var a, b, entry unix.Stat_t
	if unix.Fstat(fno, &a) != nil || a.Mode&unix.S_IFMT != unix.S_IFREG || a.Mode&07777 != mode || a.Uid != 0 || a.Gid != 0 || a.Nlink != 1 || a.Size < 1 || a.Size > max {
		return nil, ErrAdmission
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) != a.Size {
		return nil, ErrAdmission
	}
	if unix.Fstat(fno, &b) != nil || unix.Fstatat(fd, leaf, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFileCustody(a, b) || !sameFileCustody(a, entry) {
		return nil, ErrAdmission
	}
	return raw, nil
}

func checkInstalledAttribution(p ExecutablePeer, d DeploymentIdentity) error {
	if p.UID != 0 || p.GID != 0 || p.Path != ObserverExecutable || p.validate() != nil || d.validate() != nil {
		return ErrAdmission
	}
	raw, e := readInstalledPublic(ObserverExecutable, 0755, 128<<20)
	if e != nil || Digest(raw) != p.SHA256 {
		return ErrAdmission
	}
	raw, e = readInstalledPublic(ObserverBuildPath, 0644, 8192)
	if e != nil || Digest(raw) != d.SidecarSHA256 {
		return ErrAdmission
	}
	var b BuildAttribution
	if DecodeCanonical(raw, &b) != nil || b.Version != 1 || b.SourceCommit != d.SourceCommit || b.BuildIdentitySHA256 != d.BuildIdentitySHA256 || b.ExecutableSHA256 != p.SHA256 {
		return ErrAdmission
	}
	return nil
}

func validateAttribution(a ObserverAttribution, p ExecutablePeer, d DeploymentIdentity, profile string, now time.Time) error {
	ticks, e := strconv.ParseUint(a.StartTicks, 10, 64)
	if d.validate() != nil || p.Path != ObserverExecutable || p.UID != 0 || p.GID != 0 || a.Version != 1 || a.ProfileSHA256 != profile || !canonicalHex(profile, 64) || a.SourceCommit != d.SourceCommit || a.BuildIdentitySHA256 != d.BuildIdentitySHA256 || a.ExecutableSHA256 != p.SHA256 || a.ExecutablePath != p.Path || a.PID < 2 || e != nil || ticks == 0 || strconv.FormatUint(ticks, 10) != a.StartTicks || a.SocketDevice == 0 || a.SocketInode == 0 || a.HostUUID != d.HostUUID || a.BootID != d.BootID || !canonicalHex(a.StartupNonce, 64) || a.StartedAt.IsZero() || a.StartedAt.After(now) {
		return ErrAdmission
	}
	return nil
}

func readObserverAttribution(p ExecutablePeer, d DeploymentIdentity, profile string) (attributionSample, error) {
	dir, e := OpenDirectory(filepath.Dir(AttributionPath), 0, CallerID, 0750)
	if e != nil {
		return attributionSample{}, e
	}
	defer dir.Close()
	var before, after unix.Stat_t
	name := filepath.Base(AttributionPath)
	if unix.Fstatat(int(dir.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return attributionSample{}, ErrAdmission
	}
	raw, e := ReadAtDirectory(dir, name, 0, CallerID, 0640, 8192)
	if e != nil {
		return attributionSample{}, e
	}
	var a ObserverAttribution
	if DecodeCanonical(raw, &a) != nil || validateAttribution(a, p, d, profile, time.Now().UTC()) != nil || unix.Fstatat(int(dir.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFileCustody(before, after) || DirectoryStillNamed(dir, filepath.Dir(AttributionPath), 0, CallerID, 0750) != nil {
		return attributionSample{}, ErrAdmission
	}
	return attributionSample{a, Digest(raw), after}, nil
}

func kernelPeer(c *net.UnixConn) (*unix.Ucred, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return nil, ErrAdmission
	}
	var cred *unix.Ucred
	var fail error
	if raw.Control(func(fd uintptr) { cred, fail = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || fail != nil || cred == nil {
		return nil, ErrAdmission
	}
	return cred, nil
}

func checkAttributedPeer(c *net.UnixConn, a ObserverAttribution) error {
	cred, e := kernelPeer(c)
	if e != nil || cred.Uid != 0 || cred.Gid != 0 || cred.Pid != a.PID {
		return ErrAdmission
	}
	ticks, e := processBirth(cred.Pid)
	if e != nil || ticks != a.StartTicks || socketCustody(SocketPath, true) != nil {
		return ErrAdmission
	}
	var st unix.Stat_t
	if unix.Lstat(SocketPath, &st) != nil || uint64(st.Dev) != a.SocketDevice || st.Ino != a.SocketInode {
		return ErrAdmission
	}
	return nil
}

func publishObserverAttribution(a ObserverAttribution) error {
	dir, e := OpenDirectory(filepath.Dir(AttributionPath), 0, CallerID, 0750)
	if e != nil {
		return e
	}
	defer dir.Close()
	raw, e := json.Marshal(a)
	if e != nil || len(raw) > 8192 {
		return ErrAdmission
	}
	fd, e := unix.Openat(int(dir.Fd()), filepath.Base(AttributionPath), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0640)
	if e != nil {
		return ErrAdmission
	}
	f := os.NewFile(uintptr(fd), AttributionPath)
	defer f.Close()
	if f.Chown(0, CallerID) != nil || f.Chmod(0640) != nil {
		return ErrAdmission
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrAdmission
	}
	if f.Sync() != nil || dir.Sync() != nil || DirectoryStillNamed(dir, filepath.Dir(AttributionPath), 0, CallerID, 0750) != nil {
		return ErrAdmission
	}
	return nil
}
