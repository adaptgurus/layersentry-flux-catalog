//go:build linux

package workspaceproof

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenDirectory walks held directory descriptors without following any link.
// Ancestors may belong only to root or the explicitly admitted leaf owner and
// may not be writable by group/other. No path or permission is created here.
func OpenDirectory(path string, uid, gid uint32, mode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrAdmission
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdmission
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		var parent unix.Stat_t
		if unix.Fstat(fd, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || (parent.Uid != 0 && parent.Uid != uid) || parent.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrAdmission
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrAdmission
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrAdmission
		}
		if i == len(parts)-1 && (st.Uid != uid || st.Gid != gid || st.Mode&07777 != mode) {
			unix.Close(fd)
			return nil, ErrAdmission
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func safeLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "/\x00")
}

func sameFileCustody(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// ReadAtDirectory brackets a single bounded regular file and its directory
// entry. Data is returned only after owner/mode/one-link/inode/time agreement.
func ReadAtDirectory(dir *os.File, name string, uid, gid, mode uint32, max int64) ([]byte, error) {
	if dir == nil || !safeLeaf(name) || max < 1 || max > 2<<20 {
		return nil, ErrAdmission
	}
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdmission
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uid || before.Gid != gid || before.Mode&07777 != mode || before.Nlink != 1 || before.Size < 1 || before.Size > max {
		return nil, ErrAdmission
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) != before.Size {
		clear(raw)
		return nil, ErrAdmission
	}
	var after, entry unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(int(dir.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFileCustody(before, after) || !sameFileCustody(before, entry) {
		clear(raw)
		return nil, ErrAdmission
	}
	return raw, nil
}

// DirectoryStillNamed closes the pathname-to-held-directory identity bracket.
func DirectoryStillNamed(dir *os.File, path string, uid, gid, mode uint32) error {
	if dir == nil {
		return ErrAdmission
	}
	current, e := OpenDirectory(path, uid, gid, mode)
	if e != nil {
		return e
	}
	defer current.Close()
	var a, b unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &a) != nil || unix.Fstat(int(current.Fd()), &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid {
		return ErrAdmission
	}
	return nil
}
