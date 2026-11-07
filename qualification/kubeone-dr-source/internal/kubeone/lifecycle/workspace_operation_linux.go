//go:build linux

package lifecycle

import (
	"os"

	"github.com/layersentry/layersentry-platform/internal/kubeone/workspaceproof"
	"golang.org/x/sys/unix"
)

const workspaceOperationLockName = ".layersentry-workspace-operation.lock"

type workspaceOperationLock struct{ file *os.File }

// The same held lock is used by the workspace successor and provisioning.
// It survives the HTTP handler lifetime while the existing native apply runs,
// preventing a second Portal process from relying on a process-local mutex.
func acquireWorkspaceOperation(dir *os.File, uid, gid uint32) (*workspaceOperationLock, error) {
	if dir == nil || uint32(os.Geteuid()) != uid || uint32(os.Getegid()) != gid {
		return nil, workspaceproof.ErrAdmission
	}
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uid || parent.Gid != gid || parent.Mode&07777 != 0700 {
		return nil, workspaceproof.ErrAdmission
	}
	fd, e := unix.Openat(int(dir.Fd()), workspaceOperationLockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	created := e == nil
	if e == unix.EEXIST {
		fd, e = unix.Openat(int(dir.Fd()), workspaceOperationLockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if e != nil {
		return nil, workspaceproof.ErrAdmission
	}
	f := os.NewFile(uintptr(fd), workspaceOperationLockName)
	fail := func() (*workspaceOperationLock, error) { _ = f.Close(); return nil, workspaceproof.ErrAdmission }
	var st, entry unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uid || st.Gid != gid || st.Nlink != 1 || st.Size != 0 {
		return fail()
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail()
	}
	if unix.Fstatat(int(dir.Fd()), workspaceOperationLockName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || entry.Dev != st.Dev || entry.Ino != st.Ino || entry.Nlink != 1 || entry.Mode != st.Mode || entry.Uid != uid || entry.Gid != gid || entry.Size != 0 {
		return fail()
	}
	if created && (f.Sync() != nil || dir.Sync() != nil) {
		return fail()
	}
	return &workspaceOperationLock{file: f}, nil
}

func (l *workspaceOperationLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	// Closing the last descriptor releases the flock. The persistent inode is
	// never unlinked, avoiding a second lock namespace across process restarts.
	return f.Close()
}
