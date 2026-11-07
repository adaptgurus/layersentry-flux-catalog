//go:build linux

package workspaceproof

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const operationWorkspace = "/var/lib/layersentry/kubeone/lab-dc/kubeone-dc"
const operationLockName = ".layersentry-workspace-operation.lock"

// The root observer verifies that the authenticated Portal process holds the
// same existing operation lock used by publication and provisioning. Merely
// finding a lock file or an unrelated contender is not native owner authority.
func workspaceOperationHeldBy(pid int32) error {
	d, e := OpenDirectory(operationWorkspace, CallerID, CallerID, 0700)
	if e != nil {
		return ErrAdmission
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), operationLockName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrAdmission
	}
	defer unix.Close(fd)
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != CallerID || before.Gid != CallerID || before.Nlink != 1 || before.Size != 0 {
		return ErrAdmission
	}
	raw, e := readKernelOperationLocks()
	if e != nil || workspaceOperationLockOwner(raw, pid, before) != nil {
		return ErrAdmission
	}
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(int(d.Fd()), operationLockName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFileCustody(before, after) || !sameFileCustody(before, named) || DirectoryStillNamed(d, operationWorkspace, CallerID, CallerID, 0700) != nil {
		return ErrAdmission
	}
	return nil
}
func readKernelOperationLocks() ([]byte, error) {
	f, e := os.Open("/proc/locks")
	if e != nil {
		return nil, ErrAdmission
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, ErrAdmission
	}
	return b, nil
}
func workspaceOperationLockOwner(raw []byte, pid int32, st unix.Stat_t) error {
	if pid <= 1 || len(raw) > 1<<20 || st.Ino == 0 {
		return ErrAdmission
	}
	found := 0
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			continue
		}
		waiting := len(fields) > 1 && fields[1] == "->"
		if waiting {
			fields = append(fields[:1], fields[2:]...)
		}
		if len(fields) != 8 {
			return ErrAdmission
		}
		dev := strings.Split(fields[5], ":")
		if len(dev) != 3 {
			return ErrAdmission
		}
		major, e1 := strconv.ParseUint(dev[0], 16, 32)
		minor, e2 := strconv.ParseUint(dev[1], 16, 32)
		inode, e3 := strconv.ParseUint(dev[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			return ErrAdmission
		}
		if major != uint64(unix.Major(uint64(st.Dev))) || minor != uint64(unix.Minor(uint64(st.Dev))) || inode != st.Ino {
			continue
		}
		// Waiters do not hold the inode; an exact held FLOCK by the kernel peer is
		// mandatory. Other lock types/modes/owners on this inode are ambiguous.
		if waiting {
			continue
		}
		if fields[1] != "FLOCK" || fields[2] != "ADVISORY" || fields[3] != "WRITE" || fields[4] != strconv.FormatInt(int64(pid), 10) || fields[6] != "0" || fields[7] != "EOF" {
			return ErrAdmission
		}
		found++
	}
	if found != 1 {
		return ErrAdmission
	}
	return nil
}
