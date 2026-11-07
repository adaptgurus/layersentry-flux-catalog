//go:build linux

package workspaceproof

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWorkspaceOperationRequiresActualKernelPeerFlock(t *testing.T) {
	f, e := os.OpenFile(filepath.Join(t.TempDir(), "operation.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		t.Fatal("stat")
	}
	pid := int32(os.Getpid())
	raw, e := readKernelOperationLocks()
	if e != nil || workspaceOperationLockOwner(raw, pid, st) == nil {
		t.Fatal("unlocked inode adopted")
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("flock")
	}
	raw, e = readKernelOperationLocks()
	if e != nil || workspaceOperationLockOwner(raw, pid, st) != nil {
		t.Fatal("real kernel process/inode FLOCK rejected", e)
	}
	if workspaceOperationLockOwner(raw, pid+1, st) == nil {
		t.Fatal("different process adopted")
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_UN) != nil {
		t.Fatal("unlock")
	}
	raw, e = readKernelOperationLocks()
	if e != nil || workspaceOperationLockOwner(raw, pid, st) == nil {
		t.Fatal("released ownership persisted")
	}
}
func TestWorkspaceOperationLockGrammarRejectsAmbiguousOwner(t *testing.T) {
	st := unix.Stat_t{Dev: unix.Mkdev(8, 1), Ino: 12345}
	line := "1: FLOCK ADVISORY WRITE 123 08:01:12345 0 EOF\n"
	if workspaceOperationLockOwner([]byte(line), 123, st) != nil {
		t.Fatal("valid")
	}
	for _, bad := range []string{strings.Replace(line, "FLOCK", "POSIX", 1), strings.Replace(line, "WRITE", "READ", 1), strings.Replace(line, " 123 ", " 124 ", 1), strings.Replace(line, " 0 EOF", " 1 EOF", 1), strings.Replace(line, "FLOCK", "-> FLOCK", 1), line + line, strings.Replace(line, ":12345", ":12346", 1), fmt.Sprintf("1: FLOCK ADVISORY WRITE 123 08:01:12345 0 %s\n", "123")} {
		if workspaceOperationLockOwner([]byte(bad), 123, st) == nil {
			t.Fatal("ambiguous ownership accepted", bad)
		}
	}
}
