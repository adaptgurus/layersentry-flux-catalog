package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDRControllerLeaseDetectsReplacedWorkspaceDirectory(t *testing.T) {
	x := setupDRExecutionFixture(t)
	first, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal("failed to acquire original local lease", err)
	}
	defer first.Close()
	if err := first.Check(x.ws); err != nil {
		t.Fatal("stable original lease rejected", err)
	}
	prior := x.ws.Directory + "-old"
	if err := os.Rename(x.ws.Directory, prior); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(x.ws.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	// A second local flock may be acquired on an entirely NEW inode.
	// That is the RED independent-owner reproduction and why real HA
	// still requires native Kubernetes distributed Lease + witness.
	second, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal("replaced local directory was not independently lockable", err)
	}
	defer second.Close()
	if err := first.Check(x.ws); err == nil {
		t.Fatal("old coordinator kept running after its lock directory was replaced")
	}
	if err := second.Check(x.ws); err != nil {
		t.Fatal("fresh lock in new isolated directory not internally consistent", err)
	}
}

func TestDRControllerLeaseDetectsReplacedLockInSameWorkspace(t *testing.T) {
	x := setupDRExecutionFixture(t)
	first, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	path := filepath.Join(x.ws.Directory, autoDRControllerLockFile)
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := first.Check(x.ws); err == nil {
		t.Fatal("lease no longer points to current lock-file path")
	}
	second, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Check(x.ws); err != nil {
		t.Fatal(err)
	}
}
