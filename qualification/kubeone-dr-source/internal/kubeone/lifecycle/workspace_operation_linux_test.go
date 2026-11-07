//go:build linux

package lifecycle

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWorkspaceOperationSerializesSeparateOpenDescriptions(t *testing.T) {
	path := t.TempDir()
	if e := os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	dir, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	one, e := acquireWorkspaceOperation(dir, uid, gid)
	if e != nil {
		t.Fatal(e)
	}
	otherDir, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer otherDir.Close()
	if two, e := acquireWorkspaceOperation(otherDir, uid, gid); e == nil {
		two.Close()
		t.Fatal("concurrent owner acquired lock")
	}
	before, e := os.Stat(filepath.Join(path, workspaceOperationLockName))
	if e != nil {
		t.Fatal(e)
	}
	if one.Close() != nil {
		t.Fatal("close")
	}
	two, e := acquireWorkspaceOperation(otherDir, uid, gid)
	if e != nil {
		t.Fatal(e)
	}
	defer two.Close()
	after, e := os.Stat(filepath.Join(path, workspaceOperationLockName))
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("lock inode replaced")
	}
}

func TestWorkspaceOperationRejectsForeignLockCustody(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "wrong-mode", "nonempty", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, workspaceOperationLockName)
			target := filepath.Join(root, "other")
			if kind == "directory" {
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.WriteFile(target, []byte{}, 0600); e != nil {
					t.Fatal(e)
				}
				switch kind {
				case "symlink":
					if e := os.Symlink(target, path); e != nil {
						t.Fatal(e)
					}
				case "hardlink":
					if e := os.Link(target, path); e != nil {
						t.Fatal(e)
					}
				case "wrong-mode":
					if e := os.WriteFile(path, nil, 0644); e != nil {
						t.Fatal(e)
					}
					// WriteFile applies umask; force the deliberately invalid mode
					// so a restrictive runner cannot turn this into a valid fixture.
					if e := os.Chmod(path, 0644); e != nil {
						t.Fatal(e)
					}
					if st, e := os.Stat(path); e != nil || st.Mode().Perm() != 0644 {
						t.Fatalf("invalid lock-mode fixture: %v", e)
					}
				case "nonempty":
					if e := os.WriteFile(path, []byte("foreign"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			dir, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			if lock, e := acquireWorkspaceOperation(dir, uint32(os.Geteuid()), uint32(os.Getegid())); e == nil {
				lock.Close()
				t.Fatal("foreign lock adopted")
			}
		})
	}
}

func TestWorkspaceOperationCrossProcessAndRestart(t *testing.T) {
	if path := os.Getenv("LS_TEST_WORKSPACE_LOCK_CHILD"); path != "" {
		d, e := os.Open(path)
		if e != nil {
			os.Exit(3)
		}
		defer d.Close()
		l, e := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid()))
		if e != nil {
			os.Exit(2)
		}
		l.Close()
		os.Exit(0)
	}
	path := t.TempDir()
	if os.Chmod(path, 0700) != nil {
		t.Fatal("mode")
	}
	d, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	l, e := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid()))
	if e != nil {
		t.Fatal(e)
	}
	child := func() int {
		c := exec.Command(os.Args[0], "-test.run=^TestWorkspaceOperationCrossProcessAndRestart$")
		c.Env = append(os.Environ(), "LS_TEST_WORKSPACE_LOCK_CHILD="+path)
		e := c.Run()
		if e == nil {
			return 0
		}
		if x, ok := e.(*exec.ExitError); ok {
			return x.ExitCode()
		}
		t.Fatal(e)
		return -1
	}
	if child() != 2 {
		t.Fatal("independent process bypassed held operation")
	}
	if l.Close() != nil {
		t.Fatal("close")
	}
	if child() != 0 {
		t.Fatal("new process could not reuse persistent lock inode after release")
	}
}
func TestWorkspaceOperationRejectsSpecialPermissionBits(t *testing.T) {
	for _, bits := range []uint32{01000, 02000, 04000} {
		path := t.TempDir()
		if unix.Chmod(path, 0700|bits) != nil {
			t.Fatal("chmod")
		}
		d, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		if l, e := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid())); e == nil {
			l.Close()
			t.Fatal("special directory bits admitted")
		}
		d.Close()
		if unix.Chmod(path, 0700) != nil {
			t.Fatal("chmod")
		}
		f := filepath.Join(path, workspaceOperationLockName)
		if os.WriteFile(f, nil, 0600) != nil || unix.Chmod(f, 0600|bits) != nil {
			t.Fatal("lock fixture")
		}
		d, e = os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		if l, e := acquireWorkspaceOperation(d, uint32(os.Geteuid()), uint32(os.Getegid())); e == nil {
			l.Close()
			t.Fatal("special lock bits admitted")
		}
		d.Close()
	}
}
