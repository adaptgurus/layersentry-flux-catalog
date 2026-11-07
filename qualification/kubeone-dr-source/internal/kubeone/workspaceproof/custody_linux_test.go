//go:build linux

package workspaceproof

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestHeldFileReadRejectsSpecialBitsLinksAndUnknownOwner(t *testing.T) {
	path := t.TempDir()
	d, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	p := filepath.Join(path, "record")
	if os.WriteFile(p, []byte("public"), 0600) != nil {
		t.Fatal("fixture")
	}
	if b, e := ReadAtDirectory(d, "record", uid, gid, 0600, 128); e != nil || string(b) != "public" {
		t.Fatal("exact record", e)
	}
	for _, bits := range []uint32{01000, 02000, 04000} {
		if unix.Chmod(p, 0600|bits) != nil {
			t.Fatal("mode")
		}
		if _, e := ReadAtDirectory(d, "record", uid, gid, 0600, 128); e == nil {
			t.Fatal("special bits accepted")
		}
	}
	if unix.Chmod(p, 0600) != nil {
		t.Fatal("mode")
	}
	if _, e := ReadAtDirectory(d, "record", uid+1, gid, 0600, 128); e == nil {
		t.Fatal("foreign owner")
	}
	if os.Link(p, filepath.Join(path, "alias")) != nil {
		t.Fatal("hardlink")
	}
	if _, e := ReadAtDirectory(d, "record", uid, gid, 0600, 128); e == nil {
		t.Fatal("hardlink")
	}
	if os.Remove(filepath.Join(path, "alias")) != nil || os.Symlink(p, filepath.Join(path, "symlink")) != nil {
		t.Fatal("symlink fixture")
	}
	if _, e := ReadAtDirectory(d, "symlink", uid, gid, 0600, 128); e == nil {
		t.Fatal("followed symlink")
	}
	if _, e := ReadAtDirectory(d, "../record", uid, gid, 0600, 128); e == nil {
		t.Fatal("traversal")
	}
}

func TestProtectedDirectoryRejectsSpecialBitsAndReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned ancestor fixture")
	}
	root, e := os.MkdirTemp("/root", "workspace-custody-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	p := filepath.Join(root, "workspace")
	if os.Mkdir(p, 0700) != nil {
		t.Fatal("mkdir")
	}
	d, e := OpenDirectory(p, 0, 0, 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, bits := range []uint32{01000, 02000, 04000} {
		if unix.Chmod(p, 0700|bits) != nil {
			t.Fatal("mode")
		}
		if x, e := OpenDirectory(p, 0, 0, 0700); e == nil {
			x.Close()
			t.Fatal("special directory bits accepted")
		}
	}
	if unix.Chmod(p, 0700) != nil {
		t.Fatal("mode")
	}
	if os.Rename(p, p+".old") != nil || os.Mkdir(p, 0700) != nil {
		t.Fatal("replace")
	}
	if DirectoryStillNamed(d, p, 0, 0, 0700) == nil {
		t.Fatal("held inode renamed/replaced")
	}
}
