package apirelay

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedFilesRejectLooseCustodyAndLinks(t *testing.T) {
	// Use the protected source tree, not a world-writable /tmp ancestor which
	// the runtime correctly rejects regardless of the leaf's permissions.
	dir, err := os.MkdirTemp(".", ".relay-custody-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "credential")
	if err = os.WriteFile(path, []byte("private-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if _, err = protected(path, uid, gid, 0600, 64); err != nil {
		t.Fatalf("protected fixture rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0644, 0640, 0660} {
		if err = os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err = protected(path, uid, gid, 0600, 64); err == nil {
			t.Fatal("nonprivate file admitted")
		}
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = protected(path, uid+1, gid, 0600, 64); err == nil {
		t.Fatal("foreign owner admitted")
	}
	if _, err = protected(path, uid, gid, 0600, 2); err == nil {
		t.Fatal("oversized file admitted")
	}
	symlink := filepath.Join(dir, "symlink")
	if err = os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err = protected(symlink, uid, gid, 0600, 64); err == nil {
		t.Fatal("symlink admitted")
	}
	hardlink := filepath.Join(dir, "hardlink")
	if err = os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err = protected(path, uid, gid, 0600, 64); err == nil {
		t.Fatal("multiply-linked credential admitted")
	}
	if err = os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = protected(path, uid, gid, 0600, 64); err == nil {
		t.Fatal("writable parent admitted")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyCompleteExactNativePinsAreAdmitted(t *testing.T) {
	p, err := profileFor("dc")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 51)
	binary.BigEndian.PutUint32(key[:4], 11)
	copy(key[4:15], "ssh-ed25519")
	binary.BigEndian.PutUint32(key[15:19], 32)
	line := func(peer string) string {
		return peer + " ssh-ed25519 " + base64.StdEncoding.EncodeToString(key) + "\n"
	}
	valid := line(p.peers[0]) + line(p.peers[1])
	if err = validatePins([]byte(valid), p.peers); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{line(p.peers[0]), valid + line(p.peers[0]), line(p.peers[0]) + line("foreign"), strings.ReplaceAll(valid, "ssh-ed25519 ", "ssh-rsa "), strings.ReplaceAll(valid, base64.StdEncoding.EncodeToString(key), "eA==")} {
		if validatePins([]byte(bad), p.peers) == nil {
			t.Fatal("foreign, incomplete or malformed pins admitted")
		}
	}
}

func TestConfigAndCredentialsFailClosed(t *testing.T) {
	for _, site := range []string{"", "DC", "foreign", "dc;command", "dr"} {
		if _, err := profileFor(site); err == nil {
			t.Fatalf("unqualified site %q admitted", site)
		}
	}
	for _, raw := range []string{`{"site":"dc","unexpected":true}`, `{"site":"dc"} {}`, `{`} {
		if decode([]byte(raw), new(Config)) == nil {
			t.Fatal("ambiguous config admitted")
		}
	}
	for _, token := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 129), strings.Repeat("a", 31) + ":"} {
		if privateToken(token) {
			t.Fatal("invalid credential token admitted")
		}
	}
	if !privateToken(strings.Repeat("b7", 32)) {
		t.Fatal("generated hex credential rejected")
	}
}
