package secureconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvOrFileRejectsAmbiguousAndUnsafeInputs(t *testing.T) {
	t.Setenv("LS_TEST_SECRET", "env-secret")
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LS_TEST_SECRET_FILE", path)
	if _, _, err := EnvOrFile("LS_TEST_SECRET"); err == nil {
		t.Fatal("ambiguous secret source accepted")
	}

	t.Setenv("LS_TEST_SECRET", "")
	if err := os.Chmod(path, 0o604); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnvOrFile("LS_TEST_SECRET"); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}

func TestEnvOrFileReadsProtectedFileAndPreservesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	want := "user:pass with spaces"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LS_TEST_SECRET_FILE", path)
	got, ok, err := EnvOrFile("LS_TEST_SECRET")
	if err != nil || !ok || got != want {
		t.Fatalf("got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestRequiredEnvOrFileSupportsEnvironmentCompatibility(t *testing.T) {
	want := strings.Repeat("x", 32)
	t.Setenv("LS_TEST_SECRET", want)
	got, err := RequiredEnvOrFile("LS_TEST_SECRET")
	if err != nil || got != want {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestEnvOrFileRejectsWritableAncestorDirectory(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "writable")
	child := filepath.Join(ancestor, "protected")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(child, "secret")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LS_TEST_SECRET_FILE", path)
	if _, _, err := EnvOrFile("LS_TEST_SECRET"); err == nil {
		t.Fatal("secret below writable ancestor was accepted")
	}
}

func TestEnvOrFileRejectsSymlinkAncestorDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real", "protected")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "protected", "secret")
	if err := os.WriteFile(filepath.Join(realDir, "secret"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LS_TEST_SECRET_FILE", path)
	if _, _, err := EnvOrFile("LS_TEST_SECRET"); err == nil {
		t.Fatal("secret below symlink ancestor was accepted")
	}
}
