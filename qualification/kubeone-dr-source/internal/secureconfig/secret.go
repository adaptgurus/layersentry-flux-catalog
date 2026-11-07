package secureconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxSecretBytes int64 = 64 << 10

// RequiredEnvOrFile accepts either NAME or NAME_FILE, never both. File-backed
// secrets must come from a protected regular file below protected real
// directories. Group read is allowed for a dedicated service group; group
// write and all world permissions are rejected.
func RequiredEnvOrFile(name string) (string, error) {
	value, ok, err := EnvOrFile(name)
	if err != nil {
		return "", err
	}
	if !ok || value == "" {
		return "", fmt.Errorf("%s or %s_FILE is required", name, name)
	}
	return value, nil
}

// OptionalEnvOrFile returns (value,true,nil) when NAME or NAME_FILE is set.
func OptionalEnvOrFile(name string) (string, bool, error) {
	return EnvOrFile(name)
}

func EnvOrFile(name string) (string, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false, errors.New("secret environment name is required")
	}
	envValue, envSet := os.LookupEnv(name)
	fileName := name + "_FILE"
	path, fileSet := os.LookupEnv(fileName)
	envPresent := envSet && strings.TrimSpace(envValue) != ""
	filePresent := fileSet && strings.TrimSpace(path) != ""
	if envPresent && filePresent {
		return "", false, fmt.Errorf("%s and %s are mutually exclusive", name, fileName)
	}
	if envPresent {
		if strings.IndexByte(envValue, 0) >= 0 {
			return "", false, fmt.Errorf("%s contains NUL", name)
		}
		return envValue, true, nil
	}
	if !filePresent {
		return "", false, nil
	}
	value, err := readProtected(path)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", fileName, err)
	}
	return value, true, nil
}

func protectedSecretParent(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if info.Mode().Perm()&0o022 == 0 {
		return true
	}
	// Root-owned sticky directories such as /tmp protect entries owned by
	// other users from rename/unlink while still permitting temporary roots.
	if info.Mode()&os.ModeSticky != 0 {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
			return true
		}
	}
	return false
}

func readProtected(path string) (string, error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("secret path must be absolute and canonical")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		parentInfo, err := os.Lstat(parent)
		if err != nil {
			return "", fmt.Errorf("secret parent: %w", err)
		}
		if !protectedSecretParent(parentInfo) {
			return "", errors.New("secret parent directories must be protected real directories")
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("secret must be a regular non-symlink file")
	}
	if before.Mode().Perm()&0o027 != 0 {
		return "", errors.New("secret file must not be group-writable or accessible by other users")
	}
	if before.Size() < 1 || before.Size() > maxSecretBytes {
		return "", errors.New("secret file size is invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return "", errors.New("secret file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil || int64(len(raw)) > maxSecretBytes {
		return "", errors.New("secret read failed or exceeded size limit")
	}
	if strings.IndexByte(string(raw), 0) >= 0 {
		return "", errors.New("secret contains NUL")
	}
	value := string(raw)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value == "" {
		return "", errors.New("secret is empty")
	}
	return value, nil
}
