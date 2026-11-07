package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

type apiProxyCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func readAPIProxyCredentials(path string) (apiProxyCredentials, error) {
	var credential apiProxyCredentials
	fail := func() (apiProxyCredentials, error) {
		return apiProxyCredentials{}, fmt.Errorf("%w: private API relay credential custody differs", ErrValidation)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		parent, err := os.Lstat(dir)
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 {
			return fail()
		}
		native, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || (native.Uid != 0 && native.Uid != uint32(os.Geteuid())) {
			return fail()
		}
		if dir == "/" {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail()
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() == 0 || s.Size() > 4096 {
		return fail()
	}
	native, ok := s.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&credential) != nil {
		return fail()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail()
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9]{32,128}$`)
	if !valid.MatchString(credential.Username) || !valid.MatchString(credential.Password) {
		return fail()
	}
	return credential, nil
}
