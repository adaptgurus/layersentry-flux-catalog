// Package apirelay provides the bounded, private qualification API transport.
package apirelay

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Site            string `json:"site"`
	ListenAddress   string `json:"listen_address"`
	SSHPrivateKey   string `json:"ssh_private_key"`
	KnownHosts      string `json:"known_hosts"`
	CredentialsFile string `json:"credentials"`
	credentials     Credentials
	profile         siteProfile
}

type siteProfile struct {
	destination, listen, workspace string
	peers                          []string
}

func profileFor(site string) (siteProfile, error) {
	switch site {
	case "dc":
		return siteProfile{"10.254.200.10:6443", "127.0.0.1:19446", "/var/lib/layersentry/kubeone/lab-dc/kubeone-dc", []string{"10.254.60.97", "10.254.60.98"}}, nil
	default:
		return siteProfile{}, errors.New("relay site lacks an approved fixed transport profile")
	}
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid relay document")
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("relay document must contain one object")
	}
	return nil
}

func privateToken(value string) bool {
	if len(value) < 32 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Protected files and every parent must remain in the root/service custody
// boundary. Errors deliberately exclude document contents and credential paths.
func protected(path string, uid, gid uint32, mode os.FileMode, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid protected relay path")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		s, err := os.Lstat(dir)
		if err != nil {
			return nil, errors.New("relay parent unavailable")
		}
		n, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || n.Uid != 0 && n.Uid != uid {
			return nil, errors.New("relay parent custody differs")
		}
		if dir == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("protected relay file unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, errors.New("relay file stat failed")
	}
	n, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm() != mode || n.Uid != uid || n.Gid != gid || n.Nlink != 1 || s.Size() < 1 || s.Size() > limit {
		return nil, errors.New("relay file custody differs")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("relay file read failed")
	}
	return raw, nil
}

func validatePins(raw []byte, peers []string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[1] != "ssh-ed25519" || seen[fields[0]] {
			return errors.New("relay pins differ")
		}
		allowed := false
		for _, peer := range peers {
			if fields[0] == peer {
				allowed = true
			}
		}
		key, err := base64.StdEncoding.DecodeString(fields[2])
		if !allowed || err != nil || len(key) != 51 || binary.BigEndian.Uint32(key[:4]) != 11 || string(key[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(key[15:19]) != 32 {
			return errors.New("relay pins differ")
		}
		seen[fields[0]] = true
	}
	if len(seen) != len(peers) {
		return errors.New("relay pins incomplete")
	}
	return nil
}

// LoadConfig is the command's sole admission path. The service runs as oneadmin;
// configuration is root-owned 0640 and referenced workspace files are private.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	u, err := user.Lookup("oneadmin")
	if err != nil {
		return cfg, errors.New("relay service account unavailable")
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil || os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return cfg, errors.New("relay must run as the registered service account")
	}
	raw, err := protected(path, 0, uint32(gid), 0640, 8192)
	if err != nil {
		return cfg, err
	}
	if err = decode(raw, &cfg); err != nil {
		return Config{}, err
	}
	p, err := profileFor(cfg.Site)
	if err != nil {
		return Config{}, err
	}
	if cfg.ListenAddress != p.listen || cfg.SSHPrivateKey != p.workspace+"/ssh-private-key" || cfg.KnownHosts != p.workspace+"/api-relay-known-hosts" || cfg.CredentialsFile != p.workspace+"/api-relay-credentials.json" {
		return Config{}, errors.New("relay configuration differs from fixed site profile")
	}
	if _, err = protected(cfg.SSHPrivateKey, uint32(uid), uint32(gid), 0600, 65536); err != nil {
		return Config{}, err
	}
	pins, err := protected(cfg.KnownHosts, uint32(uid), uint32(gid), 0600, 65536)
	if err != nil {
		return Config{}, err
	}
	if err = validatePins(pins, p.peers); err != nil {
		return Config{}, err
	}
	credential, err := protected(cfg.CredentialsFile, uint32(uid), uint32(gid), 0600, 4096)
	if err != nil {
		return Config{}, err
	}
	if decode(credential, &cfg.credentials) != nil || !privateToken(cfg.credentials.Username) || !privateToken(cfg.credentials.Password) {
		return Config{}, errors.New("invalid relay credential")
	}
	cfg.profile = p
	return cfg, nil
}
