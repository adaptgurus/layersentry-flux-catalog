package testgateway

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const passwordScheme = "pbkdf2-sha256-600000/v1"
const stepUpAttempts = 32

// StepUpVerifier contains no plaintext password. The client certificate and
// password are enrolled for the SAME fixed test subscriber, not a node identity.
type StepUpVerifier struct {
	Scheme string `json:"scheme"`
	Salt   string `json:"salt"`
	Digest string `json:"digest"`
}

func (v *StepUpVerifier) validate() error {
	if v == nil {
		return nil
	}
	if v.Scheme != passwordScheme {
		return errors.New("unrecognized test password scheme")
	}
	for _, s := range []string{v.Salt, v.Digest} {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 || strings.ToLower(s) != s || s == strings.Repeat("0", 64) {
			return errors.New("invalid test password verifier")
		}
	}
	return nil
}

func validTestPassword(p []byte) bool {
	if len(p) < 32 || len(p) > 128 {
		return false
	}
	for _, c := range p {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// BootstrapWithPasswordFile explicitly enrolls the independent knowledge factor.
// The root-custodied input must be outside the NEW gateway directory; it is never
// copied into the gateway root or returned/logged. Operator custody/distribution
// of that credential is distinct from deployment of the verifier.
func BootstrapWithPasswordFile(path string, c Config, passwordFile string) error {
	if !filepath.IsAbs(passwordFile) || filepath.Clean(passwordFile) != passwordFile || passwordFile == path || strings.HasPrefix(passwordFile, path+string(os.PathSeparator)) {
		return errors.New("separate canonical private password file required")
	}
	input, err := Open(filepath.Dir(passwordFile))
	if err != nil {
		return err
	}
	defer input.Close()
	p, err := readPrivate(input, filepath.Base(passwordFile))
	if err != nil {
		return err
	}
	defer clear(p)
	if !validTestPassword(p) {
		return errors.New("test password must be 32-128 printable non-space ASCII bytes; use an independently generated random password")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	digest, err := pbkdf2.Key(sha256.New, string(p), salt, 600000, 32)
	if err != nil {
		return err
	}
	c.StepUp = &StepUpVerifier{Scheme: passwordScheme, Salt: hex.EncodeToString(salt), Digest: hex.EncodeToString(digest)}
	return Bootstrap(path, c)
}

// reserveStepUpAttempt fails closed across gateway restarts and competing
// processes. Every password verification consumes one of 32 durable slots,
// including successful ones. No automatic unlock/reset or password fallback.
func reserveStepUpAttempt(root *os.Root) error {
	for i := 0; i < stepUpAttempts; i++ {
		err := writeNew(root, fmt.Sprintf("stepup-attempt-%02d", i), []byte("TEST_ONLY verification attempt\n"))
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		d, err := root.Open(".")
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	if err := Revoke(root); err != nil {
		return err
	}
	return errors.New("test step-up budget exhausted; enrollment revoked")
}

func verifyPassword(root *os.Root, c Config, r *http.Request) bool {
	if err := reserveStepUpAttempt(root); err != nil {
		return false
	}
	if len(r.Header.Values("Authorization")) != 1 {
		return false
	}
	user, password, ok := r.BasicAuth()
	if !ok || user != c.User || !validTestPassword([]byte(password)) {
		return false
	}
	salt, _ := hex.DecodeString(c.StepUp.Salt)
	want, _ := hex.DecodeString(c.StepUp.Digest)
	got, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return false
	}
	defer clear(got)
	return subtle.ConstantTimeCompare(got, want) == 1
}
