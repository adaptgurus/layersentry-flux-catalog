// Package testgateway owns an isolated TEST_ONLY certificate session gateway.
// It is not a production identity provider and cannot enroll an active site.
package testgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

const schema = "layersentry-test-gateway/v1"

type Config struct {
	Schema         string          `json:"schema"`
	TestOnly       bool            `json:"test_only"`
	Deployment     string          `json:"deployment"`
	Listen         string          `json:"listen"`
	Upstream       string          `json:"upstream"`
	Expires        time.Time       `json:"expires"`
	User           string          `json:"user"`
	UID            string          `json:"uid"`
	Tenant         string          `json:"tenant"`
	Admin          bool            `json:"admin"`
	TenantAdmin    bool            `json:"tenant_admin,omitempty"`
	ClientSHA256   string          `json:"client_sha256"`
	UpstreamSHA256 string          `json:"upstream_sha256"`
	GatewaySHA256  string          `json:"gateway_sha256"`
	StepUp         *StepUpVerifier `json:"step_up,omitempty"`
}

func loopbackAddress(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || port == "" || port == "0" {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback()
}

func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func fingerprint(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (c Config) validate(now time.Time) error {
	if c.TenantAdmin && (c.Admin || c.StepUp == nil) {
		return errors.New("tenant administrator requires independent two-factor enrollment and cannot be super-admin")
	}
	if err := c.StepUp.validate(); err != nil {
		return err
	}
	if c.Schema != schema || !c.TestOnly || !validName(c.Deployment) || !validName(c.User) || !validName(c.UID) || !validName(c.Tenant) {
		return errors.New("explicit TEST_ONLY deployment and identity required")
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !loopbackAddress(u.Host) || !loopbackAddress(c.Listen) || c.Listen == u.Host {
		return errors.New("distinct fixed loopback HTTPS upstream and listener required")
	}
	if !c.Expires.After(now) || c.Expires.After(now.Add(4*time.Hour)) {
		return errors.New("test session expired or exceeds four-hour bound")
	}
	for _, pin := range []string{c.ClientSHA256, c.UpstreamSHA256, c.GatewaySHA256} {
		b, err := hex.DecodeString(pin)
		if err != nil || len(b) != 32 || strings.ToLower(pin) != pin || pin == strings.Repeat("0", 64) {
			return errors.New("exact certificate digest required")
		}
	}
	if c.ClientSHA256 == c.GatewaySHA256 || c.ClientSHA256 == c.UpstreamSHA256 || c.GatewaySHA256 == c.UpstreamSHA256 {
		return errors.New("test identities must be independent")
	}
	return nil
}

// Open checks owner custody. os.Root confines all subsequent opens and rejects
// escapes; private entries additionally reject symlinks, special files and
// group/other access. The operator must use a NEW root, never active credentials.
func Open(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("canonical absolute test root required")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (sys.Uid != 0 && sys.Uid != uint32(os.Geteuid())) {
			return nil, errors.New("untrusted test root ancestry")
		}
		if p == path && st.Mode().Perm() != 0700 {
			return nil, errors.New("test root must have mode 0700")
		}
		if st.Mode().Perm()&0022 != 0 && !(sys.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return nil, errors.New("writable test root ancestry")
		}
		if p == "/" {
			break
		}
	}
	return os.OpenRoot(path)
}

func readPrivate(root *os.Root, name string) ([]byte, error) {
	st, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > 65536 {
		return nil, errors.New("invalid private test file custody")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(st, after) {
		return nil, errors.New("test file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if len(b) > 65536 {
		return nil, errors.New("test file too large")
	}
	return b, err
}

func load(root *os.Root) (Config, error) {
	var c Config
	b, err := readPrivate(root, "config.json")
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing test configuration")
	}
	return c, c.validate(time.Now().UTC())
}

func certificate(root *os.Root, name string) (tls.Certificate, error) {
	pem, err := readPrivate(root, name+".pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := readPrivate(root, name+".key")
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(pem, key)
}

// NewServer authenticates the client certificate against one enrolled identity;
// no request-provided roles, tenant, admin or assurance headers are trusted.
// Revocation is checked on EVERY request including existing keep-alive sessions.
func NewServer(root *os.Root) (*http.Server, error) {
	c, err := load(root)
	if err != nil {
		return nil, err
	}
	ca, err := readPrivate(root, "ca.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid private test CA")
	}
	front, err := certificate(root, "front")
	if err != nil {
		return nil, err
	}
	back, err := certificate(root, "gateway")
	if err != nil {
		return nil, err
	}
	if fingerprint(back.Certificate[0]) != c.GatewaySHA256 {
		return nil, errors.New("gateway enrollment mismatch")
	}
	token, err := readPrivate(root, "gateway.token")
	if err != nil {
		return nil, err
	}
	if len(token) != 64 {
		return nil, errors.New("invalid gateway credential")
	}
	u, _ := url.Parse(c.Upstream)
	// Only a successful local factor verification can construct this context.
	type verifiedStepUpKey struct{}
	passwordSlot := make(chan struct{}, 1)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{back},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || fingerprint(cs.PeerCertificates[0].Raw) != c.UpstreamSHA256 {
				return errors.New("upstream is not the enrolled private test backend")
			}
			return nil
		},
	}, MaxConnsPerHost: 8, MaxIdleConnsPerHost: 8, ResponseHeaderTimeout: 30 * time.Second}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(u)
			p.Out.Host = u.Host
			for h := range p.Out.Header {
				if strings.HasPrefix(strings.ToLower(h), "x-layersentry-") || strings.HasPrefix(strings.ToLower(h), "x-forwarded-") || strings.EqualFold(h, "Authorization") || strings.EqualFold(h, "Cookie") || strings.EqualFold(h, "Forwarded") {
					p.Out.Header.Del(h)
				}
			}
			p.Out.Header.Set(platformapi.GatewayTokenHeader, string(token))
			p.Out.Header.Set(platformapi.GatewayUserHeader, c.User)
			p.Out.Header.Set(platformapi.GatewayUIDHeader, c.UID)
			p.Out.Header.Set(platformapi.GatewayTenantHeader, c.Tenant)
			p.Out.Header.Set(platformapi.GatewayAssuranceHeader, "1")
			if verifiedAt, ok := p.In.Context().Value(verifiedStepUpKey{}).(time.Time); ok {
				p.Out.Header.Set(platformapi.GatewayAssuranceHeader, "2")
				p.Out.Header.Set(platformapi.GatewayStepUpAtHeader, verifiedAt.Format(time.RFC3339Nano))
			}
			if c.Admin {
				p.Out.Header.Set(platformapi.GatewayAdminHeader, "true")
			}
			if c.TenantAdmin {
				p.Out.Header.Set(platformapi.GatewayRolesHeader, "admin")
			}
		}, Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "private test backend unavailable", http.StatusBadGateway)
		},
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-LayerSentry-Test-Only", "true")
		_, revoked := root.Lstat("revoked")
		if !errors.Is(revoked, os.ErrNotExist) || !time.Now().Before(c.Expires) {
			http.Error(w, "test session revoked or expired", http.StatusUnauthorized)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			http.Error(w, "verified test client required", 401)
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		if fingerprint(leaf.Raw) != c.ClientSHA256 || !time.Now().Before(leaf.NotAfter) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://layersentry-test/"+c.Deployment+"/client" {
			http.Error(w, "unregistered test identity", 401)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/") || r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
			http.Error(w, "test API route not admitted", 403)
			return
		}
		if c.StepUp != nil && len(r.Header.Values("Authorization")) != 0 {
			select {
			case passwordSlot <- struct{}{}:
			default:
				http.Error(w, "test verifier busy", http.StatusTooManyRequests)
				return
			}
			verified := verifyPassword(root, c, r)
			<-passwordSlot
			if !verified {
				http.Error(w, "test step-up rejected", http.StatusUnauthorized)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), verifiedStepUpKey{}, time.Now().UTC()))
		}
		// Password work must not let expiry/revocation race into a new dispatch.
		_, revoked = root.Lstat("revoked")
		if !errors.Is(revoked, os.ErrNotExist) || !time.Now().Before(c.Expires) {
			http.Error(w, "test session revoked or expired", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		proxy.ServeHTTP(w, r)
	})
	s := &http.Server{Addr: c.Listen, Handler: h, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{front}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	s.RegisterOnShutdown(transport.CloseIdleConnections)
	return s, nil
}

// Revoke is monotonic for this test deployment. It does not terminate already
// admitted operations, replay them, or change backend/provider state.
func Revoke(root *os.Root) error {
	f, err := root.OpenFile("revoked", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.WriteString("TEST_ONLY session revoked\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
