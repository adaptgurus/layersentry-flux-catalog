package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/layersentry/layersentry-platform/internal/secureconfig"
)

const readinessPrefix = "LAYERSENTRY_KUBEONE_PORTAL_READINESS_"

var portalTLSSettings = []string{
	"LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE",
	"LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY_FILE",
	"LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE",
	"LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256",
}

// Diagnostic dispatch precedes all registry loading, portal construction and
// automatic recovery. These commands consume existing transport identities;
// they never enroll an identity or initialize a controller.
func runPortalCommand(args []string) error {
	if len(args) == 0 {
		return run()
	}
	if len(args) != 1 || (args[0] != "--check-readiness-config" && args[0] != "--check-ready") {
		return errors.New("supported arguments: --check-readiness-config or --check-ready")
	}
	probe, err := newPortalReadinessProbe()
	if err != nil {
		return err
	}
	defer probe.client.CloseIdleConnections()
	if args[0] == "--check-readiness-config" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return probe.wait(ctx, time.Second)
}

type portalReadinessProbe struct {
	endpoint string
	client   *http.Client
}

func newPortalReadinessProbe() (*portalReadinessProbe, error) {
	address := valueOr("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", "127.0.0.1:9445")
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 {
		return nil, errors.New("readiness requires a listener with a numeric TCP port")
	}
	if strings.ContainsAny(host, " \t\r\n/@?#\\") {
		return nil, errors.New("readiness listener host contains URL delimiters")
	}
	configured := false
	for _, name := range portalTLSSettings {
		_, set := os.LookupEnv(name)
		configured = configured || set
	}
	if _, set := os.LookupEnv("LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY"); set {
		return nil, errors.New("portal TLS private key requires protected file custody")
	}
	scheme := "http"
	var tlsConfig *tls.Config
	if !configured {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("plaintext readiness requires a literal loopback listener")
		}
		for _, suffix := range []string{"SERVER_CA_FILE", "SERVER_NAME", "CLIENT_CERT_FILE", "CLIENT_KEY_FILE", "CLIENT_KEY"} {
			if _, set := os.LookupEnv(readinessPrefix + suffix); set {
				return nil, errors.New("readiness TLS settings require a complete portal TLS profile")
			}
		}
	} else {
		for _, name := range portalTLSSettings {
			if strings.TrimSpace(os.Getenv(name)) == "" {
				return nil, errors.New("incomplete portal TLS profile; no plaintext readiness fallback")
			}
		}
		for _, name := range portalTLSSettings[:3] {
			if !canonicalReadinessPath(os.Getenv(name)) {
				return nil, errors.New("portal TLS paths must be absolute and canonical")
			}
		}
		tlsConfig, err = readinessTLSConfig()
		if err != nil {
			return nil, err
		}
		scheme = "https"
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			host = "::1"
		}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}
	endpoint := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port), Path: "/readyz"}).String()
	if _, err := http.NewRequest(http.MethodGet, endpoint, nil); err != nil {
		return nil, errors.New("readiness listener cannot form a valid HTTP endpoint")
	}
	return &portalReadinessProbe{
		endpoint: endpoint,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func canonicalReadinessPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// Public trust material is bounded and protected against unprivileged writes;
// private key loading retains the existing secureconfig file-custody contract.
func readinessPEM(name string) ([]byte, error) {
	path := os.Getenv(name)
	if !canonicalReadinessPath(path) {
		return nil, errors.New("readiness certificate paths must be absolute and canonical")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("readiness trust directories must be protected")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return nil, errors.New("readiness trust directory ownership rejected")
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 ||
		before.Size() < 1 || before.Size() > 1<<20 {
		return nil, errors.New("readiness trust file unavailable or unsafe")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("readiness trust file ownership rejected")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("readiness trust file unavailable")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("readiness trust file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("readiness trust file read failed")
	}
	return raw, nil
}

func readinessRoots(name string) (*x509.CertPool, error) {
	raw, err := readinessPEM(name)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("readiness trust file contains no certificates")
	}
	return pool, nil
}

func readinessCertificate(raw []byte, roots *x509.CertPool, usage x509.ExtKeyUsage, name string) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("readiness certificate chain invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("readiness certificate chain invalid")
		}
		if leaf == nil {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
		raw = rest
	}
	if leaf == nil {
		return nil, errors.New("readiness certificate chain empty")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: name,
		KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		return nil, errors.New("readiness certificate identity or trust rejected")
	}
	return leaf, nil
}

func readinessTLSConfig() (*tls.Config, error) {
	if _, set := os.LookupEnv(readinessPrefix + "CLIENT_KEY"); set {
		return nil, errors.New("readiness client private key requires protected file custody")
	}
	serverName := strings.TrimSpace(os.Getenv(readinessPrefix + "SERVER_NAME"))
	if serverName == "" || strings.ContainsAny(serverName, " \t\r\n/@*\\") {
		return nil, errors.New("readiness requires the expected TLS server name")
	}
	serverRoots, err := readinessRoots(readinessPrefix + "SERVER_CA_FILE")
	if err != nil {
		return nil, err
	}
	serverPEM, err := readinessPEM("LAYERSENTRY_KUBEONE_PORTAL_TLS_CERT_FILE")
	if err != nil {
		return nil, err
	}
	serverCert, err := readinessCertificate(serverPEM, serverRoots, x509.ExtKeyUsageServerAuth, serverName)
	if err != nil {
		return nil, err
	}
	clientRoots, err := readinessRoots("LAYERSENTRY_KUBEONE_PORTAL_CLIENT_CA_FILE")
	if err != nil {
		return nil, err
	}
	clientPEM, err := readinessPEM(readinessPrefix + "CLIENT_CERT_FILE")
	if err != nil {
		return nil, err
	}
	clientCert, err := readinessCertificate(clientPEM, clientRoots, x509.ExtKeyUsageClientAuth, "")
	if err != nil {
		return nil, err
	}
	serverPublic, err := x509.MarshalPKIXPublicKey(serverCert.PublicKey)
	if err != nil {
		return nil, errors.New("readiness server identity invalid")
	}
	clientPublic, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
	if err != nil || bytes.Equal(serverPublic, clientPublic) {
		return nil, errors.New("readiness requires a separate client identity")
	}
	key, err := secureconfig.RequiredEnvOrFile(readinessPrefix + "CLIENT_KEY")
	if err != nil {
		return nil, errors.New("readiness client private key custody rejected")
	}
	pair, err := tls.X509KeyPair(clientPEM, []byte(key))
	if err != nil {
		return nil, errors.New("readiness client certificate/key mismatch")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: serverRoots, ServerName: serverName,
		Certificates: []tls.Certificate{pair},
	}, nil
}

// /readyz proves initialized portal transport only. It does not certify a
// unique installed build, Kubernetes health, storage, fencing or DR readiness.
func (p *portalReadinessProbe) wait(ctx context.Context, delay time.Duration) error {
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
		if err != nil {
			return errors.New("readiness request invalid")
		}
		response, err := p.client.Do(req)
		if err == nil {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				if readErr == nil && string(raw) == "ready\n" {
					return nil
				}
				return errors.New("readiness endpoint returned an unexpected response")
			}
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				return errors.New("readiness redirects are not permitted")
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("portal readiness was not established before cancellation or timeout")
		case <-timer.C:
		}
	}
}
