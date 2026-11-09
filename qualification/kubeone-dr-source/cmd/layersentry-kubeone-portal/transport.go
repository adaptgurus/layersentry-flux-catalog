package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
	"github.com/layersentry/layersentry-platform/internal/secureconfig"
)

// Existing loopback deployments retain their local gateway transport. An
// explicitly configured TLS deployment must bind all transport and gateway
// identities together; partial/empty settings never fall back to plaintext.
func portalTransport(address, token string) (*tls.Config, *platformapi.GatewayAuth, error) {
	names := portalTLSSettings
	configured := false
	values := make([]string, len(names))
	for i, name := range names {
		v, set := os.LookupEnv(name)
		configured = configured || set
		values[i] = strings.TrimSpace(v)
	}
	if _, set := os.LookupEnv("LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY"); set {
		return nil, nil, errors.New("portal TLS private key requires protected file custody")
	}
	if !configured {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			return nil, nil, errors.New("plaintext portal requires a literal loopback listener")
		}
		auth, err := platformapi.NewGatewayAuth(token)
		return nil, auth, err
	}
	for i, v := range values {
		if v == "" || (i < 3 && (!filepath.IsAbs(v) || filepath.Clean(v) != v)) {
			return nil, nil, errors.New("portal mTLS requires canonical certificate/key/CA files and exact gateway pins")
		}
	}
	auth, err := platformapi.NewGatewayAuthWithConfig(platformapi.GatewayAuthConfig{
		Token: token, RequireVerifiedWorkloadMTLS: true,
		AllowedGatewayCertificateSHA256: strings.Split(values[3], ","),
	})
	if err != nil {
		return nil, nil, err
	}
	key, err := secureconfig.RequiredEnvOrFile("LAYERSENTRY_KUBEONE_PORTAL_TLS_KEY")
	if err != nil {
		return nil, nil, errors.New("portal private key custody rejected")
	}
	cert, err := os.ReadFile(values[0])
	if err != nil {
		return nil, nil, errors.New("portal server certificate unavailable")
	}
	pair, err := tls.X509KeyPair(cert, []byte(key))
	if err != nil {
		return nil, nil, errors.New("portal TLS certificate/key mismatch")
	}
	ca, err := os.ReadFile(values[2])
	if err != nil {
		return nil, nil, errors.New("portal client CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("portal client CA invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, auth, nil
}
