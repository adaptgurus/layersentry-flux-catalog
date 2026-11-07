package testgateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

// OwnerBackend reads the same protected enrollment used by the gateway. It
// cannot promote a certificate-only subscriber or the legacy super-admin probe.
func OwnerBackend(root *os.Root) (Config, *tls.Config, platformapi.GatewayAuthConfig, error) {
	c, err := load(root)
	if err != nil {
		return c, nil, platformapi.GatewayAuthConfig{}, err
	}
	if !c.TenantAdmin || c.Admin || c.StepUp == nil {
		return c, nil, platformapi.GatewayAuthConfig{}, errors.New("dedicated two-factor tenant administrator required")
	}
	ca, err := readPrivate(root, "ca.pem")
	if err != nil {
		return c, nil, platformapi.GatewayAuthConfig{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return c, nil, platformapi.GatewayAuthConfig{}, errors.New("invalid owner CA")
	}
	cert, err := certificate(root, "backend")
	if err != nil {
		return c, nil, platformapi.GatewayAuthConfig{}, err
	}
	if fingerprint(cert.Certificate[0]) != c.UpstreamSHA256 {
		return c, nil, platformapi.GatewayAuthConfig{}, errors.New("owner backend pin differs")
	}
	token, err := readPrivate(root, "gateway.token")
	if err != nil {
		return c, nil, platformapi.GatewayAuthConfig{}, err
	}
	auth := platformapi.GatewayAuthConfig{Token: string(token), RequireVerifiedWorkloadMTLS: true, AllowedGatewayCertificateSHA256: []string{c.GatewaySHA256}}
	return c, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, auth, nil
}
