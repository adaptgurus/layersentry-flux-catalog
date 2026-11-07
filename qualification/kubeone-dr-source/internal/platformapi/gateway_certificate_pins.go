package platformapi

import (
	"encoding/hex"
	"errors"
	"strings"
)

const MaxGatewayCertificatePins = 16

func gatewayCertificatePins(cfg GatewayAuthConfig) (map[string]struct{}, error) {
	if len(cfg.AllowedGatewayCertificateSHA256) == 0 {
		return nil, nil
	}
	if !cfg.RequireVerifiedWorkloadMTLS || len(cfg.AllowedGatewayCertificateSHA256) > MaxGatewayCertificatePins {
		return nil, errors.New("gateway certificate pins require verified mTLS and at most 16 leaves")
	}
	pins := make(map[string]struct{}, len(cfg.AllowedGatewayCertificateSHA256))
	for _, pin := range cfg.AllowedGatewayCertificateSHA256 {
		raw, err := hex.DecodeString(pin)
		if err != nil || len(raw) != 32 || pin != strings.ToLower(pin) || pin == strings.Repeat("0", 64) {
			return nil, errors.New("invalid gateway leaf certificate SHA-256")
		}
		identity := "mtls-sha256:" + pin
		if _, duplicate := pins[identity]; duplicate {
			return nil, errors.New("duplicate gateway leaf certificate SHA-256")
		}
		pins[identity] = struct{}{}
	}
	return pins, nil
}
