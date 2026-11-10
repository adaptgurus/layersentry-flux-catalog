package lifecycle

import (
	"errors"
	"os"
)

// reconcileZeroTouchDRAfterStartup repairs only the enrollment-write crash
// window following a durably completed primary provision. It never dispatches
// KubeOne, creates a DR target, or marks backup or restore verified.
//
// The original terminal provision identity and registered admin-owned DR site
// must still match. Corrupt or ambiguous records remain blocked and are
// reported via the read-only protection endpoint, not overwritten.
func (p *Portal) reconcileZeroTouchDRAfterStartup() (admitted, blocked int) {
	if p == nil || p.Client == nil || p.Client.registry == nil || p.recovery == nil {
		return 0, 0
	}
	for _, ws := range p.Client.registry.List() {
		if _, enabled := p.zeroTouchDRPolicy(ws); !enabled {
			continue
		}
		var primary ProvisionJob
		err := readBoundedJob(provisionJobPath(ws), &primary)
		if errors.Is(err, os.ErrNotExist) {
			continue // primary has never finished provisioning
		}
		if err != nil {
			blocked++
			continue // ambiguous primary result remains untouched
		}
		if primary.Status != "SUCCEEDED" || primary.EvidenceLabel != "LIVE_PROVEN" {
			continue // terminal failure/UNKNOWN is not enrollment authority
		}
		if err := p.queueZeroTouchDR(ws, primary); err != nil {
			blocked++ // corrupt or switched-site intent is never overwritten
		} else {
			admitted++ // includes idempotent exact-identity delivery
		}
	}
	return admitted, blocked
}
