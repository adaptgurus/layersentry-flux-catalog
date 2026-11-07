package lifecycle

import (
	"context"
	"fmt"
	"time"
)

// The DR leader must renew its Kubernetes Lease even while Velero or
// signed evidence readbacks take longer than a regular monitoring tick.
// On loss of either local inode continuity or native distributed ownership,
// cancel all controller-owned operations and stop the decision loop. This
// does NOT replace independent physical writer/storage fencing.
func startDRAutomationLeaseWatchdog(
	ctx context.Context,
	cancel context.CancelFunc,
	local *autoDRControllerLease,
	distributed *drKubernetesControllerLease,
	source Workspace,
	cadence time.Duration,
) <-chan error {
	failures := make(chan error, 1)
	go func() {
		defer close(failures)
		if cadence <= 0 {
			failures <- fmt.Errorf("%w: invalid DR controller heartbeat cadence", ErrValidation)
			cancel()
			return
		}
		ticker := time.NewTicker(cadence)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := local.Check(source); err != nil {
					failures <- fmt.Errorf("%w: DR local owner lock replaced during heartbeat", ErrValidation)
					cancel()
					return
				}
				if err := distributed.Renew(ctx); err != nil {
					failures <- fmt.Errorf("%w: DR native Kubernetes leader renewal failed: %v", ErrValidation, err)
					cancel()
					return
				}
				if err := local.Check(source); err != nil {
					failures <- fmt.Errorf("%w: DR local owner lock changed during leader renewal", ErrValidation)
					cancel()
					return
				}
			}
		}
	}()
	return failures
}

func drControllerHeartbeatCadence(pollSeconds int) time.Duration {
	// Kubernetes Lease is pre-provisioned with 3 polls + 90s minimum;
	// renew more frequently than normal decision samples and always
	// leave ample room for API/readback timeouts.
	interval := time.Duration(pollSeconds) * time.Second / 2
	if interval > 10*time.Second {
		interval = 10 * time.Second
	}
	if interval < 3*time.Second {
		interval = 3 * time.Second
	}
	return interval
}
