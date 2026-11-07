package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// RunDRAutomation is an OPT-IN, server-only DR-side supervisor. It cannot mint
// an authenticated human actor, a native fencing signature, an app checksum or
// a DNS/VIP cutover receipt. Each transition uses the same internal engine
// as the gateway's manually approved workflow.
func (p *Portal) RunDRAutomation(ctx context.Context, controllerClusterID string) error {
	if p == nil || p.recovery == nil || !recoveryIDPattern.MatchString(controllerClusterID) {
		return fmt.Errorf("%w: registered independent DR controller required", ErrValidation)
	}
	var policies []DRAutomationPolicy
	for _, policy := range p.recovery.config.DRAutomation {
		if !policy.Enabled {
			continue
		}
		if policy.ControllerClusterID != controllerClusterID ||
			policy.TargetClusterID != controllerClusterID {
			return fmt.Errorf("%w: automatic DR may run only on its designated DR-side controller", ErrValidation)
		}
		if _, err := p.Client.Workspace(policy.Tenant, policy.SourceClusterID); err != nil {
			return fmt.Errorf("%w: source workspace not independently registered", ErrValidation)
		}
		if _, err := p.Client.Workspace(policy.Tenant, policy.TargetClusterID); err != nil {
			return fmt.Errorf("%w: DR workspace not independently registered", ErrValidation)
		}
		policies = append(policies, policy)
	}
	if len(policies) == 0 {
		return fmt.Errorf("%w: no explicitly enabled automatic DR policies", ErrValidation)
	}
	// A portal instance can host exactly one automatic scheduler. Cross-host HA
	// still needs independently qualified site-wide leader election and shared
	// native fencing; a local flock is not distributed consensus.
	p.mu.Lock()
	if p.autoDRRunning {
		p.mu.Unlock()
		return fmt.Errorf("%w: DR controller already running", ErrValidation)
	}
	p.autoDRRunning = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.autoDRRunning = false
		p.mu.Unlock()
	}()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, len(policies))
	var wg sync.WaitGroup
	for _, policy := range policies {
		wg.Add(1)
		go func(a DRAutomationPolicy) {
			defer wg.Done()
			if err := p.automaticDRLoop(runCtx, a); err != nil && runCtx.Err() == nil {
				select {
				case failures <- err:
				default:
				}
				cancel()
			}
		}(policy)
	}
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-failures:
	case <-runCtx.Done():
		if ctx.Err() != nil {
			result = ctx.Err()
		} else {
			result = errors.New("DR automatic controller shut down")
		}
	}
	cancel()
	wg.Wait()
	if errors.Is(result, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return result
}

func (p *Portal) automaticDRLoop(ctx context.Context, a DRAutomationPolicy) error {
	source, err := p.Client.Workspace(a.Tenant, a.SourceClusterID)
	if err != nil {
		return err
	}
	target, err := p.Client.Workspace(a.Tenant, a.TargetClusterID)
	if err != nil {
		return err
	}
	lease, err := acquireAutoDRControllerLease(source)
	if err != nil {
		return fmt.Errorf("%w: duplicate or unsafe DR coordinator", ErrValidation)
	}
	defer lease.Close()
	// A local flock is only an additional single-host guard. Require an
	// already authorized, pre-provisioned native Kubernetes Lease in the
	// DR cluster before any automatic decision can run. The pre-provision
	// and narrow DR ServiceAccount RBAC are external operator admissions.
	leader, err := acquireDRKubernetesControllerLease(ctx, p.Client, source, target, a)
	if err != nil {
		return fmt.Errorf("%w: independent DR-side Kubernetes controller leader unavailable", ErrValidation)
	}
	state, err := readAutoDRStatus(source)
	if errors.Is(err, os.ErrNotExist) {
		state = AutoDRStatus{ClusterID: source.ClusterID, TargetClusterID: target.ClusterID, State: "INITIALIZING"}
	} else if err != nil || state.TargetClusterID != target.ClusterID {
		return fmt.Errorf("%w: persisted DR automatic decision journal needs human reconciliation", ErrValidation)
	}
	// A decision tick can be blocked on API/Velero reads for longer than a
	// normal poll interval. Renew native DR leadership independently while
	// it is in flight; cancellation stops automatic async restores as well.
	leaderCtx, stopLeader := context.WithCancel(ctx)
	watchFailures := startDRAutomationLeaseWatchdog(
		leaderCtx, stopLeader, lease, leader, source,
		drControllerHeartbeatCadence(a.PollSeconds),
	)
	defer func() {
		stopLeader()
		for range watchFailures {
			// Drain before exiting, to avoid a leaked watchdog goroutine.
		}
	}()
	leaderLost := func() error {
		select {
		case err := <-watchFailures:
			if err != nil {
				return err
			}
		default:
		}
		return fmt.Errorf("%w: DR distributed controller leadership was interrupted", ErrValidation)
	}
	poll := time.Duration(a.PollSeconds) * time.Second
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if leaderCtx.Err() != nil {
			return leaderLost()
		}
		// A local flock on a detached directory inode is NOT a live lease.
		// Halt before further automatic decisions when the owned path has
		// been replaced. This guard does not substitute for a distributed
		// HA leader/witness on independent controller hosts.
		if err := lease.Check(source); err != nil {
			return fmt.Errorf("%w: local controller lock ownership changed; no further automatic operations", ErrValidation)
		}
		// The background watchdog renews the distributed CAS while this
		// tick is executing. Never start the tick with stale leadership.
		if err := leader.Check(leaderCtx); err != nil {
			return fmt.Errorf("%w: DR controller lost distributed Kubernetes leader", ErrValidation)
		}
		if err := p.automaticDRTick(leaderCtx, a, source, target, &state); err != nil {
			if leaderCtx.Err() != nil && ctx.Err() == nil {
				return leaderLost()
			}
			// Fail closed on corrupt or unpublishable durable state: never loop
			// into infrastructure writes after losing decision ownership.
			return fmt.Errorf("%w: automatic DR journal cannot be advanced", err)
		}
		if err := lease.Check(source); err != nil {
			return fmt.Errorf("%w: local controller lock replaced during automatic iteration; reconciliation required", ErrValidation)
		}
		if err := leader.Check(leaderCtx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%w: DR controller lost distributed leader after an automatic iteration", ErrValidation)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-leaderCtx.Done():
			if ctx.Err() != nil {
				return nil
			}
			return leaderLost()
		case err := <-watchFailures:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return leaderLost()
			}
			return err
		case <-ticker.C:
		}
	}
}
