package lifecycle

import (
	"context"
	"os"
	"testing"
	"time"
)

func drWatchdogFixture(t *testing.T) (*drTestSite, *autoDRControllerLease, *drKubernetesControllerLease, Workspace) {
	t.Helper()
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	local, err := acquireAutoDRControllerLease(x.ws)
	if err != nil {
		t.Fatal(err)
	}
	target, err := x.portal.Client.Workspace(a.Tenant, a.TargetClusterID)
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	leader, err := acquireDRKubernetesControllerLease(context.Background(), x.portal.Client, x.ws, target, a)
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	return x, local, leader, target
}

// The heartbeat renews native Kubernetes lease independently of a slow
// Velero/SQL status read. It never issues a fencing receipt.
func TestDRControllerWatchdogRenewsDuringSlowTick(t *testing.T) {
	x, local, leader, _ := drWatchdogFixture(t)
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	errs := startDRAutomationLeaseWatchdog(ctx, cancel, local, leader, x.ws, 5*time.Millisecond)
	deadline := time.After(2 * time.Second)
	for {
		x.runner.drKubeLeader.mu.Lock()
		patches := x.runner.drKubeLeader.patches
		x.runner.drKubeLeader.mu.Unlock()
		if patches >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("watchdog never renewed native CAS while main loop is busy")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := leader.Check(ctx); err != nil {
		t.Fatal("healthy leader lost admission during renewal", err)
	}
	cancel()
	for err := range errs {
		if err != nil {
			t.Fatal("deliberate shutdown generated failure", err)
		}
	}
}

func TestDRControllerWatchdogStopsOnForeignKubernetesHolder(t *testing.T) {
	x, local, leader, _ := drWatchdogFixture(t)
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x.runner.drKubeLeader.mu.Lock()
	x.runner.drKubeLeader.record.Spec.HolderIdentity = "other-DR-controller"
	x.runner.drKubeLeader.mu.Unlock()
	errs := startDRAutomationLeaseWatchdog(ctx, cancel, local, leader, x.ws, 5*time.Millisecond)
	select {
	case err, ok := <-errs:
		if !ok || err == nil {
			t.Fatal("lost Kubernetes Lease did not fail closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not stop after independent leader replacement")
	}
	if ctx.Err() == nil {
		t.Fatal("lost leadership did not cancel owner context")
	}
}

func TestDRControllerWatchdogStopsOnWorkspaceInodeReplacement(t *testing.T) {
	x, local, leader, _ := drWatchdogFixture(t)
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := startDRAutomationLeaseWatchdog(ctx, cancel, local, leader, x.ws, 5*time.Millisecond)
	displaced := x.ws.Directory + "-displaced"
	if err := os.Rename(x.ws.Directory, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(x.ws.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	select {
	case err, ok := <-errs:
		if !ok || err == nil {
			t.Fatal("detached local lock holder still presented as leader")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not stop after local directory replacement")
	}
	if ctx.Err() == nil {
		t.Fatal("detached local owner continued background restores")
	}
}
