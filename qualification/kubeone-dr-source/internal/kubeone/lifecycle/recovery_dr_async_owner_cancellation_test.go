package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The manual endpoint intentionally persists a long-running restore after
// sending HTTP 202. The AUTOMATIC path must be bound to its DR leader's
// lifetime instead: cancellation before dispatch may record an UNKNOWN
// durable journal, but may not start a new potentially writable restore.
func TestDRAutomaticAsyncRestoreStopsWhenLeaderAlreadyLost(t *testing.T) {
	x := setupDRExecutionFixture(t)
	nonce := strings.Repeat("e", 32)
	x.fence(nonce, "FAILOVER", nil)
	ownerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	job, err := x.portal.dispatchDRTransitionOwned(
		context.Background(), ownerCtx, x.ws, "FAILOVER", nonce)
	if err != nil {
		t.Fatal("failed to record signed DR intent before async stop", err)
	}
	if job.Status != "RUNNING" {
		t.Fatal("signed restore intent was not journaled", job)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state, err := readDRTransition(x.ws)
		if err == nil && state.Status == "UNKNOWN" {
			x.runner.mu.Lock()
			restores := x.runner.restoreCalls
			x.runner.mu.Unlock()
			if restores != 0 {
				t.Fatalf("auto restore created %d workloads after leadership had been lost", restores)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("canceled automatic DR restore did not publish UNKNOWN for reconciliation")
}
