package lifecycle

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDRAutomationStatusGETDowngradesStaleOrFutureGreenJournal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		observed  time.Duration
		wantState string
		fresh     bool
	}{
		{"fresh_signed_history", 0, "DR_ACTIVE", true},
		{"coordinator_died_hours_ago", -4 * time.Hour, "STALE_CONTROLLER_STATUS", false},
		{"clock_rolled_back", time.Hour, "STALE_CONTROLLER_STATUS", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupDRExecutionFixture(t)
			a := registeredAutoDRPolicy(t, x)
			status := AutoDRStatus{ClusterID: a.SourceClusterID, TargetClusterID: a.TargetClusterID,
				State: "DR_ACTIVE", Reason: "Historical signed site cutover", ObservedAt: time.Now().UTC().Add(tc.observed),
				LastAction: "FAILOVER", LastOperationID: strings.Repeat("d", 32)}
			if err := persistAutoDRStatus(x.ws, status); err != nil {
				t.Fatal(err)
			}
			got := portalAdminRequest(t, x.handler, http.MethodGet,
				"/v1/kubernetes/clusters/cluster-a/dr/automation", "", a.Tenant)
			if got.Code != 200 {
				t.Fatalf("status API returned %d: %s", got.Code, got.Body.String())
			}
			if !strings.Contains(got.Body.String(), `"state":"`+tc.wantState+`"`) {
				t.Fatalf("stale or future controller journal still exposed as current: %s", got.Body.String())
			}
			freshness := `"status_fresh":false`
			if tc.fresh {
				freshness = `"status_fresh":true`
			}
			if !strings.Contains(got.Body.String(), freshness) {
				t.Fatalf("freshness not independently surfaced: %s", got.Body.String())
			}
			persisted, err := readAutoDRStatus(x.ws)
			if err != nil || persisted.State != "DR_ACTIVE" {
				t.Fatal("GET observation mutated historical durable journal", persisted, err)
			}
		})
	}
}

func TestDRAutomationStatusGETRejectsForeignTargetJournal(t *testing.T) {
	x := setupDRExecutionFixture(t)
	a := registeredAutoDRPolicy(t, x)
	foreign := AutoDRStatus{
		ClusterID:       a.SourceClusterID,
		TargetClusterID: "foreign-dr",
		State:           "DR_ACTIVE",
		Reason:          "Foreign workflow journal is not current tenant DR authority",
		ObservedAt:      time.Now().UTC(),
	}
	if err := persistAutoDRStatus(x.ws, foreign); err != nil {
		t.Fatal(err)
	}
	reply := portalAdminRequest(t, x.handler, http.MethodGet,
		"/v1/kubernetes/clusters/cluster-a/dr/automation", "", a.Tenant)
	if reply.Code != http.StatusConflict {
		t.Fatalf("foreign target DR_ACTIVE journal displayed as current tenant authority: code=%d body=%s", reply.Code, reply.Body.String())
	}
	stored, err := readAutoDRStatus(x.ws)
	if err != nil || stored.State != "DR_ACTIVE" || stored.TargetClusterID != "foreign-dr" {
		t.Fatal("failed GET modified historical foreign journal", stored, err)
	}
}
