package platformapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	GatewayTokenHeader     = "X-LayerSentry-Gateway-Token"
	GatewayUserHeader      = "X-LayerSentry-User"
	GatewayUIDHeader       = "X-LayerSentry-UID"
	GatewayTenantHeader    = "X-LayerSentry-Tenant"
	GatewayRolesHeader     = "X-LayerSentry-Roles"
	GatewayAdminHeader     = "X-LayerSentry-Oneadmin"
	GatewayAssuranceHeader = "X-LayerSentry-Assurance-Level"
	GatewayStepUpAtHeader  = "X-LayerSentry-Step-Up-At"
)

type Actor struct {
	User             string
	UID              string
	Tenant           string
	Roles            []string
	Oneadmin         bool
	AssuranceLevel   int
	StepUpAt         time.Time
	WorkloadIdentity string
	WorkloadURI      string
}

func (a Actor) HasFreshStepUp(now time.Time, maxAge time.Duration) bool {
	if a.AssuranceLevel < 2 || a.StepUpAt.IsZero() || maxAge <= 0 {
		return false
	}
	now = now.UTC()
	step := a.StepUpAt.UTC()
	if step.After(now.Add(30 * time.Second)) {
		return false
	}
	age := now.Sub(step)
	return age >= 0 && age <= maxAge
}

type actorContextKey struct{}

type GatewayAuthConfig struct {
	Token                       string
	RequireVerifiedWorkloadMTLS bool
	// Optional exact leaf authorization for the human/API gateway boundary.
	// Machine certificate handling retains its existing independent URI policy.
	AllowedGatewayCertificateSHA256 []string
	MaxFailuresPerSource            int
	FailureWindow                   time.Duration
	BlockDuration                   time.Duration
	MaxTrackedSources               int
}

type authFailureState struct {
	Failures     int
	WindowStart  time.Time
	BlockedUntil time.Time
	LastSeen     time.Time
}

type authFailureTracker struct {
	mu         sync.Mutex
	states     map[string]authFailureState
	maxFailure int
	window     time.Duration
	block      time.Duration
	maxEntries int
}

type GatewayAuth struct {
	token                       string
	requireVerifiedWorkloadMTLS bool
	failures                    *authFailureTracker
	now                         func() time.Time
	allowedGatewayCertificates  map[string]struct{}
}

func NewGatewayAuth(token string) (*GatewayAuth, error) {
	return NewGatewayAuthWithConfig(GatewayAuthConfig{Token: token})
}

func newAuthFailureTracker(cfg GatewayAuthConfig) (*authFailureTracker, error) {
	if cfg.MaxFailuresPerSource <= 0 {
		cfg.MaxFailuresPerSource = 8
	}
	if cfg.MaxFailuresPerSource < 3 || cfg.MaxFailuresPerSource > 100 {
		return nil, errors.New("gateway auth max failures per source must be 3..100")
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 5 * time.Minute
	}
	if cfg.FailureWindow < 30*time.Second || cfg.FailureWindow > time.Hour {
		return nil, errors.New("gateway auth failure window must be between 30s and 1h")
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 15 * time.Minute
	}
	if cfg.BlockDuration < time.Minute || cfg.BlockDuration > 24*time.Hour {
		return nil, errors.New("gateway auth block duration must be between 1m and 24h")
	}
	if cfg.MaxTrackedSources <= 0 {
		cfg.MaxTrackedSources = 10000
	}
	if cfg.MaxTrackedSources < 128 || cfg.MaxTrackedSources > 1000000 {
		return nil, errors.New("gateway auth tracked-source limit must be 128..1000000")
	}
	return &authFailureTracker{
		states: map[string]authFailureState{}, maxFailure: cfg.MaxFailuresPerSource,
		window: cfg.FailureWindow, block: cfg.BlockDuration, maxEntries: cfg.MaxTrackedSources,
	}, nil
}

func requestSourceKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.TrimSpace(host)
	}
	if net.ParseIP(raw) != nil {
		return raw
	}
	return ""
}

func (t *authFailureTracker) blocked(source string, now time.Time) time.Duration {
	if t == nil || source == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.states[source]
	if !ok {
		return 0
	}
	if state.BlockedUntil.After(now) {
		return state.BlockedUntil.Sub(now)
	}
	if !state.BlockedUntil.IsZero() && !state.BlockedUntil.After(now) {
		delete(t.states, source)
	}
	return 0
}

func (t *authFailureTracker) evictOldestLocked() {
	if len(t.states) < t.maxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, state := range t.states {
		if oldestKey == "" || state.LastSeen.Before(oldest) {
			oldestKey, oldest = key, state.LastSeen
		}
	}
	if oldestKey != "" {
		delete(t.states, oldestKey)
	}
}

func (t *authFailureTracker) fail(source string, now time.Time) time.Duration {
	if t == nil || source == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	state, exists := t.states[source]
	if !exists {
		t.evictOldestLocked()
		state.WindowStart = now
	}
	if state.BlockedUntil.After(now) {
		state.LastSeen = now
		t.states[source] = state
		return state.BlockedUntil.Sub(now)
	}
	if state.WindowStart.IsZero() || now.Sub(state.WindowStart) > t.window || now.Before(state.WindowStart) {
		state.Failures = 0
		state.WindowStart = now
		state.BlockedUntil = time.Time{}
	}
	state.Failures++
	state.LastSeen = now
	if state.Failures >= t.maxFailure {
		state.BlockedUntil = now.Add(t.block)
	}
	t.states[source] = state
	if state.BlockedUntil.After(now) {
		return state.BlockedUntil.Sub(now)
	}
	return 0
}

func (t *authFailureTracker) success(source string) {
	if t == nil || source == "" {
		return
	}
	t.mu.Lock()
	delete(t.states, source)
	t.mu.Unlock()
}

func NewGatewayAuthWithConfig(cfg GatewayAuthConfig) (*GatewayAuth, error) {
	token := strings.TrimSpace(cfg.Token)
	if len(token) < 32 {
		return nil, errors.New("LayerSentry gateway token must contain at least 32 characters")
	}
	pins, err := gatewayCertificatePins(cfg)
	if err != nil {
		return nil, err
	}
	tracker, err := newAuthFailureTracker(cfg)
	if err != nil {
		return nil, err
	}
	return &GatewayAuth{
		token: token, requireVerifiedWorkloadMTLS: cfg.RequireVerifiedWorkloadMTLS,
		failures: tracker, now: time.Now,
		allowedGatewayCertificates: pins,
	}, nil
}

func (a *GatewayAuth) reject(w http.ResponseWriter, r *http.Request, message string) {
	now := time.Now().UTC()
	if a != nil && a.now != nil {
		now = a.now().UTC()
	}
	remaining := time.Duration(0)
	if a != nil && a.failures != nil {
		remaining = a.failures.fail(requestSourceKey(r), now)
	}
	if remaining > 0 {
		seconds := int(remaining.Round(time.Second) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "authentication temporarily rate limited"})
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": message})
}

func verifiedWorkloadIdentity(r *http.Request) (string, string) {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || r.TLS.VerifiedChains[0][0] == nil {
		return "", ""
	}
	leaf := r.TLS.VerifiedChains[0][0]
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := "mtls-sha256:" + hex.EncodeToString(sum[:])
	var workloadURI string
	for _, uri := range leaf.URIs {
		if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") {
			continue
		}
		if workloadURI != "" {
			// Ambiguous multiple SPIFFE identities fail closed for callers that
			// require a URI-bound workload identity.
			return fingerprint, ""
		}
		workloadURI = uri.String()
	}
	return fingerprint, workloadURI
}

// A verified chain with multiple SPIFFE URI identities must not fall back
// into the privileged gateway-header path when no unique machine URI is found.
func ambiguousVerifiedWorkloadIdentity(r *http.Request) bool {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || r.TLS.VerifiedChains[0][0] == nil {
		return false
	}
	count := 0
	for _, uri := range r.TLS.VerifiedChains[0][0].URIs {
		if uri != nil && strings.EqualFold(uri.Scheme, "spiffe") {
			count++
		}
	}
	return count > 1
}

func validIdentity(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	return !strings.ContainsAny(value, "\r\n\x00")
}

func optionalIdentity(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || validIdentity(value)
}

func machineAgentRole(workloadURI string) (string, bool) {
	uri := strings.ToLower(strings.TrimSpace(workloadURI))
	switch {
	case strings.HasPrefix(uri, "spiffe://layersentry/node-agent/"):
		return "node-agent", true
	case strings.HasPrefix(uri, "spiffe://layersentry/workload-agent/"):
		return "workload-agent", true
	default:
		return "", false
	}
}

func parseRoles(value string) ([]string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, true
	}
	parts := strings.Split(value, ",")
	if len(parts) > 32 {
		return nil, false
	}
	seen := map[string]struct{}{}
	roles := make([]string, 0, len(parts))
	for _, part := range parts {
		role := strings.TrimSpace(part)
		if !validIdentity(role) {
			return nil, false
		}
		if _, exists := seen[role]; exists {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	return roles, true
}

func (a *GatewayAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		if a.now != nil {
			now = a.now().UTC()
		}
		source := requestSourceKey(r)
		if remaining := a.failures.blocked(source, now); remaining > 0 {
			seconds := int(remaining.Round(time.Second) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "authentication temporarily rate limited"})
			return
		}
		if ambiguousVerifiedWorkloadIdentity(r) {
			a.reject(w, r, "ambiguous LayerSentry certificate identity")
			return
		}
		workloadIdentity, workloadURI := verifiedWorkloadIdentity(r)
		if a.requireVerifiedWorkloadMTLS && workloadIdentity == "" {
			a.reject(w, r, "verified LayerSentry gateway workload identity is required")
			return
		}
		agentRole, machine := machineAgentRole(workloadURI)
		roles := []string{}
		assurance := 1
		stepUpAt := time.Time{}
		if machine {
			// A verified single-SPIFFE X.509 identity is the machine credential.
			// Never distribute or require the shared human/API gateway bearer
			// secret on node/workload agents. Privilege is derived only from the
			// certificate namespace and exact downstream resource binding.
			roles = []string{agentRole}
		} else {
			if a.allowedGatewayCertificates != nil {
				if _, approved := a.allowedGatewayCertificates[workloadIdentity]; !approved {
					a.reject(w, r, "unauthorized LayerSentry gateway certificate")
					return
				}
			}
			presented := strings.TrimSpace(r.Header.Get(GatewayTokenHeader))
			if len(presented) != len(a.token) || subtle.ConstantTimeCompare([]byte(presented), []byte(a.token)) != 1 {
				a.reject(w, r, "unauthorized LayerSentry gateway")
				return
			}
			var ok bool
			roles, ok = parseRoles(r.Header.Get(GatewayRolesHeader))
			if !ok {
				a.reject(w, r, "invalid LayerSentry role context")
				return
			}
			rawAssurance := strings.TrimSpace(r.Header.Get(GatewayAssuranceHeader))
			rawStepUp := strings.TrimSpace(r.Header.Get(GatewayStepUpAtHeader))
			if rawAssurance != "" {
				parsed, err := strconv.Atoi(rawAssurance)
				if err != nil || parsed < 1 || parsed > 3 {
					a.reject(w, r, "invalid LayerSentry assurance context")
					return
				}
				assurance = parsed
			}
			if rawStepUp != "" {
				parsed, err := time.Parse(time.RFC3339Nano, rawStepUp)
				if err != nil || assurance < 2 {
					a.reject(w, r, "invalid LayerSentry step-up context")
					return
				}
				stepUpAt = parsed.UTC()
			}
			if assurance >= 2 && stepUpAt.IsZero() {
				a.reject(w, r, "AAL2+ requires LayerSentry step-up timestamp")
				return
			}
		}
		actor := Actor{
			User:             strings.TrimSpace(r.Header.Get(GatewayUserHeader)),
			UID:              strings.TrimSpace(r.Header.Get(GatewayUIDHeader)),
			Tenant:           strings.TrimSpace(r.Header.Get(GatewayTenantHeader)),
			Roles:            roles,
			Oneadmin:         strings.EqualFold(strings.TrimSpace(r.Header.Get(GatewayAdminHeader)), "true"),
			AssuranceLevel:   assurance,
			StepUpAt:         stepUpAt,
			WorkloadIdentity: workloadIdentity,
			WorkloadURI:      workloadURI,
		}
		if machine {
			actor.Oneadmin = false
			actor.AssuranceLevel = 1
			actor.StepUpAt = time.Time{}
		}
		if !validIdentity(actor.User) || !validIdentity(actor.UID) || !optionalIdentity(actor.Tenant) {
			a.reject(w, r, "authenticated LayerSentry user identity is required and must be valid")
			return
		}
		a.failures.success(source)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func ActorFromContext(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(actorContextKey{}).(Actor)
	return actor, ok
}
