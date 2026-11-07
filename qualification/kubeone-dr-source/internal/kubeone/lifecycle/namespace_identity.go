package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/layersentry/layersentry-platform/internal/kubeone/statusreadback"
)

var errNamespaceIdentityUnavailable = errors.New("namespace identity observation is unavailable")
var errNamespaceIdentityNotFound = errors.New("registered cluster is unavailable")

// NamespaceIdentityObservation is a read-only observation, not a cluster/etcd
// identity, an independence certificate, or authorization for any mutation.
type NamespaceIdentityObservation struct {
	Tenant           string    `json:"tenant"`
	ClusterID        string    `json:"cluster_id"`
	NamespaceName    string    `json:"namespace_name"`
	NamespaceUID     string    `json:"namespace_uid"`
	ObservedAt       time.Time `json:"observed_at"`
	ObservationScope string    `json:"observation_scope"`
}

// NamespaceIdentity resolves its own tenant-scoped registry entry. Callers cannot
// supply a workspace or kubeconfig path. No readiness or lifecycle state changes.
func (c *Client) NamespaceIdentity(ctx context.Context, tenant, clusterID string) (NamespaceIdentityObservation, error) {
	if ctx == nil || ctx.Err() != nil || c == nil || c.registry == nil || c.runner == nil {
		return NamespaceIdentityObservation{}, errNamespaceIdentityUnavailable
	}
	ws, err := c.registry.Resolve(tenant, clusterID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NamespaceIdentityObservation{}, errNamespaceIdentityNotFound
		}
		return NamespaceIdentityObservation{}, errNamespaceIdentityUnavailable
	}
	if !c.KubeconfigExists(ws) || ctx.Err() != nil {
		return NamespaceIdentityObservation{}, errNamespaceIdentityUnavailable
	}
	raw, err := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary,
		[]string{"--kubeconfig", ws.Kubeconfig, "get", "namespace", "kube-system", "-o", "json"}, c.cfg.Environment)
	if err != nil || raw.StdoutTruncated || ctx.Err() != nil {
		return NamespaceIdentityObservation{}, errNamespaceIdentityUnavailable
	}
	uid, err := statusreadback.KubeSystemNamespaceUID(raw.Stdout)
	if err != nil || ctx.Err() != nil {
		return NamespaceIdentityObservation{}, errNamespaceIdentityUnavailable
	}
	return NamespaceIdentityObservation{
		Tenant: ws.Tenant, ClusterID: ws.ClusterID, NamespaceName: "kube-system",
		NamespaceUID: uid, ObservedAt: time.Now().UTC(), ObservationScope: "KUBE_SYSTEM_NAMESPACE_OBJECT_ONLY",
	}, nil
}

func (p *Portal) namespaceIdentity(w http.ResponseWriter, r *http.Request) {
	tenant, ok := portalTenant(r)
	if !ok {
		portalError(w, http.StatusForbidden, errors.New("authenticated tenant context is required"))
		return
	}
	id := r.PathValue("id")
	if id == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\r\n\x00/") {
		portalError(w, http.StatusNotFound, errNamespaceIdentityNotFound)
		return
	}
	observation, err := p.Client.NamespaceIdentity(r.Context(), tenant, id)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errNamespaceIdentityNotFound) {
			status = http.StatusNotFound
		}
		portalError(w, status, err)
		return
	}
	portalJSON(w, http.StatusOK, observation)
}
