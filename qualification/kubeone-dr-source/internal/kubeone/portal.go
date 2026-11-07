package kubeone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

const maxPortalBodyBytes int64 = 64 << 10
const workerReconcileFile = ".layersentry-worker-reconcile.json"

var acceleratorProfileIDPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9_.]*[a-z0-9])?$`)

// AcceleratorProfile is a provider-published worker accelerator option. It is
// inventory only: selecting it never grants provider mutation authority.
type AcceleratorProfile struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	MaxCount int    `json:"max_count"`
}

// Portal exposes a small tenant-scoped HTTP facade over the typed KubeOne
// adapter. It does not implement Kubernetes lifecycle or accept command text.
type Portal struct {
	Client       *Client
	Accelerators []AcceleratorProfile
	mu           sync.Mutex
	running      map[string]bool
}

type WorkerReconcileJob struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	Status        string    `json:"status"`
	ReadyNodes    int       `json:"ready_nodes"`
	ExpectedNodes int       `json:"expected_nodes"`
	RequestedAt   time.Time `json:"requested_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Message       string    `json:"message,omitempty"`
}

type portalCluster struct {
	ID                    string `json:"id"`
	ExpectedControlPlanes int    `json:"expected_control_planes"`
	ExpectedNodes         int    `json:"expected_nodes"`
	WorkerRepairQualified bool   `json:"worker_repair_qualified"`
	Status                Status `json:"status"`
	ReadbackError         string `json:"readback_error,omitempty"`
}

func NewPortal(client *Client, accelerators []AcceleratorProfile) (*Portal, error) {
	if client == nil {
		return nil, errors.New("KubeOne portal requires typed client")
	}
	seen := map[string]bool{}
	profiles := make([]AcceleratorProfile, 0, len(accelerators))
	for _, profile := range accelerators {
		profile.ID = strings.ToLower(strings.TrimSpace(profile.ID))
		profile.Label = strings.TrimSpace(profile.Label)
		profile.Kind = strings.ToUpper(strings.TrimSpace(profile.Kind))
		if !acceleratorProfileIDPattern.MatchString(profile.ID) || profile.Label == "" ||
			(profile.Kind != "GPU" && profile.Kind != "VGPU") || profile.MaxCount < 1 || profile.MaxCount > 8 {
			return nil, fmt.Errorf("%w: invalid worker accelerator profile", ErrValidation)
		}
		if seen[profile.ID] {
			return nil, fmt.Errorf("%w: duplicate worker accelerator profile", ErrValidation)
		}
		seen[profile.ID] = true
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return &Portal{Client: client, Accelerators: profiles, running: map[string]bool{}}, nil
}

func LoadAcceleratorProfiles(path string) ([]AcceleratorProfile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profiles []AcceleratorProfile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profiles); err != nil {
		return nil, fmt.Errorf("decode worker accelerator profiles: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: accelerator profile file must contain one JSON value", ErrValidation)
	}
	return profiles, nil
}

func portalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func portalError(w http.ResponseWriter, status int, err error) {
	portalJSON(w, status, map[string]string{"error": err.Error()})
}

func portalTenant(r *http.Request) (string, bool) {
	actor, ok := platformapi.ActorFromContext(r.Context())
	if !ok || strings.TrimSpace(actor.Tenant) == "" || strings.TrimSpace(actor.UID) == "" {
		return "", false
	}
	return strings.TrimSpace(actor.Tenant), true
}

func (p *Portal) resolve(r *http.Request) (Workspace, error) {
	tenant, ok := portalTenant(r)
	if !ok {
		return Workspace{}, errors.New("authenticated tenant context is required")
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || strings.ContainsAny(id, "\r\n\x00/") {
		return Workspace{}, fmt.Errorf("%w: invalid cluster identity", ErrValidation)
	}
	return p.Client.Workspace(tenant, id)
}

func (p *Portal) listClusters(w http.ResponseWriter, r *http.Request) {
	tenant, ok := portalTenant(r)
	if !ok {
		portalError(w, http.StatusForbidden, errors.New("authenticated tenant context is required"))
		return
	}
	items := []portalCluster{}
	for _, workspace := range p.Client.Workspaces() {
		if workspace.Tenant != tenant {
			continue
		}
		status, err := p.Client.Status(r.Context(), workspace)
		if err != nil {
			items = append(items, portalCluster{
				ID: workspace.ClusterID, ExpectedControlPlanes: workspace.ExpectedCPNodes,
				ExpectedNodes: workspace.ExpectedNodes, WorkerRepairQualified: workspace.AutonomousWorkerRepairQualified,
				Status: status, ReadbackError: "cluster health readback is unavailable",
			})
			continue
		}
		items = append(items, portalCluster{
			ID: workspace.ClusterID, ExpectedControlPlanes: workspace.ExpectedCPNodes,
			ExpectedNodes: workspace.ExpectedNodes, WorkerRepairQualified: workspace.AutonomousWorkerRepairQualified,
			Status: status,
		})
	}
	portalJSON(w, http.StatusOK, map[string]any{"clusters": items, "accelerator_profiles": p.Accelerators})
}

func (p *Portal) listNamespaces(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	items, err := p.Client.Namespaces(r.Context(), workspace)
	if err != nil {
		portalError(w, http.StatusBadGateway, err)
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"namespaces": items})
}

func (p *Portal) createNamespace(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPortalBodyBytes)
	var request struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		portalError(w, http.StatusBadRequest, fmt.Errorf("decode namespace request: %w", err))
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		portalError(w, http.StatusBadRequest, errors.New("namespace request must contain one JSON object"))
		return
	}
	namespace, created, err := p.Client.CreateNamespace(r.Context(), workspace, request.Name)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrValidation) {
			status = http.StatusBadRequest
		} else if strings.Contains(err.Error(), "not owned") {
			status = http.StatusConflict
		}
		portalError(w, status, err)
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"namespace": namespace, "created": created})
}

func (p *Portal) kubeconfig(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	raw, err := os.ReadFile(workspace.Kubeconfig)
	if err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("kubeconfig is unavailable"))
		return
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		portalError(w, http.StatusInternalServerError, errors.New("kubeconfig failed bounded readback"))
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+workspace.ClusterID+`.kubeconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func workerJobPath(workspace Workspace) string {
	return filepath.Join(workspace.Directory, workerReconcileFile)
}

func readWorkerJob(workspace Workspace) (WorkerReconcileJob, error) {
	path := workerJobPath(workspace)
	info, err := os.Lstat(path)
	if err != nil {
		return WorkerReconcileJob{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxPortalBodyBytes {
		return WorkerReconcileJob{}, fmt.Errorf("%w: invalid worker reconciliation state", ErrValidation)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return WorkerReconcileJob{}, err
	}
	var job WorkerReconcileJob
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil {
		return WorkerReconcileJob{}, fmt.Errorf("decode worker reconciliation state: %w", err)
	}
	return job, nil
}

func writeWorkerJob(workspace Workspace, job WorkerReconcileJob) error {
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(workspace.Directory, ".layersentry-worker-reconcile-*.tmp")
	if err != nil {
		return err
	}
	path := temp.Name()
	defer os.Remove(path)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(path, workerJobPath(workspace))
}

func newWorkerJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (p *Portal) workerJob(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	p.mu.Lock()
	job, err := readWorkerJob(workspace)
	if err != nil {
		p.mu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			portalError(w, http.StatusNotFound, errors.New("no worker reconciliation has been requested"))
			return
		}
		portalError(w, http.StatusInternalServerError, errors.New("worker reconciliation state is unavailable"))
		return
	}
	if job.Status == "RUNNING" && !p.running[registryKey(workspace.Tenant, workspace.ClusterID)] {
		job.Status = "UNKNOWN"
		job.UpdatedAt = time.Now().UTC()
		job.Message = "service restarted before the KubeOne result was reconciled"
		_ = writeWorkerJob(workspace, job)
	}
	p.mu.Unlock()
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (p *Portal) reconcileWorkers(w http.ResponseWriter, r *http.Request) {
	actor, ok := platformapi.ActorFromContext(r.Context())
	if !ok || !actor.Oneadmin {
		portalError(w, http.StatusForbidden, errors.New("provider administrator authorization is required"))
		return
	}
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	p.mu.Lock()
	if p.running[key] {
		job, _ := readWorkerJob(workspace)
		p.mu.Unlock()
		portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
		return
	}
	p.running[key] = true
	p.mu.Unlock()

	status, err := p.Client.Status(r.Context(), workspace)
	if err != nil || !status.APIReady || status.ReadyControlPlanes != workspace.ExpectedCPNodes || status.KubeSystemNonReady != 0 {
		p.mu.Lock()
		delete(p.running, key)
		p.mu.Unlock()
		portalError(w, http.StatusConflict, errors.New("worker reconciliation requires healthy control-plane quorum and kube-system"))
		return
	}
	if workspace.ExpectedNodes <= workspace.ExpectedCPNodes {
		p.mu.Lock()
		delete(p.running, key)
		p.mu.Unlock()
		portalError(w, http.StatusConflict, errors.New("registered topology has no qualified worker baseline"))
		return
	}
	now := time.Now().UTC()
	jobID, err := newWorkerJobID()
	if err != nil {
		p.mu.Lock()
		delete(p.running, key)
		p.mu.Unlock()
		portalError(w, http.StatusInternalServerError, errors.New("could not create durable worker reconciliation identity"))
		return
	}
	job := WorkerReconcileJob{ID: jobID, ClusterID: workspace.ClusterID, Status: "RUNNING", ReadyNodes: status.ReadyNodes, ExpectedNodes: workspace.ExpectedNodes, RequestedAt: now, UpdatedAt: now}
	if status.ReadyNodes >= workspace.ExpectedNodes {
		job.Status = "SUCCEEDED"
		job.Message = "registered worker topology is already converged"
		if err := writeWorkerJob(workspace, job); err != nil {
			p.mu.Lock()
			delete(p.running, key)
			p.mu.Unlock()
			portalError(w, http.StatusInternalServerError, errors.New("could not persist worker reconciliation result"))
			return
		}
		p.mu.Lock()
		delete(p.running, key)
		p.mu.Unlock()
		portalJSON(w, http.StatusOK, map[string]any{"job": job})
		return
	}
	if err := writeWorkerJob(workspace, job); err != nil {
		p.mu.Lock()
		delete(p.running, key)
		p.mu.Unlock()
		portalError(w, http.StatusInternalServerError, errors.New("could not persist worker reconciliation plan"))
		return
	}
	go p.runWorkerReconcile(key, workspace, job)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (p *Portal) runWorkerReconcile(key string, workspace Workspace, job WorkerReconcileJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	message := "registered worker topology converged through KubeOne"
	if _, err := p.Client.Apply(ctx, workspace, ApplyOptions{}); err != nil {
		job.Status = "UNKNOWN"
		message = "KubeOne apply did not return a confirmed result; authoritative readback is required"
	} else if status, err := p.Client.WaitHealthy(ctx, workspace, workspace.ExpectedCPNodes, workspace.ExpectedNodes); err != nil {
		job.Status = "UNKNOWN"
		job.ReadyNodes = status.ReadyNodes
		message = "KubeOne returned but the registered topology did not reach confirmed healthy state"
	} else {
		job.Status = "SUCCEEDED"
		job.ReadyNodes = status.ReadyNodes
	}
	job.Message = message
	job.UpdatedAt = time.Now().UTC()
	p.mu.Lock()
	_ = writeWorkerJob(workspace, job)
	delete(p.running, key)
	p.mu.Unlock()
}

func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kubernetes/clusters", p.listClusters)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/namespaces", p.listNamespaces)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/namespaces", p.createNamespace)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/kubeconfig", p.kubeconfig)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/worker-reconciliation", p.workerJob)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/worker-reconciliation", p.reconcileWorkers)
	return mux
}

func (p *Portal) Ready(_ context.Context) error {
	if p == nil || p.Client == nil {
		return errors.New("KubeOne portal is not configured")
	}
	return nil
}
