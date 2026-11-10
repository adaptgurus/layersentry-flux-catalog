package lifecycle

import (
	"bytes"
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
const controlPlaneReconcileFile = ".layersentry-control-plane-reconcile.json"
const provisionFile = ".layersentry-provision.json"

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
	Client                   *Client
	Accelerators             []AcceleratorProfile
	Applications             []ApplicationProfile
	HelmBinary               string
	mu                       sync.Mutex
	running                  map[string]bool
	appMu                    sync.Mutex
	appRunning               map[string]bool
	nativeWorkspaceSuccessor bool
	recovery                 *RecoveryManager // disabled unless protected server-side config is supplied
	autoDRRunning            bool             // opt-in, single local DR controller loop
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
	EvidenceLabel string    `json:"evidence_label"`
}

type ControlPlaneReconcileJob struct {
	ID                    string    `json:"id"`
	ClusterID             string    `json:"cluster_id"`
	Status                string    `json:"status"`
	ReadyControlPlanes    int       `json:"ready_control_planes"`
	ExpectedControlPlanes int       `json:"expected_control_planes"`
	RequestedAt           time.Time `json:"requested_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	Message               string    `json:"message,omitempty"`
	EvidenceLabel         string    `json:"evidence_label"`
}

type ProvisionJob struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	Status        string    `json:"status"`
	ReadyNodes    int       `json:"ready_nodes"`
	ExpectedNodes int       `json:"expected_nodes"`
	RequestedAt   time.Time `json:"requested_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Message       string    `json:"message,omitempty"`
	EvidenceLabel string    `json:"evidence_label"`
}

type portalCluster struct {
	ID                    string `json:"id"`
	Suspended             bool   `json:"suspended,omitempty"`
	DisplayName           string `json:"display_name"`
	Provisionable         bool   `json:"provisionable"`
	Provisioned           bool   `json:"provisioned"`
	SelfServiceLifecycle  bool   `json:"self_service_lifecycle"`
	ExpectedControlPlanes int    `json:"expected_control_planes"`
	ExpectedNodes         int    `json:"expected_nodes"`
	WorkerRepairQualified bool   `json:"worker_repair_qualified"`
	Status                Status `json:"status"`
	ReadbackError         string `json:"readback_error,omitempty"`
}

type portalDiagnosticIssue struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

type portalDiagnostics struct {
	ClusterID           string                  `json:"cluster_id"`
	Phase               string                  `json:"phase"`
	Healthy             bool                    `json:"healthy"`
	ReadyToProvision    bool                    `json:"ready_to_provision"`
	Status              *Status                 `json:"status,omitempty"`
	Issues              []portalDiagnosticIssue `json:"issues"`
	EvidenceLabel       string                  `json:"evidence_label"`
	ObservedAt          time.Time               `json:"observed_at"`
	ProductionCertified bool                    `json:"production_certified"`
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
	return &Portal{Client: client, Accelerators: profiles, running: map[string]bool{}, appRunning: map[string]bool{}}, nil
}

func (p *Portal) ConfigureApplications(profiles []ApplicationProfile, helmBinary string) error {
	if p == nil {
		return errors.New("KubeOne portal is not configured")
	}
	profiles = cloneApplicationProfiles(profiles)
	if err := validateApplicationProfiles(profiles); err != nil {
		return err
	}
	helmBinary = strings.TrimSpace(helmBinary)
	if helmBinary != "" {
		if !filepath.IsAbs(helmBinary) || filepath.Clean(helmBinary) != helmBinary {
			return fmt.Errorf("%w: Helm binary path must be absolute and normalized", ErrValidation)
		}
		info, err := os.Stat(helmBinary)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("%w: Helm binary is not executable", ErrValidation)
		}
	}
	p.Applications = append([]ApplicationProfile(nil), profiles...)
	sort.Slice(p.Applications, func(i, j int) bool { return p.Applications[i].ID < p.Applications[j].ID })
	p.HelmBinary = helmBinary
	return nil
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

func lifecycleAuthorized(r *http.Request, workspace Workspace) bool {
	actor, ok := platformapi.ActorFromContext(r.Context())
	if !ok || actor.Tenant != workspace.Tenant || !actor.HasFreshStepUp(time.Now().UTC(), 5*time.Minute) {
		return false
	}
	if actor.Oneadmin {
		return true
	}
	if workspace.SelfServiceLifecycle {
		for _, role := range actor.Roles {
			if role == "admin" {
				return true
			}
		}
	}
	return false
}

func lifecycleEvidenceLabel(status string) string {
	if status == "SUCCEEDED" {
		return "LIVE_PROVEN"
	}
	return "UNKNOWN"
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
		if workspace.Suspended {
			items = append(items, portalCluster{
				ID: workspace.ClusterID, DisplayName: workspace.DisplayName, Suspended: true,
				ExpectedControlPlanes: workspace.ExpectedCPNodes, ExpectedNodes: workspace.ExpectedNodes,
				ReadbackError: "workspace is suspended; provisioning and health are not evaluated",
			})
			continue
		}
		provisioned := p.Client.KubeconfigExists(workspace)
		if !provisioned {
			items = append(items, portalCluster{
				ID: workspace.ClusterID, DisplayName: workspace.DisplayName,
				Provisionable: workspace.Provisionable, Provisioned: false,
				SelfServiceLifecycle:  workspace.SelfServiceLifecycle,
				ExpectedControlPlanes: workspace.ExpectedCPNodes,
				ExpectedNodes:         workspace.ExpectedNodes,
				WorkerRepairQualified: workspace.AutonomousWorkerRepairQualified,
				ReadbackError:         "cluster has not been provisioned yet",
			})
			continue
		}
		status, err := p.Client.Status(r.Context(), workspace)
		if err != nil {
			items = append(items, portalCluster{
				ID: workspace.ClusterID, DisplayName: workspace.DisplayName,
				Provisionable: workspace.Provisionable, Provisioned: true,
				SelfServiceLifecycle:  workspace.SelfServiceLifecycle,
				ExpectedControlPlanes: workspace.ExpectedCPNodes,
				ExpectedNodes:         workspace.ExpectedNodes, WorkerRepairQualified: workspace.AutonomousWorkerRepairQualified,
				Status: status, ReadbackError: "cluster health readback is unavailable",
			})
			continue
		}
		items = append(items, portalCluster{
			ID: workspace.ClusterID, DisplayName: workspace.DisplayName,
			Provisionable: workspace.Provisionable, Provisioned: true,
			SelfServiceLifecycle:  workspace.SelfServiceLifecycle,
			ExpectedControlPlanes: workspace.ExpectedCPNodes,
			ExpectedNodes:         workspace.ExpectedNodes, WorkerRepairQualified: workspace.AutonomousWorkerRepairQualified,
			Status: status,
		})
	}
	portalJSON(w, http.StatusOK, map[string]any{"clusters": items, "accelerator_profiles": p.Accelerators})
}

func (p *Portal) capabilities(w http.ResponseWriter, _ *http.Request) {
	portalJSON(w, http.StatusOK, map[string]any{
		"schema":        "layersentry-kubeone-capabilities/v1",
		"multi_cluster": true,
		"operations": []string{
			"cluster.list", "cluster.diagnostics", "cluster.provision",
			"control_plane.reconcile", "workers.reconcile", "namespace.list",
			"namespace.create", "kubeconfig.download", "application.list", "application.install",
		},
		"destructive_lifecycle": false,
		"workspace_ownership":   "server",
		"completion_policy": map[string]any{
			"allowed_evidence_labels":                             []string{"REPO_PROVEN", "TEST_PROVEN", "LIVE_PROVEN", "UPSTREAM_VERIFIED", "USER_DECLARED", "INFERRED", "UNKNOWN"},
			"code_tests_can_certify_live":                         false,
			"production_certification_requires_external_evidence": true,
		},
	})
}

func (p *Portal) diagnostics(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	result := portalDiagnostics{ClusterID: workspace.ClusterID, Phase: "PLANNED", Issues: []portalDiagnosticIssue{}, EvidenceLabel: "REPO_PROVEN", ObservedAt: time.Now().UTC()}
	if !p.Client.KubeconfigExists(workspace) {
		// Absence of a kubeconfig does not prove an earlier apply never ran.
		// Use the same durable admission fence as provisionCluster, without
		// rewriting the job during a diagnostic read.
		p.mu.Lock()
		var previous ProvisionJob
		readErr := readBoundedJob(provisionJobPath(workspace), &previous)
		busy := p.running[registryKey(workspace.Tenant, workspace.ClusterID)]
		p.mu.Unlock()
		if busy || (readErr == nil && !retryableProvisionJob(previous, workspace)) ||
			(readErr != nil && !errors.Is(readErr, os.ErrNotExist)) {
			result.Phase = "UNKNOWN"
			if busy {
				result.Phase = "PROVISIONING"
			}
			result.EvidenceLabel = "UNKNOWN"
			result.Issues = append(result.Issues, portalDiagnosticIssue{
				Code: "PROVISION_RECONCILIATION_REQUIRED", Severity: "ERROR",
				Message:     "A previous lifecycle outcome is active, unavailable, or not safely retryable.",
				Remediation: "Reconcile the durable lifecycle job and authoritative guest state before starting provisioning.",
			})
			portalJSON(w, http.StatusOK, result)
			return
		}
		result.ReadyToProvision = workspace.Provisionable
		if workspace.Provisionable {
			result.Issues = append(result.Issues, portalDiagnosticIssue{
				Code: "NOT_PROVISIONED", Severity: "INFO",
				Message:     "The registered KubeOne plan has not been applied.",
				Remediation: "Start the cluster provision operation and monitor its durable job.",
			})
		} else {
			result.Issues = append(result.Issues, portalDiagnosticIssue{
				Code: "PLAN_NOT_PROVISIONABLE", Severity: "ERROR",
				Message:     "The workspace is not authorized for cluster provisioning.",
				Remediation: "Have an administrator qualify and register a server-owned provisionable workspace.",
			})
		}
		portalJSON(w, http.StatusOK, result)
		return
	}
	result.Phase = "PROVISIONED"
	status, statusErr := p.Client.Status(r.Context(), workspace)
	if statusErr != nil {
		result.EvidenceLabel = "UNKNOWN"
		result.Issues = append(result.Issues, portalDiagnosticIssue{
			Code: "READBACK_UNAVAILABLE", Severity: "ERROR",
			Message:     "Authoritative Kubernetes health readback is unavailable.",
			Remediation: "Verify the API endpoint, load-balancer/VIP, credentials, and network path before retrying lifecycle operations.",
		})
		portalJSON(w, http.StatusOK, result)
		return
	}
	result.Status = &status
	result.EvidenceLabel = "LIVE_PROVEN"
	if !status.APIReady {
		result.Issues = append(result.Issues, portalDiagnosticIssue{Code: "API_NOT_READY", Severity: "ERROR", Message: "The Kubernetes API readiness endpoint is not healthy.", Remediation: "Repair API endpoint or control-plane reachability before running KubeOne reconciliation."})
	}
	if status.ReadyControlPlanes < workspace.ExpectedCPNodes {
		result.Issues = append(result.Issues, portalDiagnosticIssue{Code: "CONTROL_PLANE_SHORTFALL", Severity: "ERROR", Message: fmt.Sprintf("%d of %d expected control-plane nodes are Ready.", status.ReadyControlPlanes, workspace.ExpectedCPNodes), Remediation: "Use the control-plane reconciliation operation after confirming quorum and kube-system health."})
	}
	if workspace.ExpectedNodes > 0 && status.ReadyNodes < workspace.ExpectedNodes {
		result.Issues = append(result.Issues, portalDiagnosticIssue{Code: "NODE_SHORTFALL", Severity: "WARNING", Message: fmt.Sprintf("%d of %d expected nodes are Ready.", status.ReadyNodes, workspace.ExpectedNodes), Remediation: "Use worker reconciliation after the control plane and kube-system are healthy."})
	}
	if status.KubeSystemNonReady > 0 {
		result.Issues = append(result.Issues, portalDiagnosticIssue{Code: "KUBE_SYSTEM_NOT_READY", Severity: "ERROR", Message: fmt.Sprintf("%d kube-system pods are not Ready.", status.KubeSystemNonReady), Remediation: "Inspect kube-system workloads and repair the owning addon or infrastructure dependency before lifecycle mutation."})
	}
	result.Healthy = len(result.Issues) == 0
	if result.Healthy {
		result.Phase = "HEALTHY"
	} else {
		result.Phase = "DEGRADED"
	}
	portalJSON(w, http.StatusOK, result)
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
	if workspace.APIProxyURL != "" && err == nil {
		// The private server transport and its authentication never leave the portal.
		raw, err = p.Client.DownloadKubeconfig(r.Context(), workspace)
	}
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
	var job WorkerReconcileJob
	if err := readBoundedJob(workerJobPath(workspace), &job); err != nil {
		return WorkerReconcileJob{}, err
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
		operation, lockErr := lockNativeWorkspace(workspace)
		if lockErr != nil {
			p.mu.Unlock()
			portalJSON(w, http.StatusOK, map[string]any{"job": job})
			return
		}
		if operation != nil {
			defer operation.Close()
		}
		job.Status = "UNKNOWN"
		job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
		job.UpdatedAt = time.Now().UTC()
		job.Message = "service restarted before the KubeOne result was reconciled"
		_ = writeWorkerJob(workspace, job)
	}
	p.mu.Unlock()
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (p *Portal) reconcileWorkers(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, errors.New("cluster lifecycle is not enabled for this tenant"))
		return
	}
	operation, lockErr := lockNativeWorkspace(workspace)
	if lockErr != nil {
		portalError(w, http.StatusConflict, errors.New("workspace operation is active or custody is unavailable"))
		return
	}
	transferred := false
	defer func() {
		if !transferred && operation != nil {
			operation.Close()
		}
	}()
	if err := readableReconciliationState(workspace); err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("cluster lifecycle state is unavailable; automatic KubeOne replay is blocked"))
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	if previous := func() *ProvisionJob {
		var job ProvisionJob
		if err := readBoundedJob(provisionJobPath(workspace), &job); err == nil {
			return &job
		}
		return nil
	}(); previous != nil && (previous.Status == "UNKNOWN" || previous.Status == "RUNNING") {
		portalError(w, http.StatusConflict, errors.New("previous provisioning outcome is unknown; aggregate health cannot establish completion; automatic KubeOne replay is blocked"))
		return
	}

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
	// Status is external readback. Serialize a fresh all-kind admission check
	// with initial publication after that callback has returned.
	p.mu.Lock()
	defer p.mu.Unlock()
	if !lifecycleAuthorized(r, workspace) {
		delete(p.running, key)
		portalError(w, http.StatusForbidden, errors.New("fresh lifecycle step-up is required"))
		return
	}
	pending, stateErr := reconciliationState(workspace)
	if stateErr != nil || pending {
		delete(p.running, key)
		if stateErr != nil {
			portalError(w, http.StatusInternalServerError, errors.New("cluster lifecycle state is unavailable; automatic KubeOne replay is blocked"))
		} else {
			portalError(w, http.StatusConflict, errors.New("previous cluster lifecycle outcome is unknown; automatic KubeOne replay is blocked"))
		}
		return
	}

	now := time.Now().UTC()
	jobID, err := newWorkerJobID()
	if err != nil {
		delete(p.running, key)
		portalError(w, http.StatusInternalServerError, errors.New("could not create durable worker reconciliation identity"))
		return
	}
	job := WorkerReconcileJob{ID: jobID, ClusterID: workspace.ClusterID, Status: "RUNNING", ReadyNodes: status.ReadyNodes, ExpectedNodes: workspace.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	if status.ReadyNodes >= workspace.ExpectedNodes {
		job.Status = "SUCCEEDED"
		job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
		job.Message = "registered worker topology is already converged"
		if err := writeWorkerJob(workspace, job); err != nil {
			delete(p.running, key)
			portalError(w, http.StatusInternalServerError, errors.New("could not persist worker reconciliation result"))
			return
		}
		delete(p.running, key)
		portalJSON(w, http.StatusOK, map[string]any{"job": job})
		return
	}
	if err := writeWorkerJob(workspace, job); err != nil {
		delete(p.running, key)
		portalError(w, http.StatusInternalServerError, errors.New("could not persist worker reconciliation plan"))
		return
	}
	transferred = true
	go p.runWorkerReconcile(key, workspace, job, operation)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (p *Portal) runWorkerReconcile(key string, workspace Workspace, job WorkerReconcileJob, operation *nativeWorkspaceLease) {
	if operation != nil {
		defer operation.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	message := "registered worker topology converged through KubeOne"
	if _, err := p.Client.Apply(ctx, workspace, ApplyOptions{}); err != nil {
		job.Status = "UNKNOWN"
		message = "KubeOne apply did not return a confirmed result; current worker health cannot establish the original outcome; retry is blocked"
	} else if status, err := p.Client.WaitHealthy(ctx, workspace, workspace.ExpectedCPNodes, workspace.ExpectedNodes); err != nil {
		job.Status = "UNKNOWN"
		job.ReadyNodes = status.ReadyNodes
		message = "KubeOne returned but the registered topology did not reach confirmed healthy state"
	} else {
		job.Status = "SUCCEEDED"
		job.ReadyNodes = status.ReadyNodes
	}
	job.Message = message
	job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
	job.UpdatedAt = time.Now().UTC()
	p.mu.Lock()
	_ = writeWorkerJob(workspace, job)
	delete(p.running, key)
	p.mu.Unlock()
}

func controlPlaneJobPath(workspace Workspace) string {
	return filepath.Join(workspace.Directory, controlPlaneReconcileFile)
}

func provisionJobPath(workspace Workspace) string {
	return filepath.Join(workspace.Directory, provisionFile)
}

func readBoundedJob(path string, out any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPortalBodyBytes {
		return fmt.Errorf("%w: invalid lifecycle operation state", ErrValidation)
	}
	f, err := os.Open(path)
	if err != nil {
		// Only the initial Lstat may establish absence. A disappearing record
		// after that observation remains unreadable intent, not fresh admission.
		return fmt.Errorf("%w: lifecycle operation state cannot be opened: %v", ErrValidation, err)
	}
	defer f.Close()
	opened, statErr := f.Stat()
	current, currentErr := os.Lstat(path)
	if statErr != nil || currentErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return fmt.Errorf("%w: lifecycle operation state changed during read", ErrValidation)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPortalBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: lifecycle operation state cannot be read: %v", ErrValidation, err)
	}
	if len(raw) > int(maxPortalBodyBytes) {
		return fmt.Errorf("%w: lifecycle operation state exceeds bound", ErrValidation)
	}
	return decodeLifecycleJob(raw, out)
}

// Reconciliation cannot interpret unreadable intent as absence. Check every
// lifecycle journal for this workspace before readback or publication, because
// provisioning and both reconciliation paths share the native lifecycle owner.
func readableReconciliationState(workspace Workspace) error {
	_, err := reconciliationState(workspace)
	return err
}

// pending is diagnostic admission state, not proof of a native outcome. Read
// every record even after finding ambiguity, so a later read error is retained.
func reconciliationState(workspace Workspace) (pending bool, err error) {
	var worker WorkerReconcileJob
	var controlPlane ControlPlaneReconcileJob
	var provision ProvisionJob
	for _, state := range []struct {
		path     string
		out      any
		identity func() (string, string, string)
	}{
		{workerJobPath(workspace), &worker, func() (string, string, string) { return worker.ID, worker.ClusterID, worker.Status }},
		{controlPlaneJobPath(workspace), &controlPlane, func() (string, string, string) { return controlPlane.ID, controlPlane.ClusterID, controlPlane.Status }},
		{provisionJobPath(workspace), &provision, func() (string, string, string) { return provision.ID, provision.ClusterID, provision.Status }},
	} {
		err := readBoundedJob(state.path, state.out)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		id, clusterID, status := state.identity()
		if strings.TrimSpace(id) == "" || clusterID != workspace.ClusterID {
			return false, fmt.Errorf("%w: lifecycle operation identity is unavailable", ErrValidation)
		}
		switch status {
		case "RUNNING", "UNKNOWN":
			pending = true
		case "SUCCEEDED", "FAILED", "NOT_STARTED":
		default:
			return false, fmt.Errorf("%w: lifecycle operation status is unavailable", ErrValidation)
		}
	}
	// Kubernetes DR is another exclusive native-lifecycle operation owner.
	// A restart with a RUNNING/UNKNOWN/unverified restore can never silently
	// restart provisioning, rotate API nodes or clean PVCs.
	dr, drErr := readDRTransition(workspace)
	if drErr == nil && dr.Status != "VERIFIED" {
		pending = true
	}
	if drErr != nil && !errors.Is(drErr, os.ErrNotExist) {
		return false, drErr
	}
	return pending, nil
}

func writeBoundedJob(workspace Workspace, target, prefix string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(workspace.Directory, prefix)
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
	if err := os.Rename(path, target); err != nil {
		return err
	}
	directory, err := os.Open(workspace.Directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func newLifecycleJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (p *Portal) provisionJob(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	p.mu.Lock()
	defer p.mu.Unlock()
	var job ProvisionJob
	if err := readBoundedJob(provisionJobPath(workspace), &job); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			portalError(w, http.StatusNotFound, errors.New("no cluster provisioning has been requested"))
			return
		}
		portalError(w, http.StatusInternalServerError, errors.New("cluster provisioning state is unavailable"))
		return
	}
	if job.Status == "RUNNING" && !p.running[key] {
		operation, e := lockNativeWorkspace(workspace)
		if e != nil {
			// Another Portal process may still own the native apply. A local
			// empty running map is not authority to rewrite its durable job.
			portalJSON(w, http.StatusOK, map[string]any{"job": job})
			return
		}
		if operation != nil {
			defer operation.Close()
		}
		job.Status = "UNKNOWN"
		job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
		job.UpdatedAt = time.Now().UTC()
		job.Message = "service restarted before the KubeOne provisioning result was reconciled"
		_ = writeBoundedJob(workspace, provisionJobPath(workspace), ".layersentry-provision-*.tmp", job)
	}
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (p *Portal) provisionCluster(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !workspace.Provisionable {
		portalError(w, http.StatusConflict, errors.New("cluster plan is not provisionable"))
		return
	}
	if !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, errors.New("cluster lifecycle is not enabled for this tenant"))
		return
	}
	if err := emptyProvisionRequest(w, r); err != nil {
		portalError(w, http.StatusBadRequest, err)
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	// Admission and intent publication share the completion/reconciliation lock.
	// A waiting request must read the current durable outcome before dispatch.
	p.mu.Lock()
	defer p.mu.Unlock()
	if nativeWorkspaceSelected(workspace) && !p.nativeWorkspaceSuccessor {
		portalError(w, http.StatusConflict, errors.New("native workspace successor admission is unavailable"))
		return
	}
	operation, lockErr := lockNativeWorkspace(workspace)
	if lockErr != nil {
		portalError(w, http.StatusConflict, errors.New("workspace operation is active or custody is unavailable"))
		return
	}
	transferred := false
	defer func() {
		if operation != nil && !transferred {
			_ = operation.Close()
		}
	}()
	if p.Client.KubeconfigExists(workspace) {
		portalError(w, http.StatusConflict, errors.New("cluster is already provisioned"))
		return
	}
	var previous ProvisionJob
	readErr := readBoundedJob(provisionJobPath(workspace), &previous)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		portalError(w, http.StatusInternalServerError, errors.New("cluster provisioning state is unavailable; automatic KubeOne replay is blocked"))
		return
	}
	if p.running[key] {
		if readErr == nil && previous.Status == "RUNNING" && previous.ClusterID == workspace.ClusterID {
			portalJSON(w, http.StatusAccepted, map[string]any{"job": previous})
		} else {
			portalError(w, http.StatusConflict, errors.New("a cluster lifecycle operation is already running"))
		}
		return
	}
	if readErr == nil && !retryableProvisionJob(previous, workspace) {
		portalError(w, http.StatusConflict, errors.New("previous provisioning outcome is unknown or not retryable; automatic KubeOne replay is blocked"))
		return
	}
	jobID, err := newLifecycleJobID()
	if err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not create provisioning operation identity"))
		return
	}
	if operation != nil {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(150 * time.Second))
		ctx, cancel := context.WithTimeout(r.Context(), 125*time.Second)
		err = p.verifyNativeWorkspaceProvision(ctx, workspace, operation)
		cancel()
		if err != nil {
			portalError(w, http.StatusConflict, errors.New("current native workspace publication proof is unavailable; provisioning is blocked"))
			return
		}
	}
	// Qualification may call the native owner. Recheck all outcomes afterwards
	// without allowing a nonpending result to replace original retry authority.
	pending, stateErr := reconciliationState(workspace)
	if stateErr != nil {
		portalError(w, http.StatusInternalServerError, errors.New("cluster lifecycle state is unavailable; automatic KubeOne replay is blocked"))
		return
	}
	if pending {
		portalError(w, http.StatusConflict, errors.New("previous cluster lifecycle outcome is unknown; automatic KubeOne replay is blocked"))
		return
	}
	var current ProvisionJob
	currentErr := readBoundedJob(provisionJobPath(workspace), &current)
	if (currentErr != nil && !errors.Is(currentErr, os.ErrNotExist)) ||
		(errors.Is(readErr, os.ErrNotExist) != errors.Is(currentErr, os.ErrNotExist)) ||
		(readErr == nil && current != previous) ||
		(currentErr == nil && !retryableProvisionJob(current, workspace)) {
		portalError(w, http.StatusConflict, errors.New("original provisioning admission changed; automatic KubeOne replay is blocked"))
		return
	}

	// Request-body reads, lock contention and native proof collection may outlive
	// the gateway step-up. Revalidate before publishing any new durable intent.
	if !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, errors.New("fresh lifecycle step-up is required"))
		return
	}
	now := time.Now().UTC()
	job := ProvisionJob{ID: jobID, ClusterID: workspace.ClusterID, Status: "RUNNING", ExpectedNodes: workspace.ExpectedNodes, RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	if err := writeBoundedJob(workspace, provisionJobPath(workspace), ".layersentry-provision-*.tmp", job); err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not persist cluster provisioning intent"))
		return
	}
	p.running[key] = true
	transferred = true
	go p.runProvision(key, workspace, job, operation)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

// Only the bounded native owner may reconcile an ambiguous apply to NOT_STARTED.
// A missing kubeconfig never makes an existing completed or unknown job retryable.
func retryableProvisionJob(job ProvisionJob, workspace Workspace) bool {
	id, err := hex.DecodeString(job.ID)
	return err == nil && len(id) == 16 && job.Status == "NOT_STARTED" &&
		job.ClusterID == workspace.ClusterID && job.ReadyNodes == 0 &&
		job.ExpectedNodes == workspace.ExpectedNodes && !job.RequestedAt.IsZero() &&
		!job.UpdatedAt.IsZero() && job.EvidenceLabel == "LIVE_PROVEN"
}

// Provisioning consumes the server-owned workspace only. Reject supplied
// settings before creating an intent or dispatching KubeOne. An omitted body
// remains valid for clients of this parameterless operation.
func emptyProvisionRequest(w http.ResponseWriter, r *http.Request) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPortalBodyBytes))
	if err != nil {
		return errors.New("cluster provisioning request exceeds the bounded empty-object contract")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	if raw[0] != '{' {
		return errors.New("cluster provisioning request must be an empty JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&struct{}{}); err != nil {
		return errors.New("cluster provisioning request must be an empty JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("cluster provisioning request must contain one empty JSON object")
	}
	return nil
}

func (p *Portal) runProvision(key string, workspace Workspace, job ProvisionJob, operation *nativeWorkspaceLease) {
	if operation != nil {
		defer operation.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	message := "KubeOne cluster provisioned and passed authoritative health readback"
	if _, err := p.Client.Apply(ctx, workspace, ApplyOptions{}); err != nil {
		job.Status = "UNKNOWN"
		message = "KubeOne apply did not return a confirmed result; current cluster health cannot establish the original outcome; retry is blocked"
	} else if err := p.Client.PersistKubeconfig(ctx, workspace); err != nil {
		job.Status = "UNKNOWN"
		message = "KubeOne applied but kubeconfig readback was not confirmed"
	} else if status, err := p.Client.WaitHealthy(ctx, workspace, workspace.ExpectedCPNodes, workspace.ExpectedNodes); err != nil {
		job.Status = "UNKNOWN"
		job.ReadyNodes = status.ReadyNodes
		message = "KubeOne applied but registered topology did not reach confirmed healthy state"
	} else {
		job.Status = "SUCCEEDED"
		job.ReadyNodes = status.ReadyNodes
	}
	job.Message = message
	job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
	job.UpdatedAt = time.Now().UTC()
	p.mu.Lock()
	// A failed terminal publication leaves the durable RUNNING intent (or an
	// unreadable result), never retry authority. Restart readback must classify
	// it UNKNOWN; releasing this lock does not report durable success.
	published := writeBoundedJob(workspace, provisionJobPath(workspace), ".layersentry-provision-*.tmp", job)
	delete(p.running, key)
	p.mu.Unlock()
	// The customer already submitted the one permitted provision request.
	// Enrollment is server-owned and starts only after the primary source
	// result is durably SUCCEEDED, never on a merely healthy UNKNOWN apply.
	// Missing DR site/credentials/controller cannot mark this cluster protected.
	if published == nil && job.Status == "SUCCEEDED" {
		_ = p.queueZeroTouchDR(workspace, job)
	}
}

func (p *Portal) controlPlaneJob(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	p.mu.Lock()
	defer p.mu.Unlock()
	var job ControlPlaneReconcileJob
	if err := readBoundedJob(controlPlaneJobPath(workspace), &job); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			portalError(w, http.StatusNotFound, errors.New("no control-plane reconciliation has been requested"))
			return
		}
		portalError(w, http.StatusInternalServerError, errors.New("control-plane reconciliation state is unavailable"))
		return
	}
	if job.Status == "RUNNING" && !p.running[key] {
		operation, lockErr := lockNativeWorkspace(workspace)
		if lockErr != nil {
			portalJSON(w, http.StatusOK, map[string]any{"job": job})
			return
		}
		if operation != nil {
			defer operation.Close()
		}
		job.Status = "UNKNOWN"
		job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
		job.UpdatedAt = time.Now().UTC()
		job.Message = "service restarted before the KubeOne control-plane result was reconciled"
		_ = writeBoundedJob(workspace, controlPlaneJobPath(workspace), ".layersentry-control-plane-*.tmp", job)
	}
	portalJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (p *Portal) reconcileControlPlane(w http.ResponseWriter, r *http.Request) {
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	if !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, errors.New("cluster lifecycle is not enabled for this tenant"))
		return
	}
	operation, lockErr := lockNativeWorkspace(workspace)
	if lockErr != nil {
		portalError(w, http.StatusConflict, errors.New("workspace operation is active or custody is unavailable"))
		return
	}
	transferred := false
	defer func() {
		if !transferred && operation != nil {
			operation.Close()
		}
	}()
	if err := readableReconciliationState(workspace); err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("cluster lifecycle state is unavailable; automatic KubeOne replay is blocked"))
		return
	}
	if !p.Client.KubeconfigExists(workspace) {
		portalError(w, http.StatusConflict, errors.New("cluster must be provisioned before control-plane reconciliation"))
		return
	}
	status, err := p.Client.Status(r.Context(), workspace)
	if err != nil || !status.APIReady || status.ReadyControlPlanes < 1 || status.KubeSystemNonReady != 0 {
		portalError(w, http.StatusConflict, errors.New("control-plane reconciliation requires a healthy existing quorum and kube-system"))
		return
	}
	if workspace.ExpectedCPNodes < 3 || workspace.ExpectedCPNodes%2 == 0 {
		portalError(w, http.StatusConflict, errors.New("registered production control-plane topology must be odd and at least three"))
		return
	}
	key := registryKey(workspace.Tenant, workspace.ClusterID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, errors.New("fresh lifecycle step-up is required"))
		return
	}
	if p.running[key] {
		var job ControlPlaneReconcileJob
		_ = readBoundedJob(controlPlaneJobPath(workspace), &job)
		portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
		return
	}
	pending, stateErr := reconciliationState(workspace)
	if stateErr != nil {
		portalError(w, http.StatusInternalServerError, errors.New("cluster lifecycle state is unavailable; automatic KubeOne replay is blocked"))
		return
	}
	if pending {
		portalError(w, http.StatusConflict, errors.New("previous cluster lifecycle outcome is unknown; automatic KubeOne replay is blocked"))
		return
	}
	p.running[key] = true

	jobID, err := newLifecycleJobID()
	if err != nil {
		delete(p.running, key)
		portalError(w, http.StatusInternalServerError, errors.New("could not create control-plane operation identity"))
		return
	}
	now := time.Now().UTC()
	job := ControlPlaneReconcileJob{
		ID: jobID, ClusterID: workspace.ClusterID, Status: "RUNNING",
		ReadyControlPlanes: status.ReadyControlPlanes, ExpectedControlPlanes: workspace.ExpectedCPNodes,
		RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN",
	}
	if status.ReadyControlPlanes >= workspace.ExpectedCPNodes {
		job.Status = "SUCCEEDED"
		job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
		job.Message = "registered control-plane topology is already converged"
		if err := writeBoundedJob(workspace, controlPlaneJobPath(workspace), ".layersentry-control-plane-*.tmp", job); err != nil {
			delete(p.running, key)
			portalError(w, http.StatusInternalServerError, errors.New("could not persist control-plane reconciliation result"))
			return
		}
		delete(p.running, key)
		portalJSON(w, http.StatusOK, map[string]any{"job": job})
		return
	}
	if err := writeBoundedJob(workspace, controlPlaneJobPath(workspace), ".layersentry-control-plane-*.tmp", job); err != nil {
		delete(p.running, key)
		portalError(w, http.StatusInternalServerError, errors.New("could not persist control-plane reconciliation intent"))
		return
	}
	transferred = true
	go p.runControlPlaneReconcile(key, workspace, job, operation)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (p *Portal) runControlPlaneReconcile(key string, workspace Workspace, job ControlPlaneReconcileJob, operation *nativeWorkspaceLease) {
	if operation != nil {
		defer operation.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	message := "registered control-plane topology converged through KubeOne"
	if _, err := p.Client.Apply(ctx, workspace, ApplyOptions{}); err != nil {
		job.Status = "UNKNOWN"
		message = "KubeOne apply did not return a confirmed result; current control-plane health cannot establish the original outcome; retry is blocked"
	} else if status, err := p.Client.WaitHealthy(ctx, workspace, workspace.ExpectedCPNodes, 0); err != nil {
		job.Status = "UNKNOWN"
		job.ReadyControlPlanes = status.ReadyControlPlanes
		message = "KubeOne returned but the registered control-plane topology did not reach confirmed healthy state"
	} else {
		job.Status = "SUCCEEDED"
		job.ReadyControlPlanes = status.ReadyControlPlanes
	}
	job.Message = message
	job.EvidenceLabel = lifecycleEvidenceLabel(job.Status)
	job.UpdatedAt = time.Now().UTC()
	p.mu.Lock()
	_ = writeBoundedJob(workspace, controlPlaneJobPath(workspace), ".layersentry-control-plane-*.tmp", job)
	delete(p.running, key)
	p.mu.Unlock()
}

func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kubernetes/capabilities", p.capabilities)
	mux.HandleFunc("GET /v1/kubernetes/backup-destinations", p.recoveryDestinations)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/backups", p.getBackup)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/backups", p.startBackup)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/dr", p.getDRPolicy)
	mux.HandleFunc("PUT /v1/kubernetes/clusters/{id}/dr", p.updateDRPolicy)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/dr/validate", p.validateDRPolicy)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/dr/protection", p.getZeroTouchDRProtection)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/dr/automation", p.getDRAutomation)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/dr/transition", p.getDRTransition)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/dr/complete", p.completeDRTransition)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/dr/failover", p.startDRTransition)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/dr/failback", p.startDRTransition)
	mux.HandleFunc("GET /v1/kubernetes/clusters", p.listClusters)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/identity", p.namespaceIdentity)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/diagnostics", p.diagnostics)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/provision", p.provisionJob)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/provision", p.provisionCluster)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/workspace-successor/{action}", p.workspaceSuccessorAction)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/control-plane-reconciliation", p.controlPlaneJob)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/control-plane-reconciliation", p.reconcileControlPlane)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/namespaces", p.listNamespaces)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/namespaces", p.createNamespace)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/kubeconfig", p.kubeconfig)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/worker-reconciliation", p.workerJob)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/worker-reconciliation", p.reconcileWorkers)
	mux.HandleFunc("GET /v1/kubernetes/clusters/{id}/applications", p.listApplications)
	mux.HandleFunc("POST /v1/kubernetes/clusters/{id}/applications/{app}", p.installApplication)
	return mux
}

func (p *Portal) Ready(_ context.Context) error {
	if p == nil || p.Client == nil {
		return errors.New("KubeOne portal is not configured")
	}
	return nil
}
