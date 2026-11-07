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
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layersentry/layersentry-platform/internal/platformapi"
)

const maxApplicationCatalogBytes int64 = 1 << 20
const maxHelmInventoryBytes = 1 << 20
const maxHelmInventoryReleases = 256

var (
	applicationIDPattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9_.]*[a-z0-9])?$`)
	helmTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.:/-]*[A-Za-z0-9])?$`)
	qualifiedChartName    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	qualifiedChartVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?(\+([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$`)
)

func cloneApplicationProfiles(profiles []ApplicationProfile) []ApplicationProfile {
	profiles = slices.Clone(profiles)
	for i := range profiles {
		profiles[i].Dependencies = slices.Clone(profiles[i].Dependencies)
		profiles[i].Values = maps.Clone(profiles[i].Values)
	}
	return profiles
}

// This is exact catalog matching, not repository/provenance verification.
// Aliases, ranges and leading-v normalization require separate qualification.
func applicationChartIdentity(p ApplicationProfile) (string, bool) {
	if !qualifiedChartName.MatchString(p.Chart) || !qualifiedChartVersion.MatchString(p.Version) {
		return "", false
	}
	version := strings.SplitN(p.Version, "+", 2)[0]
	if parts := strings.SplitN(version, "-", 2); len(parts) == 2 {
		for _, label := range strings.Split(parts[1], ".") {
			if strings.Trim(label, "0123456789") == "" && len(label) > 1 && label[0] == '0' {
				return "", false
			}
		}
	}
	return p.Chart + "-" + p.Version, true
}

type helmReleaseKey struct{ Namespace, Name string }
type helmRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Revision  string `json:"revision"`
	Status    string `json:"status"`
	Chart     string `json:"chart"`
}

// Selected native/job objects must not silently normalize duplicate or aliased
// field names. The permitted metadata keys are the pinned Helm list contract.
func applicationJSONFields(raw []byte, allowed string) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid application JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("application JSON object required")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || !slices.Contains(strings.Fields(allowed), name) {
			return errors.New("ambiguous application JSON field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid application JSON document")
	}
	return nil
}

func (r *helmRelease) UnmarshalJSON(raw []byte) error {
	if err := applicationJSONFields(raw, "name namespace revision status chart updated app_version"); err != nil {
		return err
	}
	type plain helmRelease
	return json.Unmarshal(raw, (*plain)(r))
}

type helmInventory map[helmReleaseKey]helmRelease

func (v helmInventory) installed(p ApplicationProfile) (helmRelease, bool) {
	r, present := v[helmReleaseKey{p.Namespace, p.ReleaseName}]
	chart, supported := applicationChartIdentity(p)
	return r, present && supported && r.Status == "deployed" && r.Chart == chart
}

type helmInventoryOutput struct{ buffer bytes.Buffer }

func (v *helmInventoryOutput) Write(p []byte) (int, error) {
	if len(p) > maxHelmInventoryBytes-v.buffer.Len() {
		return 0, errors.New("Helm inventory exceeds bound")
	}
	return v.buffer.Write(p)
}

type ApplicationProfile struct {
	ID              string            `json:"id"`
	Label           string            `json:"label"`
	Category        string            `json:"category"`
	Description     string            `json:"description,omitempty"`
	RepositoryURL   string            `json:"repository_url"`
	Chart           string            `json:"chart"`
	Version         string            `json:"version"`
	ReleaseName     string            `json:"release_name"`
	Namespace       string            `json:"namespace"`
	CreateNamespace bool              `json:"create_namespace"`
	Dependencies    []string          `json:"dependencies,omitempty"`
	Values          map[string]string `json:"values,omitempty"`
}

type ApplicationInstallJob struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	Application   string    `json:"application"`
	Status        string    `json:"status"`
	RequestedAt   time.Time `json:"requested_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Message       string    `json:"message,omitempty"`
	EvidenceLabel string    `json:"evidence_label"`
}

type applicationState struct {
	Profile   ApplicationProfile     `json:"profile"`
	Installed bool                   `json:"installed"`
	HelmChart string                 `json:"helm_chart,omitempty"`
	Job       *ApplicationInstallJob `json:"job,omitempty"`
}

type applicationCatalogFile struct {
	Applications []ApplicationProfile `json:"applications"`
}

func LoadApplicationProfiles(path string) ([]ApplicationProfile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxApplicationCatalogBytes {
		return nil, errors.New("application catalog must be a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, maxApplicationCatalogBytes))
	decoder.DisallowUnknownFields()
	var catalog applicationCatalogFile
	if err := decoder.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode application catalog: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("application catalog must contain one JSON value")
	}
	if err := validateApplicationProfiles(catalog.Applications); err != nil {
		return nil, err
	}
	return catalog.Applications, nil
}

func validateApplicationProfiles(profiles []ApplicationProfile) error {
	seen := map[string]bool{}
	for i := range profiles {
		p := &profiles[i]
		p.ID = strings.ToLower(strings.TrimSpace(p.ID))
		p.Label = strings.TrimSpace(p.Label)
		p.Category = strings.TrimSpace(p.Category)
		p.RepositoryURL = strings.TrimSpace(p.RepositoryURL)
		p.Chart = strings.TrimSpace(p.Chart)
		p.Version = strings.TrimSpace(p.Version)
		p.ReleaseName = strings.TrimSpace(p.ReleaseName)
		p.Namespace = strings.TrimSpace(p.Namespace)
		if !applicationIDPattern.MatchString(p.ID) || seen[p.ID] || p.Label == "" || p.Category == "" {
			return fmt.Errorf("%w: invalid or duplicate application profile", ErrValidation)
		}
		seen[p.ID] = true
		if !strings.HasPrefix(p.RepositoryURL, "https://") || strings.ContainsAny(p.RepositoryURL, " \t\r\n") {
			return fmt.Errorf("%w: application repository must use HTTPS", ErrValidation)
		}
		for _, token := range []string{p.Chart, p.ReleaseName, p.Namespace} {
			if !helmTokenPattern.MatchString(token) || strings.Contains(token, "..") {
				return fmt.Errorf("%w: invalid Helm application identity", ErrValidation)
			}
		}
		if (!helmTokenPattern.MatchString(p.Version) && !qualifiedChartVersion.MatchString(p.Version)) || strings.Contains(p.Version, "..") {
			return fmt.Errorf("%w: invalid Helm application version", ErrValidation)
		}
		for key, value := range p.Values {
			if !helmTokenPattern.MatchString(key) || strings.ContainsAny(value, "\r\n\x00") || len(value) > 4096 {
				return fmt.Errorf("%w: invalid fixed Helm value", ErrValidation)
			}
		}
		for _, dep := range p.Dependencies {
			if !applicationIDPattern.MatchString(dep) || dep == p.ID {
				return fmt.Errorf("%w: invalid application dependency", ErrValidation)
			}
		}
	}
	for _, p := range profiles {
		for _, dep := range p.Dependencies {
			if !seen[dep] {
				return fmt.Errorf("%w: unknown application dependency %q", ErrValidation, dep)
			}
		}
	}
	return nil
}

func applicationJobPath(workspace Workspace, appID string) string {
	return filepath.Join(workspace.Directory, ".layersentry-application-"+appID+".json")
}

func readApplicationJob(workspace Workspace, appID string) (*ApplicationInstallJob, error) {
	path := applicationJobPath(workspace, appID)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPortalBodyBytes {
		return nil, errors.New("invalid application job file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("existing application job cannot be opened")
	}
	defer f.Close()
	opened, statErr := f.Stat()
	current, currentErr := os.Lstat(path)
	if statErr != nil || currentErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return nil, errors.New("application job file changed during read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPortalBodyBytes+1))
	if err != nil || len(raw) > int(maxPortalBodyBytes) {
		return nil, errors.New("application job read is unavailable")
	}
	var job ApplicationInstallJob
	if err := applicationJSONFields(raw, "id cluster_id application status requested_at updated_at message evidence_label"); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&job); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || job.ID == "" || job.ClusterID != workspace.ClusterID || job.Application != appID || job.RequestedAt.IsZero() || job.UpdatedAt.Before(job.RequestedAt) {
		return nil, errors.New("invalid original application job")
	}
	switch job.Status {
	case "RUNNING", "UNKNOWN", "SUCCEEDED", "FAILED":
	default:
		return nil, errors.New("invalid original application job status")
	}
	return &job, nil
}

func writeApplicationJob(workspace Workspace, job ApplicationInstallJob) error {
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(workspace.Directory, ".layersentry-app-job-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, applicationJobPath(workspace, job.Application))
}

func newApplicationJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func applicationMutationAllowed(r *http.Request) bool {
	actor, ok := platformapi.ActorFromContext(r.Context())
	if !ok {
		return false
	}
	if actor.Oneadmin {
		return true
	}
	for _, role := range actor.Roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "owner", "admin", "cluster-admin", "kubernetes-admin", "k8s-admin":
			return true
		}
	}
	return false
}

func applicationProfile(profiles []ApplicationProfile, id string) (ApplicationProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return ApplicationProfile{}, false
}

func helmList(ctx context.Context, workspace Workspace, binary string) (helmInventory, error) {
	if binary == "" {
		return nil, errors.New("Helm inventory is not configured")
	}
	cmd := exec.CommandContext(ctx, binary, "list", "--all-namespaces", "--all", "--max", strconv.Itoa(maxHelmInventoryReleases), "--kubeconfig", workspace.Kubeconfig, "-o", "json")
	var output helmInventoryOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var rows []helmRelease
	if err := json.Unmarshal(output.buffer.Bytes(), &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) >= maxHelmInventoryReleases {
		return nil, errors.New("Helm inventory is incomplete")
	}
	out := make(helmInventory, len(rows))
	for _, row := range rows {
		revision, err := strconv.Atoi(row.Revision)
		if !applicationIDPattern.MatchString(row.Name) || !applicationIDPattern.MatchString(row.Namespace) || row.Chart == "" || strings.TrimSpace(row.Chart) != row.Chart || err != nil || revision < 1 || strconv.Itoa(revision) != row.Revision {
			return nil, errors.New("malformed Helm release identity")
		}
		switch row.Status {
		case "unknown", "deployed", "uninstalled", "superseded", "failed", "uninstalling", "pending-install", "pending-upgrade", "pending-rollback":
		default:
			return nil, errors.New("malformed Helm release status")
		}
		key := helmReleaseKey{row.Namespace, row.Name}
		if _, exists := out[key]; exists {
			return nil, errors.New("ambiguous Helm release identity")
		}
		out[key] = row
	}
	return out, nil
}

func (p *Portal) listApplications(w http.ResponseWriter, r *http.Request) {
	profiles, binary := cloneApplicationProfiles(p.Applications), p.HelmBinary
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	releases, err := helmList(r.Context(), workspace, binary)
	if err != nil {
		portalError(w, http.StatusBadGateway, errors.New("Helm inventory is unavailable"))
		return
	}
	items := make([]applicationState, 0, len(profiles))
	for _, profile := range profiles {
		item := applicationState{Profile: profile}
		if release, ok := releases.installed(profile); ok {
			item.Installed = true
			item.HelmChart = release.Chart
		}
		if job, err := readApplicationJob(workspace, profile.ID); err == nil {
			item.Job = job
		}
		items = append(items, item)
	}
	portalJSON(w, http.StatusOK, map[string]any{"applications": items})
}

func (p *Portal) installApplication(w http.ResponseWriter, r *http.Request) {
	if !applicationMutationAllowed(r) {
		portalError(w, http.StatusForbidden, errors.New("cluster administration authorization is required"))
		return
	}
	profiles, binary := cloneApplicationProfiles(p.Applications), p.HelmBinary
	workspace, err := p.resolve(r)
	if err != nil {
		portalError(w, http.StatusNotFound, err)
		return
	}
	profile, ok := applicationProfile(profiles, strings.TrimSpace(r.PathValue("app")))
	if !ok {
		portalError(w, http.StatusNotFound, errors.New("application is not in the LayerSentry catalog"))
		return
	}
	if _, supported := applicationChartIdentity(profile); !supported {
		portalError(w, http.StatusConflict, errors.New("application chart requires a qualified bare name and exact canonical version"))
		return
	}
	previous, previousErr := readApplicationJob(workspace, profile.ID)
	if previousErr != nil && !os.IsNotExist(previousErr) {
		portalError(w, http.StatusConflict, errors.New("previous application job evidence is unavailable; replay is blocked"))
		return
	}
	if previous != nil && (previous.Status == "UNKNOWN" || previous.Status == "RUNNING") {
		portalError(w, http.StatusConflict, errors.New("previous application installation outcome is unknown; automatic Helm replay is blocked"))
		return
	}
	status, err := p.Client.Status(r.Context(), workspace)
	if err != nil || !status.APIReady || status.ReadyControlPlanes != workspace.ExpectedCPNodes || status.KubeSystemNonReady != 0 {
		portalError(w, http.StatusConflict, errors.New("application install requires a healthy cluster"))
		return
	}
	releases, err := helmList(r.Context(), workspace, binary)
	if err != nil {
		portalError(w, http.StatusBadGateway, errors.New("Helm inventory is unavailable"))
		return
	}
	// Reserve only this process's existing per-application slot, then reload job
	// evidence after external callbacks. This is not a cross-process lease.
	key := registryKey(workspace.Tenant, workspace.ClusterID) + "/" + profile.ID
	p.appMu.Lock()
	if p.appRunning[key] {
		p.appMu.Unlock()
		portalError(w, http.StatusConflict, errors.New("application installation is already in progress"))
		return
	}
	p.appRunning[key] = true
	p.appMu.Unlock()
	workerOwnsReservation := false
	defer func() {
		if !workerOwnsReservation {
			p.appMu.Lock()
			delete(p.appRunning, key)
			p.appMu.Unlock()
		}
	}()
	previous, previousErr = readApplicationJob(workspace, profile.ID)
	if previousErr != nil && !os.IsNotExist(previousErr) {
		portalError(w, http.StatusConflict, errors.New("previous application job evidence is unavailable; replay is blocked"))
		return
	}
	if previous != nil && (previous.Status == "UNKNOWN" || previous.Status == "RUNNING") {
		portalError(w, http.StatusConflict, errors.New("previous application installation outcome is unknown; automatic Helm replay is blocked"))
		return
	}
	if release, installed := releases.installed(profile); installed {
		portalJSON(w, http.StatusOK, map[string]any{"installed": true, "chart": release.Chart})
		return
	}
	if _, present := releases[helmReleaseKey{profile.Namespace, profile.ReleaseName}]; present || previous != nil {
		portalError(w, http.StatusConflict, errors.New("existing application release or job cannot authorize automatic upgrade or replay"))
		return
	}
	for _, depID := range profile.Dependencies {
		dep, _ := applicationProfile(profiles, depID)
		if _, installed := releases.installed(dep); !installed {
			portalError(w, http.StatusConflict, fmt.Errorf("required application %s is not installed", dep.Label))
			return
		}
	}
	id, err := newApplicationJobID()
	if err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not create application job"))
		return
	}
	now := time.Now().UTC()
	job := ApplicationInstallJob{ID: id, ClusterID: workspace.ClusterID, Application: profile.ID, Status: "RUNNING", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"}
	if err := writeApplicationJob(workspace, job); err != nil {
		portalError(w, http.StatusInternalServerError, errors.New("could not persist application job"))
		return
	}
	workerOwnsReservation = true
	go p.runApplicationInstall(key, workspace, profile, job, binary)
	portalJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (p *Portal) runApplicationInstall(key string, workspace Workspace, profile ApplicationProfile, job ApplicationInstallJob, binary string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	args := []string{"upgrade", "--install", profile.ReleaseName, profile.Chart, "--repo", profile.RepositoryURL, "--version", profile.Version, "--namespace", profile.Namespace, "--kubeconfig", workspace.Kubeconfig, "--wait", "--timeout", "15m"}
	if profile.CreateNamespace {
		args = append(args, "--create-namespace")
	}
	keys := make([]string, 0, len(profile.Values))
	for key := range profile.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, valueKey := range keys {
		args = append(args, "--set-string", valueKey+"="+profile.Values[valueKey])
	}
	if err := exec.CommandContext(ctx, binary, args...).Run(); err != nil {
		job.Status = "UNKNOWN"
		job.Message = "Helm did not return a confirmed installation result; inventory cannot prove the original invocation; retry is blocked"
	} else if releases, err := helmList(ctx, workspace, binary); err != nil {
		job.Status = "UNKNOWN"
		job.Message = "Helm returned but installed-state readback is unavailable"
	} else if _, ok := releases.installed(profile); !ok {
		job.Status = "UNKNOWN"
		job.Message = "Helm returned but exact deployed namespace/release/chart/version is not confirmed"
	} else {
		job.Status = "SUCCEEDED"
		job.Message = "Helm invocation completed and exact deployed release inventory matched; application/PVC/DR health is not established"
	}
	job.UpdatedAt = time.Now().UTC()
	job.EvidenceLabel = "UNKNOWN"
	if job.Status == "SUCCEEDED" {
		job.EvidenceLabel = "HELM_RELEASE_CONFIRMED"
	}
	p.appMu.Lock()
	_ = writeApplicationJob(workspace, job)
	delete(p.appRunning, key)
	p.appMu.Unlock()
}
