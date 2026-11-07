package kubeone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/layersentry/layersentry-platform/internal/kubeone/statusreadback"
)

var ErrValidation = errors.New("kubeone adapter validation failed")

var kubernetesNamespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Workspace struct {
	Tenant                          string `json:"tenant"`
	ClusterID                       string `json:"cluster_id"`
	Directory                       string `json:"directory"`
	Manifest                        string `json:"manifest"`
	TFJSON                          string `json:"tfjson,omitempty"`
	Credentials                     string `json:"credentials,omitempty"`
	Kubeconfig                      string `json:"kubeconfig"`
	ExpectedCPNodes                 int    `json:"expected_control_planes,omitempty"`
	ExpectedNodes                   int    `json:"expected_nodes,omitempty"`
	AutonomousWorkerRepairQualified bool   `json:"autonomous_worker_repair_qualified,omitempty"`
}

type RegistryFile struct {
	Clusters []Workspace `json:"clusters"`
}

type Registry struct {
	root string
	byID map[string]Workspace
}

func NewRegistry(root string, cfg RegistryFile) (*Registry, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: workspace root is required", ErrValidation)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}
	out := &Registry{root: resolvedRoot, byID: map[string]Workspace{}}
	for _, item := range cfg.Clusters {
		if err := out.add(item); err != nil {
			return nil, err
		}
	}
	if len(out.byID) == 0 {
		return nil, fmt.Errorf("%w: workspace registry is empty", ErrValidation)
	}
	return out, nil
}

func LoadRegistry(root, path string) (*Registry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: registry file is required", ErrValidation)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg RegistryFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode kubeone registry: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: registry must contain exactly one JSON value", ErrValidation)
	}
	return NewRegistry(root, cfg)
}

func registryKey(tenant, clusterID string) string {
	tenant = strings.TrimSpace(tenant)
	clusterID = strings.TrimSpace(clusterID)
	return strconv.Itoa(len(tenant)) + ":" + tenant + clusterID
}

func (r *Registry) resolvePath(dir, value string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return "", fmt.Errorf("%w: required workspace file missing", ErrValidation)
		}
		return "", nil
	}
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("%w: workspace file must be relative to cluster directory", ErrValidation)
	}
	path := filepath.Join(dir, filepath.Clean(value))
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	rootPrefix := r.root + string(os.PathSeparator)
	if resolved != r.root && !strings.HasPrefix(resolved, rootPrefix) {
		return "", fmt.Errorf("%w: workspace path escapes configured root", ErrValidation)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: workspace path is not a regular file", ErrValidation)
	}
	return resolved, nil
}

func (r *Registry) add(item Workspace) error {
	item.Tenant = strings.TrimSpace(item.Tenant)
	item.ClusterID = strings.TrimSpace(item.ClusterID)
	if item.Tenant == "" || item.ClusterID == "" {
		return fmt.Errorf("%w: tenant and cluster_id are required", ErrValidation)
	}
	identity := item.Tenant + item.ClusterID
	if strings.ContainsRune(identity, '\r') || strings.ContainsRune(identity, '\n') || strings.IndexByte(identity, 0) >= 0 {
		return fmt.Errorf("%w: invalid tenant/cluster identity", ErrValidation)
	}
	if item.ExpectedCPNodes != 0 && (item.ExpectedCPNodes < 3 || item.ExpectedCPNodes%2 == 0) {
		return fmt.Errorf("%w: expected_control_planes must be odd and >=3", ErrValidation)
	}
	if item.ExpectedNodes != 0 && item.ExpectedNodes < item.ExpectedCPNodes {
		return fmt.Errorf("%w: expected_nodes cannot be smaller than expected_control_planes", ErrValidation)
	}
	if item.AutonomousWorkerRepairQualified {
		if item.ExpectedCPNodes < 3 || item.ExpectedNodes <= item.ExpectedCPNodes {
			return fmt.Errorf("%w: autonomous worker repair requires explicit expected_control_planes and expected_nodes with at least one worker", ErrValidation)
		}
	}
	dir := strings.TrimSpace(item.Directory)
	if dir == "" || filepath.IsAbs(dir) {
		return fmt.Errorf("%w: cluster directory must be relative to workspace root", ErrValidation)
	}
	joined := filepath.Join(r.root, filepath.Clean(dir))
	resolvedDir, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return fmt.Errorf("resolve cluster workspace: %w", err)
	}
	rootPrefix := r.root + string(os.PathSeparator)
	if resolvedDir != r.root && !strings.HasPrefix(resolvedDir, rootPrefix) {
		return fmt.Errorf("%w: cluster workspace escapes configured root", ErrValidation)
	}
	info, err := os.Stat(resolvedDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: cluster workspace is not a directory", ErrValidation)
	}
	manifest, err := r.resolvePath(resolvedDir, item.Manifest, true)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	kubeconfig, err := r.resolvePath(resolvedDir, item.Kubeconfig, true)
	if err != nil {
		return fmt.Errorf("kubeconfig: %w", err)
	}
	tfjson, err := r.resolvePath(resolvedDir, item.TFJSON, false)
	if err != nil {
		return fmt.Errorf("tfjson: %w", err)
	}
	credentials, err := r.resolvePath(resolvedDir, item.Credentials, false)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	item.Directory = resolvedDir
	item.Manifest = manifest
	item.Kubeconfig = kubeconfig
	item.TFJSON = tfjson
	item.Credentials = credentials

	key := registryKey(item.Tenant, item.ClusterID)
	if _, exists := r.byID[key]; exists {
		return fmt.Errorf("%w: duplicate tenant/cluster workspace", ErrValidation)
	}
	r.byID[key] = item
	return nil
}

func (r *Registry) List() []Workspace {
	if r == nil {
		return nil
	}
	out := make([]Workspace, 0, len(r.byID))
	for _, item := range r.byID {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant == out[j].Tenant {
			return out[i].ClusterID < out[j].ClusterID
		}
		return out[i].Tenant < out[j].Tenant
	})
	return out
}

func (r *Registry) Resolve(tenant, clusterID string) (Workspace, error) {
	if r == nil {
		return Workspace{}, errors.New("kubeone workspace registry is nil")
	}
	item, ok := r.byID[registryKey(tenant, clusterID)]
	if !ok {
		return Workspace{}, os.ErrNotExist
	}
	return item, nil
}

type CommandResult struct {
	Stdout string
	Stderr string
}

type Runner interface {
	Run(context.Context, string, string, []string, []string) (CommandResult, error)
}

type ExecRunner struct {
	Timeout time.Duration
	MaxOut  int
}

func (r ExecRunner) Run(ctx context.Context, dir, binary string, args, env []string) (CommandResult, error) {
	if strings.TrimSpace(binary) == "" {
		return CommandResult{}, fmt.Errorf("%w: binary is required", ErrValidation)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append([]string(nil), env...)
	}
	limit := r.MaxOut
	if limit <= 0 {
		limit = 2 << 20
	}
	var stdout, stderr limitedBuffer
	stdout.max = limit
	stderr.max = limit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if runCtx.Err() != nil {
		return result, fmt.Errorf("command timed out or canceled: %w", runCtx.Err())
	}
	if err != nil {
		return result, fmt.Errorf("command failed: %w: %s", err, strings.TrimSpace(result.Stderr))
	}
	return result, nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }

type ClientConfig struct {
	KubeOneBinary string
	KubectlBinary string
	Environment   []string
	Timeout       time.Duration
	PollInterval  time.Duration
}

type Client struct {
	registry *Registry
	runner   Runner
	cfg      ClientConfig
}

func NewClient(registry *Registry, runner Runner, cfg ClientConfig) (*Client, error) {
	if registry == nil {
		return nil, errors.New("kubeone client requires workspace registry")
	}
	if runner == nil {
		runner = ExecRunner{Timeout: cfg.Timeout}
	}
	cfg.KubeOneBinary = strings.TrimSpace(cfg.KubeOneBinary)
	cfg.KubectlBinary = strings.TrimSpace(cfg.KubectlBinary)
	if cfg.KubeOneBinary == "" || cfg.KubectlBinary == "" {
		return nil, fmt.Errorf("%w: kubeone and kubectl binary paths are required", ErrValidation)
	}
	for _, path := range []string{cfg.KubeOneBinary, cfg.KubectlBinary} {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%w: binary paths must be absolute", ErrValidation)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() || info.Mode()&0111 == 0 {
			return nil, fmt.Errorf("%w: binary is not executable: %s", ErrValidation, path)
		}
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	return &Client{registry: registry, runner: runner, cfg: cfg}, nil
}

func (c *Client) Workspace(tenant, clusterID string) (Workspace, error) {
	return c.registry.Resolve(tenant, clusterID)
}

func (c *Client) Workspaces() []Workspace {
	if c == nil || c.registry == nil {
		return nil
	}
	return c.registry.List()
}

type ApplyOptions struct {
	UpgradeMachineDeployments bool
	ForceUpgrade              bool
	NoInit                    bool
}

func (c *Client) Apply(ctx context.Context, ws Workspace, opts ApplyOptions) (CommandResult, error) {
	args := []string{"apply", "--manifest", ws.Manifest, "--auto-approve"}
	if ws.TFJSON != "" {
		args = append(args, "-t", ws.TFJSON)
	}
	if ws.Credentials != "" {
		args = append(args, "--credentials", ws.Credentials)
	}
	if opts.UpgradeMachineDeployments {
		args = append(args, "--upgrade-machine-deployments")
	}
	if opts.ForceUpgrade {
		args = append(args, "--force-upgrade")
	}
	if opts.NoInit {
		args = append(args, "--no-init")
	}
	return c.runner.Run(ctx, ws.Directory, c.cfg.KubeOneBinary, args, c.cfg.Environment)
}

type NodeStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	ControlPlane bool   `json:"control_plane"`
}

type Status struct {
	APIReady           bool         `json:"api_ready"`
	Nodes              []NodeStatus `json:"nodes"`
	ReadyNodes         int          `json:"ready_nodes"`
	ReadyControlPlanes int          `json:"ready_control_planes"`
	ControlPlanes      int          `json:"control_planes"`
	KubeSystemNonReady int          `json:"kube_system_non_ready"`
}

type Namespace struct {
	Name               string `json:"name"`
	LayerSentryManaged bool   `json:"layersentry_managed"`
}

func (c *Client) Namespaces(ctx context.Context, ws Workspace) ([]Namespace, error) {
	raw, err := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary, []string{"--kubeconfig", ws.Kubeconfig, "get", "namespaces", "-o", "json"}, c.cfg.Environment)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw.Stdout), &list); err != nil {
		return nil, fmt.Errorf("decode Kubernetes namespace inventory: %w", err)
	}
	out := make([]Namespace, 0, len(list.Items))
	for _, item := range list.Items {
		if item.Metadata.Name == "" {
			return nil, errors.New("Kubernetes namespace inventory contains an empty identity")
		}
		out = append(out, Namespace{Name: item.Metadata.Name, LayerSentryManaged: item.Metadata.Labels["layersentry.io/managed"] == "true"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *Client) CreateNamespace(ctx context.Context, ws Workspace, name string) (Namespace, bool, error) {
	name = strings.TrimSpace(name)
	if len(name) > 63 || !kubernetesNamespacePattern.MatchString(name) {
		return Namespace{}, false, fmt.Errorf("%w: invalid Kubernetes namespace", ErrValidation)
	}
	manifest := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}{APIVersion: "v1", Kind: "Namespace"}
	manifest.Metadata.Name = name
	manifest.Metadata.Labels = map[string]string{
		"app.kubernetes.io/managed-by": "layersentry",
		"layersentry.io/managed":       "true",
		"layersentry.io/tenant-hash":   shortIdentityHash(ws.Tenant),
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return Namespace{}, false, err
	}
	f, err := os.CreateTemp(ws.Directory, ".layersentry-namespace-*.json")
	if err != nil {
		return Namespace{}, false, err
	}
	path := f.Name()
	defer os.Remove(path)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return Namespace{}, false, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return Namespace{}, false, err
	}
	if err := f.Close(); err != nil {
		return Namespace{}, false, err
	}
	_, createErr := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary, []string{"--kubeconfig", ws.Kubeconfig, "create", "-f", path}, c.cfg.Environment)
	namespaces, readErr := c.Namespaces(ctx, ws)
	if readErr != nil {
		if createErr != nil {
			return Namespace{}, false, fmt.Errorf("namespace create outcome is unknown: %w", createErr)
		}
		return Namespace{}, false, fmt.Errorf("namespace post-create readback failed: %w", readErr)
	}
	for _, namespace := range namespaces {
		if namespace.Name != name {
			continue
		}
		if !namespace.LayerSentryManaged {
			return Namespace{}, false, errors.New("namespace exists but is not owned by LayerSentry")
		}
		return namespace, createErr == nil, nil
	}
	if createErr != nil {
		return Namespace{}, false, createErr
	}
	return Namespace{}, false, errors.New("namespace create did not converge in provider readback")
}

func shortIdentityHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:8])
}

func (c *Client) Status(ctx context.Context, ws Workspace) (Status, error) {
	base := []string{"--kubeconfig", ws.Kubeconfig}
	raw, err := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary, append(base, "get", "--raw=/readyz"), c.cfg.Environment)
	if err != nil {
		return Status{}, err
	}
	status := Status{APIReady: strings.TrimSpace(raw.Stdout) == "ok"}
	if !status.APIReady {
		return status, errors.New("kubernetes /readyz is not healthy")
	}

	nodesRaw, err := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary, append(base, "get", "nodes", "-o", "json"), c.cfg.Environment)
	if err != nil {
		return status, err
	}
	nodes, err := statusreadback.Nodes(nodesRaw.Stdout)
	if err != nil {
		return Status{}, fmt.Errorf("%w: invalid node health inventory", ErrValidation)
	}
	// A repeated or missing native node identity cannot prove membership or quorum.
	seenNodes := make(map[string]bool, len(nodes))
	for _, item := range nodes {
		name := item.Name
		if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name || seenNodes[name] {
			return Status{}, fmt.Errorf("%w: node inventory contains an empty, noncanonical or duplicate identity", ErrValidation)
		}
		seenNodes[name] = true
	}
	for _, item := range nodes {
		cp, ready := item.ControlPlane, item.Ready
		status.Nodes = append(status.Nodes, NodeStatus{Name: item.Name, Ready: ready, ControlPlane: cp})
		if ready {
			status.ReadyNodes++
		}
		if cp {
			status.ControlPlanes++
			if ready {
				status.ReadyControlPlanes++
			}
		}
	}

	podsRaw, err := c.runner.Run(ctx, ws.Directory, c.cfg.KubectlBinary, append(base, "get", "pods", "-n", "kube-system", "-o", "json"), c.cfg.Environment)
	if err != nil {
		return status, err
	}
	pods, err := statusreadback.Pods(podsRaw.Stdout)
	if err != nil {
		return Status{}, fmt.Errorf("%w: invalid kube-system health inventory", ErrValidation)
	}
	for _, item := range pods {
		switch item.Phase {
		case "Succeeded":
			continue
		case "Running":
			if item.ContainersReady {
				continue
			}
		}
		status.KubeSystemNonReady++
	}
	return status, nil
}

func (c *Client) WaitHealthy(ctx context.Context, ws Workspace, minimumReadyControlPlanes, expectedReadyNodes int) (Status, error) {
	if minimumReadyControlPlanes < 1 {
		minimumReadyControlPlanes = 1
	}
	interval := c.cfg.PollInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var last Status
	var lastErr error
	for {
		last, lastErr = c.Status(ctx, ws)
		if lastErr == nil &&
			last.APIReady &&
			last.ReadyControlPlanes >= minimumReadyControlPlanes &&
			(expectedReadyNodes <= 0 || last.ReadyNodes >= expectedReadyNodes) &&
			last.KubeSystemNonReady == 0 {
			return last, nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return last, fmt.Errorf("kubeone post-apply health did not converge: %v: %w", lastErr, ctx.Err())
			}
			return last, fmt.Errorf("kubeone post-apply health did not converge: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func ParsePositiveIntMetadata(metadata map[string]string, key string) (int, error) {
	raw := strings.TrimSpace(metadata[key])
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%w: metadata %s must be a non-negative integer", ErrValidation, key)
	}
	return value, nil
}
