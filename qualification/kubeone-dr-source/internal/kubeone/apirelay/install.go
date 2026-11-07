package apirelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	installRoot       = "/var/lib/layersentry/native-qualification/dc"
	installName       = "dc-kubeone-go-api-relay-20261006"
	registryPath      = "/etc/layersentry/kubeone-registry.json"
	runtimePath       = "/usr/local/libexec/layersentry-kubeone-dc-api-relay"
	runtimeConfigPath = "/etc/layersentry/kubeone-api-relay-dc.json"
	unitName          = "layersentry-kubeone-dc-api-relay.service"
	unitPath          = "/etc/systemd/system/" + unitName
	originalJobID     = "8334be49cc24f22dda468754b1335ade"
	legacyHelperSHA   = "22fc58599e26d9b96c2ffd98de263c7e89765c305fa2b355c7e3969d4457a623"
	legacyUnitSHA     = "41afce65acc3bdf4610ee6bc1afaa0177393ae4d09234594ddbe0778ad5768de"
)

// Artifact is public build identity, never a credential or execution override.
type Artifact struct{ Path, SHA256, SourceCommit string }
type installProof struct {
	Address    string `json:"address"`
	VMID       int    `json:"vm_id"`
	UUID       string `json:"uuid"`
	ReceiptSHA string `json:"creation_receipt_sha256"`
}
type installRecord struct {
	Schema        string         `json:"schema"`
	Phase         string         `json:"phase"`
	Source        string         `json:"source_commit"`
	BinarySHA     string         `json:"binary_sha256"`
	OriginalSHA   string         `json:"original_registry_sha256"`
	JobSHA        string         `json:"original_job_sha256"`
	CredentialSHA string         `json:"credential_sha256"`
	Proofs        []installProof `json:"targets"`
	Scope         string         `json:"scope"`
}

// This separate private runtime file makes a crash between intent and workspace
// credential publication recoverable. It is never an evidence/export document.
type privateCredentialStage struct {
	Schema      string      `json:"schema"`
	Source      string      `json:"source_commit"`
	BinarySHA   string      `json:"binary_sha256"`
	JobSHA      string      `json:"job_sha256"`
	OriginalSHA string      `json:"registry_sha256"`
	Credential  Credentials `json:"credential"`
}

func digest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
func exactHex(value string, size int) bool {
	return len(value) == size && strings.Trim(value, "0123456789abcdef") == ""
}

func installJob(raw []byte) error {
	var j struct {
		ID       string `json:"id"`
		Cluster  string `json:"cluster_id"`
		Status   string `json:"status"`
		Ready    int    `json:"ready_nodes"`
		Expected int    `json:"expected_nodes"`
	}
	if json.Unmarshal(raw, &j) != nil || j.ID != originalJobID || j.Cluster != "kubeone-dc" || j.Status != "UNKNOWN" || j.Ready != 0 || j.Expected != 4 {
		return errors.New("relay installation requires the exact original UNKNOWN DC job")
	}
	return nil
}

func installParents(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid relay publication path")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		s, err := os.Lstat(dir)
		if err != nil {
			return errors.New("relay publication parent unavailable")
		}
		n, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || n.Uid != 0 && n.Uid != uid {
			return errors.New("relay publication parent custody differs")
		}
		if dir == "/" {
			return nil
		}
	}
}

// Existing objects are admitted by bytes as well as custody. In particular,
// installation never adopts an arbitrary file merely because root owns it.
func publishOwned(path string, raw []byte, uid, gid uint32, mode os.FileMode, allowed ...string) error {
	if err := installParents(path, uid); err != nil {
		return err
	}
	if s, err := os.Lstat(path); err == nil {
		n, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.Mode().IsRegular() || n.Uid != uid || n.Gid != gid || n.Nlink != 1 || s.Mode().Perm() != mode {
			return errors.New("foreign relay publication target")
		}
		prior, e := protected(path, uid, gid, s.Mode().Perm(), 128<<20)
		if e != nil {
			return e
		}
		match := digest(prior) == digest(raw)
		for _, want := range allowed {
			if digest(prior) == want {
				match = true
			}
		}
		if !match {
			return errors.New("relay publication content conflicts")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("relay publication target unavailable")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".api-relay-")
	if err != nil {
		return errors.New("relay staging failed")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		err = f.Chown(int(uid), int(gid))
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil {
		return errors.New("relay staged publication failed")
	}
	if os.Rename(f.Name(), path) != nil {
		return errors.New("relay atomic publication failed")
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("relay directory unavailable")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("relay directory sync failed")
	}
	return nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("native output exceeds relay bound")
	}
	return b.Buffer.Write(p)
}
func nativeInstall(ctx context.Context, program string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.WaitDelay = time.Second
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("native relay operation failed")
	}
	return out.Bytes(), nil
}

func proveInstallPeers(ctx context.Context, p siteProfile, key string) ([]installProof, []byte, error) {
	var proofs []installProof
	var pins bytes.Buffer
	for i, peer := range p.peers {
		op := fmt.Sprintf("k1-dc-lb%d-20261005", i+1)
		raw, err := protected("/var/lib/layersentry/native-lab/receipts/dc-kubeone/"+op+".json", 0, 0, 0600, 65536)
		if err != nil {
			return nil, nil, err
		}
		var r struct {
			Schema    string `json:"schema"`
			Site      string `json:"site_id"`
			Role      string `json:"site_role"`
			Resource  string `json:"resource"`
			Operation string `json:"operation_id"`
			Phase     string `json:"phase"`
			Observed  struct {
				ID     int    `json:"id"`
				UUID   string `json:"uuid"`
				Secure bool   `json:"secure_boot"`
				TPM    bool   `json:"tpm"`
			} `json:"observed"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Schema != "layersentry-native-lab-receipt/v1" || r.Site != "lab-dc" || r.Role != "dc" || r.Resource != "vm" || r.Operation != op || r.Phase != "RELEASED" || r.Observed.ID != 10+i || !r.Observed.Secure || !r.Observed.TPM || len(r.Observed.UUID) != 36 {
			return nil, nil, errors.New("native LB receipt differs")
		}
		found, err := nativeInstall(ctx, "/usr/bin/ssh-keygen", "-F", peer, "-f", "/root/.ssh/known_hosts")
		if err != nil {
			return nil, nil, err
		}
		var match []string
		for _, line := range strings.Split(string(found), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[1] == "ssh-ed25519" {
				match = append(match, peer+" ssh-ed25519 "+f[2]+"\n")
			}
		}
		if len(match) != 1 {
			return nil, nil, errors.New("exact established LB SSH pin required")
		}
		pins.WriteString(match[0])
		ssh := &sshTransport{key: key, pins: "/root/.ssh/known_hosts"}
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		observed, err := nativeInstall(probeCtx, "/usr/bin/ssh", append(ssh.args(), "ubuntu@"+peer, "sudo -n /usr/bin/cat /sys/class/dmi/id/product_uuid")...)
		cancel()
		if err != nil || strings.ToLower(strings.TrimSpace(string(observed))) != r.Observed.UUID {
			return nil, nil, errors.New("live LB UUID differs from native creation receipt")
		}
		proofs = append(proofs, installProof{peer, r.Observed.ID, r.Observed.UUID, digest(raw)})
	}
	if err := validatePins(pins.Bytes(), p.peers); err != nil {
		return nil, nil, err
	}
	return proofs, pins.Bytes(), nil
}

func desiredRegistry(original []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(original, &doc) != nil {
		return nil, errors.New("registry unavailable")
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(doc["clusters"], &entries) != nil {
		return nil, errors.New("registry clusters unavailable")
	}
	count := 0
	str := func(entry map[string]json.RawMessage, key string) string {
		var s string
		_ = json.Unmarshal(entry[key], &s)
		return s
	}
	for _, entry := range entries {
		if str(entry, "tenant") != "lab-dc" || str(entry, "cluster_id") != "kubeone-dc" {
			continue
		}
		count++
		if str(entry, "directory") != "lab-dc/kubeone-dc" || str(entry, "api_proxy_url") != "" && str(entry, "api_proxy_url") != "socks5://127.0.0.1:19446" || str(entry, "api_proxy_credentials") != "" && str(entry, "api_proxy_credentials") != "api-relay-credentials.json" {
			return nil, errors.New("registry relay ownership differs")
		}
		entry["api_proxy_url"] = json.RawMessage(`"socks5://127.0.0.1:19446"`)
		entry["api_proxy_credentials"] = json.RawMessage(`"api-relay-credentials.json"`)
	}
	if count != 1 {
		return nil, errors.New("one exact registered DC workspace required")
	}
	doc["clusters"], _ = json.Marshal(entries)
	return json.Marshal(doc)
}

func relayUnit() []byte {
	return []byte(`[Unit]
Description=LayerSentry authenticated native DC Kubernetes API relay
After=network-online.target
Wants=network-online.target
[Service]
User=oneadmin
Group=oneadmin
ExecStart=/usr/local/libexec/layersentry-kubeone-dc-api-relay /etc/layersentry/kubeone-api-relay-dc.json
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/var/lib/layersentry/kubeone/lab-dc/kubeone-dc
[Install]
WantedBy=multi-user.target
`)
}

func servicePID(ctx context.Context) (int, error) {
	raw, err := nativeInstall(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", unitName)
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || e != nil || pid < 2 {
		return 0, errors.New("relay service has no main process")
	}
	return pid, nil
}

// Inspect native socket/process ownership; a successful TCP dial alone cannot
// distinguish this relay from an unrelated process occupying its endpoint.
func listenerOwner(uid uint32, mainPID int, allowChildren bool) error {
	return listenerOwnerAt(uid, mainPID, allowChildren, 19446)
}

func listenerOwnerAt(uid uint32, mainPID int, allowChildren bool, port uint16) error {
	portHex := fmt.Sprintf("%04X", port)
	allowed := map[int]bool{mainPID: true}
	if allowChildren {
		queue := []int{mainPID}
		for len(queue) > 0 {
			pid := queue[0]
			queue = queue[1:]
			raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
			if err != nil {
				return errors.New("relay process lineage unavailable")
			}
			for _, f := range strings.Fields(string(raw)) {
				child, e := strconv.Atoi(f)
				if e != nil || len(allowed) > 64 {
					return errors.New("relay process lineage differs")
				}
				if !allowed[child] {
					allowed[child] = true
					queue = append(queue, child)
				}
			}
		}
	}
	var inodes []string
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return errors.New("native relay socket table unavailable")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 || parts[1] != portHex {
				continue
			}
			if f[1] != "0100007F:"+portHex || f[7] != strconv.FormatUint(uint64(uid), 10) {
				return errors.New("foreign relay listener")
			}
			inodes = append(inodes, f[9])
		}
	}
	if len(inodes) != 1 {
		return errors.New("one exact relay listener required")
	}
	for pid := range allowed {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
			if e == nil && target == "socket:["+inodes[0]+"]" {
				return nil
			}
		}
	}
	return errors.New("relay listener is not owned by its service")
}

func readiness(ctx context.Context, address string, credential Credentials) error {
	for mode := 0; mode < 3; mode++ {
		if err := readinessAttempt(ctx, address, credential, mode); err != nil {
			return err
		}
	}
	return nil
}
func readinessAttempt(ctx context.Context, address string, credential Credentials, mode int) error {
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp4", address)
	if err != nil {
		return errors.New("relay readiness connection failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	exchange := func(request []byte, n int) ([]byte, error) {
		if _, e := conn.Write(request); e != nil {
			return nil, e
		}
		b := make([]byte, n)
		_, e := io.ReadFull(conn, b)
		return b, e
	}
	if mode == 0 {
		r, e := exchange([]byte{5, 1, 0}, 2)
		if e != nil || !bytes.Equal(r, []byte{5, 255}) {
			return errors.New("relay allowed unauthenticated access")
		}
		return nil
	}
	r, e := exchange([]byte{5, 1, 2}, 2)
	if e != nil || !bytes.Equal(r, []byte{5, 2}) {
		return errors.New("relay authentication method differs")
	}
	password := credential.Password
	if mode == 1 {
		password = strings.Repeat("!", 32)
	}
	request := append([]byte{1, byte(len(credential.Username))}, credential.Username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	r, e = exchange(request, 2)
	want := byte(0)
	if mode == 1 {
		want = 1
	}
	if e != nil || !bytes.Equal(r, []byte{1, want}) {
		return errors.New("relay credential admission differs")
	}
	if mode == 1 {
		return nil
	}
	r, e = exchange([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 22}, 10)
	if e != nil || len(r) != 10 || r[0] != 5 || r[1] != 2 {
		return errors.New("relay foreign-destination denial differs")
	}
	return nil
}

// Install only replaces this campaign's exact legacy relay or resumes this
// intent's own bytes. It never invokes KubeOne or a provider mutation.
func Install(ctx context.Context, artifact Artifact) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("relay installer requires root")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if !exactHex(artifact.SHA256, 64) || !exactHex(artifact.SourceCommit, 40) {
		return errors.New("exact relay artifact identity required")
	}
	artifactInfo, err := os.Lstat(artifact.Path)
	if err != nil || artifactInfo.Mode().Perm() != 0700 && artifactInfo.Mode().Perm() != 0755 {
		return errors.New("relay artifact mode differs")
	}
	binary, err := protected(artifact.Path, 0, 0, artifactInfo.Mode().Perm(), 128<<20)
	if err != nil {
		return err
	}
	if digest(binary) != artifact.SHA256 {
		return errors.New("relay artifact digest differs")
	}
	build, err := buildinfo.ReadFile(artifact.Path)
	if err != nil || build.Path != "github.com/layersentry/layersentry-platform/cmd/layersentry-kubeone-api-relay" {
		return errors.New("relay artifact build identity unavailable")
	}
	settings := map[string]string{}
	for _, s := range build.Settings {
		settings[s.Key] = s.Value
	}
	if settings["vcs.revision"] != artifact.SourceCommit || settings["vcs.modified"] != "false" {
		return errors.New("relay artifact source identity differs")
	}
	u, err := user.Lookup("oneadmin")
	if err != nil {
		return errors.New("relay account unavailable")
	}
	uid64, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid64, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil {
		return errors.New("relay account differs")
	}
	uid, gid := uint32(uid64), uint32(gid64)
	p, _ := profileFor("dc")
	if err = installParents(installRoot+"/owner.lock", 0); err != nil {
		return err
	}
	fd, err := syscall.Open(installRoot+"/owner.lock", syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("native owner lock unavailable")
	}
	lock := os.NewFile(uintptr(fd), "native-owner-lock")
	defer lock.Close()
	ls, e := lock.Stat()
	if e != nil {
		return errors.New("native owner lock stat failed")
	}
	ln, ok := ls.Sys().(*syscall.Stat_t)
	if !ok || !ls.Mode().IsRegular() || ls.Mode().Perm() != 0600 || ln.Uid != 0 || ln.Gid != 0 || ln.Nlink != 1 {
		return errors.New("native owner lock custody differs")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("native qualification owner busy")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	jobPath := p.workspace + "/.layersentry-provision.json"
	job, err := protected(jobPath, uid, gid, 0600, 65536)
	if err != nil {
		return err
	}
	if err = installJob(job); err != nil {
		return err
	}
	if _, err = protected(p.workspace+"/ssh-private-key", uid, gid, 0600, 65536); err != nil {
		return err
	}
	rootPins, err := os.Lstat("/root/.ssh/known_hosts")
	if err != nil {
		return errors.New("established SSH pins unavailable")
	}
	if rootPins.Mode().Perm() != 0600 && rootPins.Mode().Perm() != 0644 {
		return errors.New("established SSH pin custody differs")
	}
	if _, err = protected("/root/.ssh/known_hosts", 0, 0, rootPins.Mode().Perm(), 1<<20); err != nil {
		return err
	}
	proofs, pins, err := proveInstallPeers(ctx, p, p.workspace+"/ssh-private-key")
	if err != nil {
		return err
	}
	unit := relayUnit()
	// Reject foreign target bytes before any service or filesystem publication.
	existingArtifacts := 0
	for path, hashes := range map[string][]string{runtimePath: {legacyHelperSHA, artifact.SHA256}, unitPath: {legacyUnitSHA, digest(unit)}} {
		if err = installParents(path, 0); err != nil {
			return err
		}
		if s, e := os.Lstat(path); e == nil {
			mode := os.FileMode(0755)
			if path == unitPath {
				mode = 0644
			}
			if s.Mode().Perm() != mode {
				return errors.New("installed relay artifact mode differs")
			}
			data, e := protected(path, 0, 0, mode, 128<<20)
			if e != nil {
				return e
			}
			match := false
			for _, h := range hashes {
				match = match || digest(data) == h
			}
			if !match {
				return errors.New("foreign installed relay artifact")
			}
			existingArtifacts++
		} else if !errors.Is(e, os.ErrNotExist) {
			return errors.New("installed relay artifact unavailable")
		}
	}
	probe, e := net.Listen("tcp4", p.listen)
	if e == nil {
		probe.Close()
	} else {
		if existingArtifacts != 2 {
			return errors.New("occupied relay endpoint lacks exact installed artifact custody")
		}
		pid, e := servicePID(ctx)
		if e != nil {
			return e
		}
		if e = listenerOwner(uid, pid, true); e != nil {
			return e
		}
	}
	registry, err := protected(registryPath, 0, gid, 0640, 1<<20)
	if err != nil {
		return err
	}
	marker := installRoot + "/" + installName + ".json"
	backup := installRoot + "/" + installName + ".original-registry.json"
	original := registry
	var prior installRecord
	var priorRaw []byte
	if _, e := os.Lstat(marker); e == nil {
		priorRaw, err = protected(marker, 0, 0, 0600, 65536)
		if err != nil {
			return err
		}
		if decode(priorRaw, &prior) != nil {
			return errors.New("relay intent malformed")
		}
		original, err = protected(backup, 0, 0, 0600, 1<<20)
		if err != nil {
			return err
		}
		if digest(original) != prior.OriginalSHA {
			return errors.New("original relay registry differs")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errors.New("relay intent unavailable")
	}
	desired, err := desiredRegistry(original)
	if err != nil {
		return err
	}
	if digest(registry) != digest(original) && digest(registry) != digest(desired) {
		return errors.New("registry changed outside relay intent")
	}
	credentialPath := p.workspace + "/api-relay-credentials.json"
	privateStagePath := installRoot + "/" + installName + ".private-credential.json"
	privateStage := privateCredentialStage{Schema: "layersentry-relay-private-credential/v1", Source: artifact.SourceCommit, BinarySHA: artifact.SHA256, JobSHA: digest(job), OriginalSHA: digest(original)}
	if _, e := os.Lstat(privateStagePath); e == nil {
		raw, e := protected(privateStagePath, 0, 0, 0600, 8192)
		if e != nil {
			return e
		}
		var saved privateCredentialStage
		if decode(raw, &saved) != nil || !privateToken(saved.Credential.Username) || !privateToken(saved.Credential.Password) {
			return errors.New("private relay credential stage differs")
		}
		privateStage.Credential = saved.Credential
		a, _ := json.Marshal(privateStage)
		b, _ := json.Marshal(saved)
		if !bytes.Equal(a, b) {
			return errors.New("private relay credential stage conflicts")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		if prior.Schema != "" {
			return errors.New("owned private relay credential stage missing")
		}
		if _, e = os.Lstat(credentialPath); !errors.Is(e, os.ErrNotExist) {
			return errors.New("unowned relay credential")
		}
		a, b := make([]byte, 32), make([]byte, 32)
		if _, err = rand.Read(a); err != nil {
			return errors.New("relay credential generation failed")
		}
		if _, err = rand.Read(b); err != nil {
			return errors.New("relay credential generation failed")
		}
		privateStage.Credential = Credentials{hex.EncodeToString(a), hex.EncodeToString(b)}
	} else {
		return errors.New("private relay credential stage unavailable")
	}
	credential := privateStage.Credential
	secret, _ := json.Marshal(credential)
	record := installRecord{"layersentry-kubeone-go-api-relay/v1", "PREPARING", artifact.SourceCommit, artifact.SHA256, digest(original), digest(job), digest(secret), proofs, "AUTHENTICATED_PINNED_TRANSPORT_NOT_API_READY_OR_KUBERNETES_PASS"}
	if prior.Schema != "" {
		if prior.Phase != "PREPARING" && prior.Phase != "VERIFIED" {
			return errors.New("relay intent phase differs")
		}
		prior.Phase = "PREPARING"
		a, _ := json.Marshal(prior)
		b, _ := json.Marshal(record)
		if !bytes.Equal(a, b) {
			return errors.New("relay intent conflicts")
		}
	}
	if err = publishOwned(backup, original, 0, 0, 0600); err != nil {
		return err
	}
	privateRaw, _ := json.Marshal(privateStage)
	if err = publishOwned(privateStagePath, privateRaw, 0, 0, 0600); err != nil {
		return err
	}
	stage, _ := json.Marshal(record)
	if err = publishOwned(marker, stage, 0, 0, 0600, digest(priorRaw)); err != nil {
		return err
	}
	if err = publishOwned(credentialPath, secret, uid, gid, 0600); err != nil {
		return err
	}
	cfg := Config{Site: "dc", ListenAddress: p.listen, SSHPrivateKey: p.workspace + "/ssh-private-key", KnownHosts: p.workspace + "/api-relay-known-hosts", CredentialsFile: credentialPath}
	cfgRaw, _ := json.Marshal(cfg)
	for _, item := range []struct {
		path     string
		raw      []byte
		uid, gid uint32
		mode     os.FileMode
		allowed  []string
	}{
		{cfg.KnownHosts, pins, uid, gid, 0600, nil}, {runtimePath, binary, 0, 0, 0755, []string{legacyHelperSHA}},
		{runtimeConfigPath, cfgRaw, 0, gid, 0640, nil}, {unitPath, unit, 0, 0, 0644, []string{legacyUnitSHA}},
	} {
		if err = publishOwned(item.path, item.raw, item.uid, item.gid, item.mode, item.allowed...); err != nil {
			return err
		}
	}
	current, err := protected(jobPath, uid, gid, 0600, 65536)
	if err != nil || !bytes.Equal(current, job) {
		return errors.New("provision job changed before relay activation")
	}
	if _, err = nativeInstall(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err = nativeInstall(ctx, "/usr/bin/systemctl", "enable", unitName); err != nil {
		return err
	}
	if _, err = nativeInstall(ctx, "/usr/bin/systemctl", "restart", unitName); err != nil {
		return err
	}
	var pid int
	readyCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	for {
		pid, err = servicePID(readyCtx)
		if err == nil {
			err = listenerOwner(uid, pid, false)
		}
		if err == nil {
			err = readiness(readyCtx, p.listen, credential)
		}
		if err == nil {
			break
		}
		select {
		case <-readyCtx.Done():
			return errors.New("relay readiness not established; registry not published")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); e != nil || exe != runtimePath {
		return errors.New("relay running executable differs")
	}
	current, err = protected(jobPath, uid, gid, 0600, 65536)
	if err != nil || !bytes.Equal(current, job) {
		return errors.New("provision job changed before registry publication")
	}
	currentRegistry, err := protected(registryPath, 0, gid, 0640, 1<<20)
	if err != nil || !bytes.Equal(currentRegistry, registry) {
		return errors.New("registry changed during relay installation")
	}
	published := true
	defer func() {
		if err != nil && published {
			if rollback := publishOwned(registryPath, original, 0, gid, 0640, digest(desired)); rollback != nil {
				err = errors.New("relay finalization failed and registry rollback requires reconciliation")
			}
		}
	}()
	if err = publishOwned(registryPath, desired, 0, gid, 0640, digest(registry)); err != nil {
		return err
	}
	if check, e := servicePID(ctx); e != nil || check != pid {
		return errors.New("relay process changed during publication")
	}
	if err = listenerOwner(uid, pid, false); err != nil {
		return err
	}
	if err = readiness(ctx, p.listen, credential); err != nil {
		return err
	}
	record.Phase = "VERIFIED"
	complete, _ := json.Marshal(record)
	if err = publishOwned(marker, complete, 0, 0, 0600, digest(stage)); err != nil {
		return err
	}
	published = false
	return nil
}
