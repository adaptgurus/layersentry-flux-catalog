package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type installerHarness struct {
	dir, config, script, effects, trace string
	env                                 []string
}

// Only this disposable test copy substitutes paths and the root guard. Every
// native service/install command is an inert double; only the owned test
// build directory can be removed. No service or installed path is changed. The shipping script and its root admission remain intact.
func newInstallerHarness(t *testing.T) installerHarness {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "deploy/kubeone/install-portal.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := installerHarness{dir: dir, config: filepath.Join(dir, "config"), effects: filepath.Join(dir, "effects"), trace: filepath.Join(dir, "trace")}
	bin := filepath.Join(dir, "bin")
	for _, path := range []string{bin, h.config, filepath.Join(dir, "units"), filepath.Join(dir, "systemd")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\nset -eu\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("systemctl", `if [[ "$1" == show ]]; then
  for arg in "$@"; do requested_unit="$arg"; done
  case "$requested_unit" in
    lsportalreadiness*.service)
      if [[ "$INSTALLER_TEST_PROBE_OVERRIDE" == 1 ]]; then
        printf 'Id=%s\nLoadState=loaded\nDropInPaths=/test/probe.conf\nEnvironment=\n' "$requested_unit"
      else
        printf 'Id=%s\nLoadState=not-found\nDropInPaths=\nEnvironment=\n' "$requested_unit"
      fi
      exit 0 ;;
  esac
  printf 'Id=%s\nLoadState=%s\nDropInPaths=%s\nEnvironment=%s\n' "$INSTALLER_TEST_UNIT_ID" "$INSTALLER_TEST_LOAD_STATE" "$INSTALLER_TEST_DROPINS" "$INSTALLER_TEST_ENVIRONMENT"
  exit 0
fi
printf 'systemctl %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
printf 'systemctl %s\n' "$1" >> "$INSTALLER_TEST_EFFECTS"
`)
	write("systemd-analyze", `printf '%s/units\n' "$INSTALLER_TEST_ROOT"
`)
	write("selinuxenabled", `printf 'selinuxenabled\n' >> "$INSTALLER_TEST_TRACE"
exit "$INSTALLER_TEST_SELINUX_STATUS"
`)
	write("matchpathcon", `[[ "$#" == 2 && "$1" == -n && "$2" == "$INSTALLER_TEST_ROOT/libexec/layersentry-kubeone-portal" ]] || exit 84
printf 'matchpathcon %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
[[ "$INSTALLER_TEST_CONTEXT_RESOLVE_FAIL" == 0 ]] || exit 85
printf '%s\n' "$INSTALLER_TEST_POLICY_CONTEXT"
`)
	write("chcon", `[[ "$#" == 3 && "$1" == -- && "$2" == "$INSTALLER_TEST_POLICY_CONTEXT" && "$3" == "$INSTALLER_TEST_ROOT"/build.*/layersentry-kubeone-portal ]] || exit 86
printf 'chcon %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
[[ "$INSTALLER_TEST_CONTEXT_APPLY_FAIL" == 0 ]] || exit 87
`)
	write("stat", `[[ "$#" == 3 && "$1" == --format=%C && "$2" == -- ]] || exit 88
case "$3" in
  "$INSTALLER_TEST_ROOT"/build.*/layersentry-kubeone-portal) mismatch="$INSTALLER_TEST_CANDIDATE_CONTEXT_MISMATCH" ;;
  "$INSTALLER_TEST_ROOT/libexec/layersentry-kubeone-portal") mismatch="$INSTALLER_TEST_INSTALLED_CONTEXT_MISMATCH" ;;
  *) exit 89 ;;
esac
printf 'stat %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
if [[ "$mismatch" == 1 ]]; then
  printf 'system_u:object_r:unexpected_fixture_t:s0\n'
else
  printf '%s\n' "$INSTALLER_TEST_POLICY_CONTEXT"
fi
`)
	write("systemd-run", `printf 'probe %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
case "$*" in
  *--check-readiness-config*)
    [[ "$INSTALLER_TEST_PROBE_FAIL" == 0 ]] || exit 79 ;;
  *--check-ready*) [[ "$INSTALLER_TEST_FINAL_FAIL" == 0 ]] || exit 81 ;;
  *) exit 80 ;;
esac
`)
	write("install", `printf 'install %s\n' "$*" >> "$INSTALLER_TEST_TRACE"
printf 'install\n' >> "$INSTALLER_TEST_EFFECTS"
`)
	for _, name := range []string{"chown", "chmod"} {
		write(name, `case "$*" in
  *"$INSTALLER_TEST_ROOT/config"*|*"$INSTALLER_TEST_ROOT/libexec"*|*"$INSTALLER_TEST_ROOT/systemd"*)
    printf 'installed-file-metadata\n' >> "$INSTALLER_TEST_EFFECTS" ;;
esac
`)
	}
	write("mktemp", `/usr/bin/mktemp -d "$INSTALLER_TEST_ROOT/build.XXXXXXXX"
`)
	// Only removal of this harness's immediate owned build directory is real.
	// Installation and service operations remain inert command doubles.
	write("rm", `[[ "$#" == 3 && "$1" == -rf && "$2" == -- ]] || exit 82
[[ "${3%/*}" == "$INSTALLER_TEST_ROOT" && "${3##*/}" == build.* && -d "$3" && ! -L "$3" ]] || exit 83
printf 'cleanup %s\n' "$3" >> "$INSTALLER_TEST_TRACE"
/usr/bin/rm -rf -- "$3"
`)
	for _, name := range []string{"go", "id", "kubeone", "kubectl", "helm", "curl"} {
		write(name, "exit 0\n")
	}
	script := string(raw)
	script = strings.ReplaceAll(script, "$"+"{EUID}", "0")
	script = strings.ReplaceAll(script, "$EUID", "0")
	for from, to := range map[string]string{
		"/usr/local/libexec":           filepath.Join(dir, "libexec"),
		"/etc/layersentry":             h.config,
		"/var/lib/layersentry/kubeone": filepath.Join(dir, "workspace"),
		"/etc/systemd/system":          filepath.Join(dir, "systemd"),
		"/sys/fs/selinux/enforce":      filepath.Join(dir, "selinux-enforce"),
		"/usr/local/bin/kubeone":       filepath.Join(bin, "kubeone"),
		"/usr/bin/kubectl":             filepath.Join(bin, "kubectl"),
		"/usr/local/bin/helm":          filepath.Join(bin, "helm"),
	} {
		script = strings.ReplaceAll(script, from, to)
	}
	h.script = filepath.Join(dir, "install.sh")
	if err := os.WriteFile(h.script, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h.env = append(os.Environ(),
		"PATH="+bin+":/usr/bin:/bin",
		"INSTALLER_TEST_ROOT="+dir,
		"INSTALLER_TEST_TRACE="+h.trace,
		"INSTALLER_TEST_EFFECTS="+h.effects,
		"INSTALLER_TEST_DROPINS=",
		"INSTALLER_TEST_ENVIRONMENT=",
		"INSTALLER_TEST_PROBE_FAIL=0",
		"INSTALLER_TEST_FINAL_FAIL=0",
		"INSTALLER_TEST_PROBE_OVERRIDE=0",
		"INSTALLER_TEST_LOAD_STATE=loaded",
		"INSTALLER_TEST_UNIT_ID=layersentry-kubeone-portal.service",
		"INSTALLER_TEST_SELINUX_STATUS=1",
		"INSTALLER_TEST_POLICY_CONTEXT=system_u:object_r:fixture_policy_exec_t:s0",
		"INSTALLER_TEST_CONTEXT_RESOLVE_FAIL=0",
		"INSTALLER_TEST_CONTEXT_APPLY_FAIL=0",
		"INSTALLER_TEST_CANDIDATE_CONTEXT_MISMATCH=0",
		"INSTALLER_TEST_INSTALLED_CONTEXT_MISMATCH=0",
	)
	return h
}

func (h installerHarness) configure(t *testing.T, registry bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.config, "kubeone-portal.env"), []byte("TEST_PROFILE=present\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if registry {
		if err := os.WriteFile(filepath.Join(h.config, "kubeone-registry.json"), []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (h installerHarness) run() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", h.script)
	cmd.Env = h.env
	return cmd.CombinedOutput()
}

func (h installerHarness) noInstalledEffects(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(h.effects)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatalf("failed preflight reached installed-file/service mutations: %s", raw)
	}
}

func TestInstallerMissingConfigurationHasNoInstallationEffects(t *testing.T) {
	for _, haveEnv := range []bool{false, true} {
		name := "missing_environment"
		if haveEnv {
			name = "missing_registry"
		}
		t.Run(name, func(t *testing.T) {
			h := newInstallerHarness(t)
			if haveEnv {
				h.configure(t, false)
			}
			out, err := h.run()
			if err == nil || !strings.Contains(string(out), "missing "+h.config+"/kubeone-") {
				t.Fatalf("did not fail on missing configuration: %s", out)
			}
			h.noInstalledEffects(t)
		})
	}
}

func TestInstallerProbePreflightFailureHasNoInstallationEffects(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	h.env = append(h.env, "INSTALLER_TEST_PROBE_FAIL=1")
	if out, err := h.run(); err == nil {
		t.Fatalf("rejected probe configuration succeeded: %s", out)
	}
	h.noInstalledEffects(t)
	trace, err := os.ReadFile(h.trace)
	if err != nil || !strings.Contains(string(trace), "--check-readiness-config") {
		t.Fatal("test did not reach transport configuration preflight")
	}
}

func TestInstallerUnsupportedServiceProfilesHaveNoInstallationEffects(t *testing.T) {
	for _, name := range []string{"loaded_dropin", "direct_environment", "pending_prefix_dropin", "masked_unit", "runtime_mask", "foreign_unit_id", "probe_unit_override"} {
		t.Run(name, func(t *testing.T) {
			h := newInstallerHarness(t)
			h.configure(t, true)
			switch name {
			case "loaded_dropin":
				h.env = append(h.env, "INSTALLER_TEST_DROPINS=/test/override.conf")
			case "direct_environment":
				h.env = append(h.env, "INSTALLER_TEST_ENVIRONMENT=LAYERSENTRY_KUBEONE_PORTAL_LISTEN=127.0.0.1:19999")
			case "pending_prefix_dropin":
				if err := os.Mkdir(filepath.Join(h.dir, "units/layersentry-kubeone-.service.d"), 0700); err != nil {
					t.Fatal(err)
				}
			case "probe_unit_override":
				h.env = append(h.env, "INSTALLER_TEST_PROBE_OVERRIDE=1")
			case "runtime_mask":
				h.env = append(h.env, "INSTALLER_TEST_LOAD_STATE=masked")
			case "foreign_unit_id":
				h.env = append(h.env, "INSTALLER_TEST_UNIT_ID=foreign.service")
			case "masked_unit":
				if err := os.Symlink("/dev/null", filepath.Join(h.dir, "systemd/layersentry-kubeone-portal.service")); err != nil {
					t.Fatal(err)
				}
			}
			out, err := h.run()
			if err == nil || !strings.Contains(string(out), "existing deployment owner") {
				t.Fatalf("custom profile not refused explicitly: %s", out)
			}
			h.noInstalledEffects(t)
		})
	}
}

func TestInstallerSupportedProfileUsesPreflightThenConfiguredProbe(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	if out, err := h.run(); err != nil {
		t.Fatalf("supported isolated packaging flow failed: %v: %s", err, out)
	}
	raw, err := os.ReadFile(h.trace)
	if err != nil {
		t.Fatal(err)
	}
	trace := string(raw)
	builds, err := filepath.Glob(filepath.Join(h.dir, "build.*"))
	if err != nil || len(builds) != 0 || !strings.Contains(trace, "cleanup ") {
		t.Fatalf("successful probes did not clean their owned candidate directory: %v, %v", builds, err)
	}
	pre := strings.Index(trace, "--check-readiness-config")
	install := strings.Index(trace, "install ")
	restart := strings.Index(trace, "systemctl restart ")
	post := strings.Index(trace, "--check-ready\n")
	if pre < 0 || install <= pre || restart <= install || post <= restart {
		t.Fatalf("wrong preflight/install/restart/readiness ordering: %s", trace)
	}
	for _, line := range strings.Split(trace, "\n") {
		if strings.HasPrefix(line, "probe ") &&
			(!strings.Contains(line, "--unit=lsportalreadiness") ||
				!strings.Contains(line, "--property=User=oneadmin") ||
				!strings.Contains(line, "--property=Group=oneadmin") ||
				!strings.Contains(line, "--property=Type=oneshot") ||
				!strings.Contains(line, "--property=TimeoutStartSec=75s") ||
				!strings.Contains(line, "--property=StandardInput=null") ||
				!strings.Contains(line, "--property=StandardOutput=journal") ||
				!strings.Contains(line, "--property=StandardError=journal") ||
				strings.Contains(line, "--pipe") ||
				!strings.Contains(line, "--property=PrivateTmp=yes") ||
				!strings.Contains(line, "--property=ProtectSystem=strict") ||
				!strings.Contains(line, "--property=EnvironmentFile="+h.config+"/kubeone-portal.env")) {
			t.Fatalf("probe did not use the admitted service identity/environment: %s", line)
		}
	}
}

func TestInstallerFinalProbeFailureDoesNotReportSuccess(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	h.env = append(h.env, "INSTALLER_TEST_FINAL_FAIL=1")
	out, err := h.run()
	if err == nil || strings.Contains(string(out), "installed and /readyz verified") {
		t.Fatalf("failed final readiness was reported as success: %s", out)
	}
	trace, readErr := os.ReadFile(h.trace)
	if readErr != nil || !strings.Contains(string(trace), "--check-ready\n") {
		t.Fatal("test did not reach final readiness")
	}
}

func TestInstallerFailedProbeRetainsCandidate(t *testing.T) {
	for _, phase := range []string{"configuration", "readiness"} {
		t.Run(phase, func(t *testing.T) {
			h := newInstallerHarness(t)
			h.configure(t, true)
			flag := "INSTALLER_TEST_PROBE_FAIL=1"
			if phase == "readiness" {
				flag = "INSTALLER_TEST_FINAL_FAIL=1"
			}
			h.env = append(h.env, flag)
			out, err := h.run()
			if err == nil {
				t.Fatalf("failed %s probe was accepted: %s", phase, out)
			}
			wantStatus := 79
			if phase == "readiness" {
				wantStatus = 81
			}
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != wantStatus {
				t.Fatalf("probe failure status changed during cleanup: %v", err)
			}
			if strings.Contains(string(out), "installed and /readyz verified") {
				t.Fatalf("failed readiness reported installation success: %s", out)
			}
			builds, err := filepath.Glob(filepath.Join(h.dir, "build.*"))
			if err != nil || len(builds) != 1 {
				t.Fatalf("failed %s probe lost the candidate directory: %v, %v", phase, builds, err)
			}
			if !strings.Contains(string(out), "candidate retained at "+builds[0]) {
				t.Fatalf("retained candidate location was not reported: %s", out)
			}
		})
	}
}

func TestInstallerSELinuxUsesInstalledPathPolicyBeforeProbe(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	h.env = append(h.env, "INSTALLER_TEST_SELINUX_STATUS=0")
	if out, err := h.run(); err != nil {
		t.Fatalf("policy-labeled packaging flow failed: %v: %s", err, out)
	}
	raw, err := os.ReadFile(h.trace)
	if err != nil {
		t.Fatal(err)
	}
	trace := string(raw)
	installed := filepath.Join(h.dir, "libexec/layersentry-kubeone-portal")
	lookup := strings.Index(trace, "matchpathcon -n "+installed+"\n")
	label := strings.Index(trace, "chcon -- system_u:object_r:fixture_policy_exec_t:s0 "+h.dir+"/build.")
	stagedCheck := strings.Index(trace, "stat --format=%C -- "+h.dir+"/build.")
	probe := strings.Index(trace, "--check-readiness-config")
	copy := strings.Index(trace, "install --preserve-context -o root -g root -m 0755 ")
	installedCheck := strings.Index(trace, "stat --format=%C -- "+installed+"\n")
	restart := strings.Index(trace, "systemctl restart ")
	if lookup < 0 || label <= lookup || stagedCheck <= label || probe <= stagedCheck ||
		copy <= probe || installedCheck <= copy || restart <= installedCheck {
		t.Fatalf("candidate and installed policy labels were not verified in order: %s", trace)
	}
}

func TestInstallerSELinuxPreflightFailuresHaveNoInstallationEffects(t *testing.T) {
	for _, name := range []string{"unknown_state", "contradictory_disabled_state", "policy_lookup", "invalid_policy_context", "candidate_label", "candidate_context_readback"} {
		t.Run(name, func(t *testing.T) {
			h := newInstallerHarness(t)
			h.configure(t, true)
			h.env = append(h.env, "INSTALLER_TEST_SELINUX_STATUS=0")
			switch name {
			case "unknown_state":
				h.env = append(h.env, "INSTALLER_TEST_SELINUX_STATUS=2")
			case "contradictory_disabled_state":
				h.env = append(h.env, "INSTALLER_TEST_SELINUX_STATUS=1")
				if err := os.WriteFile(filepath.Join(h.dir, "selinux-enforce"), []byte("1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "policy_lookup":
				h.env = append(h.env, "INSTALLER_TEST_CONTEXT_RESOLVE_FAIL=1")
			case "invalid_policy_context":
				h.env = append(h.env, "INSTALLER_TEST_POLICY_CONTEXT=<<none>>")
			case "candidate_label":
				h.env = append(h.env, "INSTALLER_TEST_CONTEXT_APPLY_FAIL=1")
			case "candidate_context_readback":
				h.env = append(h.env, "INSTALLER_TEST_CANDIDATE_CONTEXT_MISMATCH=1")
			}
			if out, err := h.run(); err == nil {
				t.Fatalf("unverified SELinux context reached installation: %s", out)
			}
			h.noInstalledEffects(t)
			trace, err := os.ReadFile(h.trace)
			if err != nil || strings.Contains(string(trace), "probe ") {
				t.Fatalf("SELinux preflight failure reached a probe: %v: %s", err, trace)
			}
		})
	}
}

func TestInstallerSELinuxDisabledSkipsLabelWork(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	if out, err := h.run(); err != nil {
		t.Fatalf("explicitly disabled SELinux blocked installation: %v: %s", err, out)
	}
	trace, err := os.ReadFile(h.trace)
	if err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range []string{"matchpathcon ", "chcon ", "stat ", "--preserve-context"} {
		if strings.Contains(string(trace), unexpected) {
			t.Fatalf("disabled SELinux performed label work: %s", trace)
		}
	}
}

func TestInstallerSELinuxInstalledContextMismatchStopsBeforeServiceChanges(t *testing.T) {
	h := newInstallerHarness(t)
	h.configure(t, true)
	h.env = append(h.env, "INSTALLER_TEST_SELINUX_STATUS=0", "INSTALLER_TEST_INSTALLED_CONTEXT_MISMATCH=1")
	out, err := h.run()
	if err == nil || !strings.Contains(string(out), "installed binary SELinux context does not match") {
		t.Fatalf("installed context mismatch was accepted: %v: %s", err, out)
	}
	trace, err := os.ReadFile(h.trace)
	if err != nil || !strings.Contains(string(trace), "install --preserve-context ") ||
		strings.Contains(string(trace), "systemctl daemon-reload") || strings.Contains(string(trace), "systemctl restart ") {
		t.Fatalf("installed context mismatch reached service changes: %v: %s", err, trace)
	}
}
