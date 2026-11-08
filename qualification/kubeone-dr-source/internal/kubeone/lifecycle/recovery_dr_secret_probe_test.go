package lifecycle

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type drSecretProbeRunner struct {
	calls          [][]string
	overrideSecret bool
	secretResult   CommandResult
	secretErr      error
}

func (r *drSecretProbeRunner) Run(_ context.Context, _, _ string, args, _ []string) (CommandResult, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(args) != 8 {
		return CommandResult{}, errors.New("unexpected synthetic namespace probe")
	}
	if args[5] == "secrets" {
		if r.overrideSecret {
			return r.secretResult, r.secretErr
		}
		if args[7] == "name" {
			return CommandResult{}, nil
		}
	}
	// Preserve the old JSON response when reproducing the baseline output choice.
	return CommandResult{Stdout: `{"items":[]}`}, nil
}

func drSecretProbeFixture(r *drSecretProbeRunner) (*RecoveryManager, Workspace, DRWorkloadProfile) {
	return &RecoveryManager{client: &Client{
			runner: r,
			cfg:    ClientConfig{KubectlBinary: "/synthetic/kubectl"},
		}},
		Workspace{Directory: "/synthetic", Kubeconfig: "/synthetic/kubeconfig"},
		DRWorkloadProfile{Namespace: "synthetic-dr"}
}

func TestDRSecretProbeUsesNamesOnly(t *testing.T) {
	runner := &drSecretProbeRunner{}
	manager, workspace, profile := drSecretProbeFixture(runner)
	if err := manager.targetNamespaceEmpty(context.Background(), workspace, profile); err != nil {
		t.Fatal("empty synthetic namespace rejected", err)
	}
	resources := []string{"pods", "persistentvolumeclaims", "deployments.apps", "statefulsets.apps", "services", "configmaps", "secrets"}
	if len(runner.calls) != len(resources) {
		t.Fatal("namespace probe did not check every required resource")
	}
	for i, resource := range resources {
		format := "json"
		if resource == "secrets" {
			format = "name"
		}
		want := []string{"--kubeconfig", workspace.Kubeconfig, "-n", profile.Namespace, "get", resource, "-o", format}
		if !slices.Equal(runner.calls[i], want) {
			t.Errorf("%s probe requested %q; want bounded native %q output", resource, runner.calls[i], format)
		}
	}
}

func TestDRSecretProbeFailsClosed(t *testing.T) {
	const canary = "SYNTHETIC_SECRET_PROBE_CANARY"
	cases := []struct {
		name   string
		result CommandResult
		runErr error
		wantOK bool
	}{
		{name: "empty", wantOK: true},
		{name: "empty_with_native_stderr", result: CommandResult{Stderr: "No resources found in synthetic-dr namespace.\n"}, wantOK: true},
		{name: "occupied", result: CommandResult{Stdout: "secret/synthetic-existing\n"}},
		{name: "whitespace", result: CommandResult{Stdout: " \t\n"}},
		{name: "count", result: CommandResult{Stdout: "0\n"}},
		{name: "json", result: CommandResult{Stdout: `{"items":[]}`}},
		{name: "malformed", result: CommandResult{Stdout: "\x00not-a-name"}},
		{name: "diagnostic", result: CommandResult{Stdout: canary}},
		{name: "command_error", result: CommandResult{Stderr: canary}, runErr: errors.New(canary)},
		{name: "command_error_with_output", result: CommandResult{Stdout: canary, Stderr: canary}, runErr: errors.New(canary)},
		{name: "truncated_empty", result: CommandResult{StdoutTruncated: true}},
		{name: "truncated_nonempty", result: CommandResult{Stdout: "secret/synthetic-existing\n", StdoutTruncated: true}},
		{name: "oversized", result: CommandResult{Stdout: strings.Repeat("x", (1<<20)+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &drSecretProbeRunner{overrideSecret: true, secretResult: tc.result, secretErr: tc.runErr}
			manager, workspace, profile := drSecretProbeFixture(runner)
			err := manager.targetNamespaceEmpty(context.Background(), workspace, profile)
			if tc.wantOK {
				if err != nil {
					t.Fatal("exact-empty successful Secret probe rejected")
				}
				return
			}
			// Identity equality also proves that native output/errors are not propagated.
			if err != ErrValidation {
				t.Fatal("uncertain or occupied Secret probe did not return the fixed validation error")
			}
		})
	}
}
