package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kubeone "github.com/layersentry/layersentry-platform/internal/kubeone/lifecycle"
	"github.com/layersentry/layersentry-platform/internal/platformapi"
	"github.com/layersentry/layersentry-platform/internal/secureconfig"
)

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	root, err := required("LAYERSENTRY_KUBEONE_WORKSPACE_ROOT")
	if err != nil {
		return err
	}
	registryFile, err := required("LAYERSENTRY_KUBEONE_REGISTRY_FILE")
	if err != nil {
		return err
	}
	token, err := secureconfig.RequiredEnvOrFile("LAYERSENTRY_GATEWAY_TOKEN")
	if err != nil {
		return err
	}
	registry, err := kubeone.LoadRegistry(root, registryFile)
	if err != nil {
		return fmt.Errorf("load KubeOne registry: %w", err)
	}
	kubeOneExecutable := valueOr("LAYERSENTRY_KUBEONE_BIN", "/usr/local/bin/kubeone")
	// Opt-in candidate qualification: preserve protected v1.14.3; reject
	// arbitrary KubeOne executable paths even when the claimed version matches.
	if version := strings.TrimSpace(os.Getenv("LAYERSENTRY_KUBEONE_RELEASE_PIN")); version != "" {
		if _, err := kubeone.VerifyKubeOneCandidate(kubeOneExecutable, version); err != nil {
			return fmt.Errorf("KubeOne release candidate pin invalid: %w", err)
		}
	}
	client, err := kubeone.NewClient(registry, nil, kubeone.ClientConfig{
		KubeOneBinary: kubeOneExecutable,
		KubectlBinary: valueOr("LAYERSENTRY_KUBECTL_BIN", "/usr/bin/kubectl"),
		Timeout:       30 * time.Minute,
		PollInterval:  10 * time.Second,
	})
	if err != nil {
		return err
	}
	profiles, err := kubeone.LoadAcceleratorProfiles(os.Getenv("LAYERSENTRY_KUBEONE_ACCELERATOR_PROFILES"))
	if err != nil {
		return err
	}
	portal, err := kubeone.NewPortal(client, profiles)
	if err != nil {
		return err
	}
	if setting := os.Getenv("LAYERSENTRY_KUBEONE_NATIVE_WORKSPACE_SUCCESSOR"); setting != "" {
		if setting != "true" {
			return errors.New("native workspace successor setting must be true or omitted")
		}
		if err := portal.EnableNativeWorkspaceSuccessor(); err != nil {
			return fmt.Errorf("configure native workspace successor: %w", err)
		}
	}
	applications, err := kubeone.LoadApplicationProfiles(os.Getenv("LAYERSENTRY_KUBEONE_APPLICATION_CATALOG"))
	if err != nil {
		return fmt.Errorf("load KubeOne application catalog: %w", err)
	}
	if len(applications) > 0 {
		if err := portal.ConfigureApplications(applications, valueOr("LAYERSENTRY_HELM_BIN", "/usr/local/bin/helm")); err != nil {
			return fmt.Errorf("configure KubeOne applications: %w", err)
		}
	}
	// One-click encrypted etcd backup and DR policy are explicitly opt-in.
	// The file lists pre-mounted, source-pinned NFS and DR identities, never
	// browser-supplied paths, password values or arbitrary network targets.
	if file := strings.TrimSpace(os.Getenv("LAYERSENTRY_KUBEONE_RECOVERY_CONFIG_FILE")); file != "" {
		config, err := kubeone.LoadRecoveryConfig(file)
		if err != nil {
			return fmt.Errorf("recovery configuration unavailable: %w", err)
		}
		if err := portal.ConfigureRecovery(config); err != nil {
			return fmt.Errorf("configure KubeOne recovery: %w", err)
		}
	}
	// Runtime DR automation is OFF by default and requires both a protected
	// explicit configuration policy and a DR-site server opt-in. Code deployment
	// cannot start automatic operations until this separate gate is provisioned.
	autoDRRequested := strings.TrimSpace(os.Getenv("LAYERSENTRY_KUBEONE_AUTODR_ENABLE"))
	if autoDRRequested != "" && autoDRRequested != "false" && autoDRRequested != "true" {
		return errors.New("automatic DR opt-in setting must be true, false or unset")
	}
	autoDRSite := ""
	if autoDRRequested == "true" {
		autoDRSite, err = required("LAYERSENTRY_KUBEONE_AUTODR_CONTROLLER_SITE")
		if err != nil {
			return err
		}
		if err = portal.ValidateAutoDRControllerSite(autoDRSite); err != nil {
			return fmt.Errorf("automatic KubeOne DR controller startup rejected: %w", err)
		}
	}
	address := valueOr("LAYERSENTRY_KUBEONE_PORTAL_LISTEN", "127.0.0.1:9445")
	tlsConfig, auth, err := portalTransport(address, token)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           serverHandler(portal, auth),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 2)
	if autoDRRequested == "true" {
		go func() {
			if controllerErr := portal.RunDRAutomation(ctx, autoDRSite); controllerErr != nil && ctx.Err() == nil {
				select {
				case errCh <- fmt.Errorf("KubeOne DR monitor exited: %w", controllerErr):
				case <-ctx.Done():
				}
			}
		}()
	}
	go func() {
		if tlsConfig != nil {
			errCh <- server.ListenAndServeTLS("", "")
		} else {
			errCh <- server.ListenAndServe()
		}
	}()
	select {
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		return server.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func serverHandler(portal *kubeone.Portal, auth *platformapi.GatewayAuth) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := portal.Ready(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("/", auth.Middleware(portal.Handler()))
	return mux
}

func valueOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
