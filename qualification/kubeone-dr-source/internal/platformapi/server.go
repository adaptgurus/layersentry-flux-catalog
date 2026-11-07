package platformapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type ServerConfig struct {
	ListenAddress            string
	TLSCertFile              string
	TLSKeyFile               string
	TLSClientCAFile          string
	RequireClientCertificate bool
	AllowInsecureHTTP        bool
	ReadHeaderTimeout        time.Duration
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
	IdleTimeout              time.Duration
	ShutdownTimeout          time.Duration
	AdmissionTimeout         time.Duration
	MaxHeaderBytes           int
	MaxConcurrentRequests    int
}

type Server struct {
	app *Application
	cfg ServerConfig
}

func NewServer(app *Application, cfg ServerConfig) (*Server, error) {
	if app == nil || app.Handler() == nil {
		return nil, errors.New("LayerSentry platform server requires an application")
	}
	cfg.ListenAddress = strings.TrimSpace(cfg.ListenAddress)
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = ":9444"
	}
	cfg.TLSCertFile = strings.TrimSpace(cfg.TLSCertFile)
	cfg.TLSKeyFile = strings.TrimSpace(cfg.TLSKeyFile)
	if !cfg.AllowInsecureHTTP && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return nil, errors.New("LayerSentry platform server requires TLS certificate/key unless insecure HTTP is explicitly enabled")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("LayerSentry platform TLS certificate and key must be configured together")
	}
	cfg.TLSClientCAFile = strings.TrimSpace(cfg.TLSClientCAFile)
	if cfg.AllowInsecureHTTP && (cfg.RequireClientCertificate || cfg.TLSClientCAFile != "") {
		return nil, errors.New("LayerSentry mTLS cannot be enabled with insecure HTTP")
	}
	if cfg.RequireClientCertificate && cfg.TLSClientCAFile == "" {
		return nil, errors.New("LayerSentry mTLS requires a client CA file")
	}
	if !cfg.RequireClientCertificate && cfg.TLSClientCAFile != "" {
		return nil, errors.New("LayerSentry client CA file requires client-certificate verification")
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 15 * time.Second
	}
	if cfg.AdmissionTimeout <= 0 {
		cfg.AdmissionTimeout = 250 * time.Millisecond
	}
	if cfg.AdmissionTimeout > 5*time.Second {
		return nil, errors.New("LayerSentry request admission timeout must not exceed 5s")
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = 32 << 10
	}
	if cfg.MaxHeaderBytes < 8<<10 || cfg.MaxHeaderBytes > 1<<20 {
		return nil, errors.New("LayerSentry max header bytes must be within 8KiB..1MiB")
	}
	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 256
	}
	if cfg.MaxConcurrentRequests < 8 || cfg.MaxConcurrentRequests > 4096 {
		return nil, errors.New("LayerSentry max concurrent requests must be within 8..4096")
	}
	return &Server{app: app, cfg: cfg}, nil
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	if s == nil {
		return nil, errors.New("LayerSentry platform server is nil")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !s.cfg.RequireClientCertificate {
		return cfg, nil
	}
	raw, err := os.ReadFile(s.cfg.TLSClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read LayerSentry client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("LayerSentry client CA file contains no valid certificates")
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}

func boundedRequestAdmission(next http.Handler, maxConcurrent int, timeout time.Duration) http.Handler {
	if maxConcurrent <= 0 {
		return next
	}
	sem := make(chan struct{}, maxConcurrent)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		case <-r.Context().Done():
			return
		case <-timer.C:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "request admission capacity exhausted"})
		}
	})
}

func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.ListenAddress,
		Handler:           boundedRequestAdmission(s.app.Handler(), s.cfg.MaxConcurrentRequests, s.cfg.AdmissionTimeout),
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout,
		ReadTimeout:       s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.WriteTimeout,
		IdleTimeout:       s.cfg.IdleTimeout,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
	}
	if !s.cfg.AllowInsecureHTTP {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			return err
		}
		httpServer.TLSConfig = tlsCfg
	}

	type result struct {
		name string
		err  error
	}
	results := make(chan result, 2)
	appCtx, cancelApp := context.WithCancel(ctx)
	defer cancelApp()

	go func() {
		results <- result{name: "application", err: s.app.Run(appCtx)}
	}()
	go func() {
		var err error
		if s.cfg.AllowInsecureHTTP {
			err = httpServer.ListenAndServe()
		} else {
			err = httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		}
		results <- result{name: "http", err: err}
	}()

	var first result
	select {
	case <-ctx.Done():
		first = result{name: "context", err: ctx.Err()}
	case first = <-results:
	}

	cancelApp()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	shutdownErr := httpServer.Shutdown(shutdownCtx)
	cancelShutdown()

	if first.name == "context" {
		if shutdownErr != nil && !errors.Is(shutdownErr, context.Canceled) {
			return fmt.Errorf("LayerSentry platform HTTP shutdown: %w", shutdownErr)
		}
		return nil
	}
	if first.name == "http" && errors.Is(first.err, http.ErrServerClosed) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.New("LayerSentry platform HTTP server closed unexpectedly")
	}
	if first.err == nil || errors.Is(first.err, context.Canceled) {
		return fmt.Errorf("LayerSentry platform %s exited unexpectedly", first.name)
	}
	return fmt.Errorf("LayerSentry platform %s failed: %w", first.name, first.err)
}
