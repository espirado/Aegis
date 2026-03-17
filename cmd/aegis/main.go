// Package main is the entrypoint for the AEGIS proxy server.
//
// AEGIS is a three-layer inline proxy for securing healthcare AI agents.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/espirado/aegis/internal/audit"
	"github.com/espirado/aegis/internal/auditor"
	"github.com/espirado/aegis/internal/classifier"
	"github.com/espirado/aegis/internal/config"
	"github.com/espirado/aegis/internal/proxy"
	"github.com/espirado/aegis/internal/sanitizer"
	"github.com/espirado/aegis/pkg/types"

	ort "github.com/yalue/onnxruntime_go"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load configuration
	cfgPath := os.Getenv("AEGIS_CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "configs/aegis.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Configure logger
	logLevel := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("aegis starting", "version", "0.2.0", "config", cfgPath)

	// Initialize ONNX Runtime
	ortLibPath := os.Getenv("AEGIS_ORT_LIB_PATH")
	if ortLibPath != "" {
		ort.SetSharedLibraryPath(ortLibPath)
	}
	if err := ort.InitializeEnvironment(); err != nil {
		slog.Error("failed to initialize ONNX Runtime", "error", err)
		os.Exit(1)
	}
	defer ort.DestroyEnvironment()

	// Initialize Layer 1: Classifier
	cls, err := classifier.New(classifier.Config{
		ModelPath:        cfg.Classifier.ModelPath,
		VocabPath:        cfg.Classifier.VocabPath,
		MaxInputLen:      cfg.Classifier.MaxInputLen,
		InferenceTimeout: cfg.Classifier.InferenceTimeout,
	})
	if err != nil {
		slog.Error("failed to initialize classifier", "error", err)
		os.Exit(1)
	}
	defer cls.Close()

	// Initialize Layer 2: Auditor
	aud, err := auditor.New(auditor.Config{
		Provider: cfg.Auditor.Provider,
		BaseURL:  cfg.Auditor.BaseURL,
		APIKey:   cfg.Auditor.APIKey,
		Model:    cfg.Auditor.Model,
		Timeout:  cfg.Auditor.Timeout,
	})
	if err != nil {
		slog.Error("failed to initialize auditor", "error", err)
		os.Exit(1)
	}

	// Initialize Layer 3: Sanitizer
	san, err := sanitizer.New(sanitizer.Config{
		NERModelPath: cfg.Sanitizer.NERModelPath,
		RedactMode:   cfg.Sanitizer.RedactMode,
	})
	if err != nil {
		slog.Error("failed to initialize sanitizer", "error", err)
		os.Exit(1)
	}

	// Initialize audit logger
	auditLog, err := audit.NewLogger(audit.Config{
		Output:               cfg.Audit.Output,
		FilePath:             cfg.Audit.FilePath,
		RedactFlaggedContent: cfg.Audit.RedactFlaggedContent,
	})
	if err != nil {
		slog.Error("failed to initialize audit logger", "error", err)
		os.Exit(1)
	}
	defer auditLog.Close()

	// Build proxy
	p := proxy.New(cls, aud, san, auditLog, proxy.Config{
		ListenAddr: cfg.Proxy.ListenAddr,
		AgentURL:   cfg.Proxy.AgentURL,
		Thresholds: types.ConfidenceThresholds{
			AutoProceed:   cfg.Thresholds.AutoProceed,
			HoldAndNotify: cfg.Thresholds.HoldAndNotify,
			PHIMultiplier: cfg.Thresholds.PHIMultiplier,
		},
	})

	// HTTP router
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)

	r.Post("/v1/proxy", p.ServeHTTP)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Main proxy server
	srv := &http.Server{
		Addr:         cfg.Proxy.ListenAddr,
		Handler:      r,
		ReadTimeout:  cfg.Proxy.ReadTimeout,
		WriteTimeout: cfg.Proxy.WriteTimeout,
	}

	// Metrics server (separate port)
	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(cfg.Metrics.Path, promhttp.Handler())
		metricsSrv = &http.Server{
			Addr:    cfg.Metrics.ListenAddr,
			Handler: metricsMux,
		}
		go func() {
			slog.Info("metrics server starting", "addr", cfg.Metrics.ListenAddr, "path", cfg.Metrics.Path)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server failed", "error", err)
			}
		}()
	}

	// Start proxy server
	go func() {
		slog.Info("aegis proxy listening",
			"addr", cfg.Proxy.ListenAddr,
			"agent_url", cfg.Proxy.AgentURL,
			"auditor_provider", cfg.Auditor.Provider,
			"auditor_model", cfg.Auditor.Model,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server failed", "error", err)
			cancel()
		}
	}()

	// Block until shutdown signal
	<-ctx.Done()
	slog.Info("aegis shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("proxy shutdown error", "error", err)
	}
	if metricsSrv != nil {
		metricsSrv.Shutdown(shutdownCtx)
	}

	slog.Info("aegis stopped")
}
