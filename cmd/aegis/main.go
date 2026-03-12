// Package main is the entrypoint for the AEGIS proxy server.
//
// AEGIS is a three-layer inline proxy for securing healthcare AI agents.
// See docs/architecture/system-architecture.md for details.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// TODO: Load configuration from configs/aegis.yaml
	// TODO: Initialize Layer 1 classifier (ONNX)
	// TODO: Initialize Layer 2 auditor client
	// TODO: Initialize Layer 3 sanitizer
	// TODO: Initialize audit logger
	// TODO: Initialize Prometheus metrics
	// TODO: Initialize hold-and-notify system
	// TODO: Start HTTP proxy server

	slog.Info("aegis starting",
		"version", "0.1.0",
		"layers", 3,
	)

	// Block until shutdown signal
	<-ctx.Done()
	slog.Info("aegis shutting down")

	// TODO: Graceful shutdown — drain in-flight requests

	fmt.Println("aegis stopped")
}
