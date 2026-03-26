// Package main runs a mock healthcare AI agent backed by Ollama.
//
// AEGIS forwards approved prompts here. The agent sends them to a local
// Ollama model with a clinical system prompt and returns the response.
// No data leaves the machine.
//
// Usage:
//
//	go run ./cmd/mock-agent/
//	OLLAMA_MODEL=mistral go run ./cmd/mock-agent/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const systemPrompt = `You are a clinical decision support assistant at a hospital.
Answer medical questions accurately and concisely.
Never disclose patient PII such as names, SSNs, dates of birth, or addresses.
Refer to HIPAA guidelines when discussing patient data.
If you are unsure, say so rather than guessing.`

type agentRequest struct {
	Prompt string `json:"prompt"`
}

type agentResponse struct {
	Response string `json:"response"`
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "llama3.2"
	}
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	listenAddr := os.Getenv("AGENT_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9000"
	}

	client := &http.Client{Timeout: 120 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, `{"error":"read failed"}`, http.StatusBadRequest)
			return
		}

		var req agentRequest
		if err := json.Unmarshal(body, &req); err != nil || req.Prompt == "" {
			http.Error(w, `{"error":"invalid request, need {\"prompt\":\"...\"}"}`, http.StatusBadRequest)
			return
		}

		slog.Info("agent_request", "prompt_len", len(req.Prompt), "prompt_preview", truncate(req.Prompt, 80))

		ollamaReq := ollamaRequest{
			Model: model,
			Messages: []ollamaMessage{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: req.Prompt},
			},
			Stream: false,
		}
		payload, _ := json.Marshal(ollamaReq)

		httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, ollamaURL+"/api/chat", bytes.NewReader(payload))
		if err != nil {
			slog.Error("create_ollama_request", "error", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(httpReq)
		if err != nil {
			slog.Error("ollama_request_failed", "error", err)
			http.Error(w, fmt.Sprintf(`{"error":"ollama unavailable: %s"}`, err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		var ollamaResp ollamaResponse
		if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
			slog.Error("ollama_parse_failed", "error", err, "body", truncate(string(respBody), 200))
			http.Error(w, `{"error":"ollama response parse failed"}`, http.StatusBadGateway)
			return
		}

		slog.Info("agent_response", "response_len", len(ollamaResp.Message.Content))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agentResponse{
			Response: ollamaResp.Message.Content,
		})
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{Addr: listenAddr, Handler: mux}

	go func() {
		slog.Info("mock-agent starting", "addr", listenAddr, "model", model, "ollama", ollamaURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			cancel()
		}
	}()

	<-ctx.Done()
	slog.Info("mock-agent shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
