// Package proxy implements the AEGIS HTTP proxy and confidence-gated decision engine.
//
// All requests to the AI agent pass through this proxy. The proxy orchestrates
// the three-layer pipeline and makes the final pass/hold/block decision based
// on confidence-gated thresholds.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/espirado/aegis/internal/audit"
	"github.com/espirado/aegis/internal/auditor"
	"github.com/espirado/aegis/internal/classifier"
	"github.com/espirado/aegis/internal/metrics"
	"github.com/espirado/aegis/internal/sanitizer"
	"github.com/espirado/aegis/pkg/types"
)

// Proxy is the main AEGIS request handler.
type Proxy struct {
	classifier  *classifier.Classifier
	auditor     *auditor.Auditor
	sanitizer   *sanitizer.Sanitizer
	thresholds  types.ConfidenceThresholds
	auditLogger *audit.Logger
	agentURL    string
	httpClient  *http.Client
	reqCounter  uint64
}

// Config for the proxy.
type Config struct {
	ListenAddr string                    `yaml:"listen_addr"`
	Thresholds types.ConfidenceThresholds `yaml:"thresholds"`
	AgentURL   string                    `yaml:"agent_url"`
}

// New creates a Proxy with all three layers.
func New(
	cls *classifier.Classifier,
	aud *auditor.Auditor,
	san *sanitizer.Sanitizer,
	auditLog *audit.Logger,
	cfg Config,
) *Proxy {
	thresholds := cfg.Thresholds
	if thresholds.AutoProceed == 0 {
		thresholds = types.DefaultThresholds()
	}

	return &Proxy{
		classifier:  cls,
		auditor:     aud,
		sanitizer:   san,
		auditLogger: auditLog,
		thresholds:  thresholds,
		agentURL:    cfg.AgentURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// ProxyRequest is the expected JSON body from clients.
type ProxyRequest struct {
	Prompt            string   `json:"prompt"`
	AgentSystemPrompt string   `json:"agent_system_prompt,omitempty"`
	AgentTools        []string `json:"agent_tools,omitempty"`
}

// ProxyResponse is the JSON response returned to clients.
type ProxyResponse struct {
	Verdict   types.Verdict `json:"verdict"`
	Body      string        `json:"body,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	RequestID string        `json:"request_id"`
}

// ServeHTTP handles incoming proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}

	var req ProxyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Prompt == "" {
		http.Error(w, `{"error":"prompt is required"}`, http.StatusBadRequest)
		return
	}

	requestID := fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), p.nextID())
	ctx := r.Context()

	resp, err := p.handleRequest(ctx, requestID, &req)
	if err != nil {
		slog.Error("proxy_request_failed", "request_id", requestID, "error", err)
		writeJSON(w, http.StatusInternalServerError, &ProxyResponse{
			Verdict:   types.VerdictError,
			Reason:    "internal error",
			RequestID: requestID,
		})
		return
	}

	resp.RequestID = requestID
	status := http.StatusOK
	if resp.Verdict == types.VerdictBlock {
		status = http.StatusForbidden
	}
	writeJSON(w, status, resp)
}

func (p *Proxy) handleRequest(ctx context.Context, requestID string, req *ProxyRequest) (*ProxyResponse, error) {
	start := time.Now()

	record := &types.AuditRecord{
		RequestID: requestID,
		Timestamp: time.Now(),
	}
	defer func() {
		record.TotalLatency = time.Since(start).Milliseconds()
		metrics.TotalLatency.Observe(time.Since(start).Seconds())
		metrics.RequestsTotal.WithLabelValues(string(record.Decision)).Inc()
		if p.auditLogger != nil {
			p.auditLogger.Log(record)
		}
	}()

	// Layer 1: Input Classification
	l1Result, err := p.classifier.Classify(ctx, req.Prompt)
	if err != nil {
		slog.Error("layer1_classify_failed", "request_id", requestID, "error", err)
		record.Layer1 = &types.ClassificationResult{Class: types.ClassBenign, Confidence: 0}
		record.Decision = types.VerdictBlock
		return &ProxyResponse{Verdict: types.VerdictBlock, Reason: "classification error"}, nil
	}
	record.Layer1 = l1Result
	record.IsPHITouching = l1Result.Class == types.ClassPHIExtraction

	metrics.ClassificationDistribution.WithLabelValues(l1Result.Class.String()).Inc()
	metrics.Layer1Latency.Observe(float64(l1Result.LatencyMs) / 1000.0)

	// Fast path: benign + high confidence → forward to agent
	threshold := p.thresholds.AutoProceed
	if record.IsPHITouching {
		threshold = clamp(threshold*p.thresholds.PHIMultiplier, 0, 1)
	}

	if l1Result.Class == types.ClassBenign && l1Result.Confidence >= threshold {
		return p.forwardAndSanitize(ctx, requestID, req.Prompt, record)
	}

	// Layer 2: Semantic Policy Enforcement
	l2Result, err := p.auditor.Evaluate(ctx, req.Prompt, req.AgentSystemPrompt, req.AgentTools, l1Result)
	if err != nil {
		slog.Error("layer2_audit_failed", "request_id", requestID, "error", err)
		metrics.AuditorErrors.Inc()
		record.Decision = types.VerdictBlock
		return &ProxyResponse{Verdict: types.VerdictBlock, Reason: "audit error"}, nil
	}
	record.Layer2 = l2Result
	metrics.Layer2Latency.Observe(float64(l2Result.LatencyMs) / 1000.0)

	// Confidence-Gated Decision
	decision := p.decide(l2Result, record.IsPHITouching)
	record.Decision = decision

	switch decision {
	case types.VerdictPass:
		return p.forwardAndSanitize(ctx, requestID, req.Prompt, record)

	case types.VerdictHold:
		return &ProxyResponse{Verdict: types.VerdictHold, Reason: "pending_human_review"}, nil

	case types.VerdictBlock:
		reason := "policy_violation"
		if l2Result != nil && l2Result.Reasoning != "" {
			reason = l2Result.Reasoning
		}
		return &ProxyResponse{Verdict: types.VerdictBlock, Reason: reason}, nil

	default:
		return &ProxyResponse{Verdict: types.VerdictBlock, Reason: "unknown_decision"}, nil
	}
}

// forwardAndSanitize sends the prompt to the agent and scans the response.
func (p *Proxy) forwardAndSanitize(ctx context.Context, requestID, prompt string, record *types.AuditRecord) (*ProxyResponse, error) {
	agentResponse, err := p.forwardToAgent(ctx, prompt)
	if err != nil {
		record.Decision = types.VerdictError
		return nil, fmt.Errorf("forward to agent: %w", err)
	}

	l3Result, err := p.sanitizer.Scan(ctx, agentResponse)
	if err != nil {
		slog.Error("layer3_scan_failed", "request_id", requestID, "error", err)
	}
	record.Layer3 = l3Result
	if l3Result != nil {
		metrics.Layer3Latency.Observe(float64(l3Result.LatencyMs) / 1000.0)
	}

	if l3Result != nil && l3Result.PHIDetected {
		record.Decision = types.VerdictBlock
		for _, pt := range l3Result.PHITypes {
			ch := "direct"
			if l3Result.ExfiltrationAttempt {
				ch = "exfiltration"
			}
			metrics.PHIDetections.WithLabelValues(pt, ch).Inc()
		}

		if p.sanitizer.RedactMode() == "redact" {
			redacted, _, _, _ := p.sanitizer.ScanAndRedact(ctx, agentResponse)
			record.Decision = types.VerdictPass
			return &ProxyResponse{Verdict: types.VerdictPass, Body: redacted}, nil
		}
		return &ProxyResponse{Verdict: types.VerdictBlock, Reason: "phi_in_output"}, nil
	}

	record.Decision = types.VerdictPass
	return &ProxyResponse{Verdict: types.VerdictPass, Body: agentResponse}, nil
}

func (p *Proxy) forwardToAgent(ctx context.Context, prompt string) (string, error) {
	if p.agentURL == "" {
		return "", fmt.Errorf("agent_url not configured")
	}

	payload, _ := json.Marshal(map[string]string{"prompt": prompt})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.agentURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create agent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read agent response: %w", err)
	}

	// Try to extract "response" field from JSON, fall back to raw body
	var agentResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &agentResp); err == nil && agentResp.Response != "" {
		return agentResp.Response, nil
	}

	return string(body), nil
}

func (p *Proxy) decide(result *types.AuditResult, isPHITouching bool) types.Verdict {
	autoThreshold := p.thresholds.AutoProceed
	holdThreshold := p.thresholds.HoldAndNotify

	if isPHITouching {
		autoThreshold = clamp(autoThreshold*p.thresholds.PHIMultiplier, 0, 1)
		holdThreshold = clamp(holdThreshold*p.thresholds.PHIMultiplier, 0, 1)
	}

	if result.Verdict == types.VerdictPass && result.Confidence >= autoThreshold {
		return types.VerdictPass
	}
	if result.Confidence >= holdThreshold {
		return types.VerdictHold
	}
	return types.VerdictBlock
}

func (p *Proxy) nextID() uint64 {
	p.reqCounter++
	return p.reqCounter
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
