// Package proxy implements the AEGIS HTTP proxy and confidence-gated decision engine.
//
// All requests to the AI agent pass through this proxy. The proxy orchestrates
// the three-layer pipeline and makes the final pass/hold/block decision based
// on confidence-gated thresholds.
package proxy

import (
	"context"
	"log/slog"
	"time"

	"github.com/YOUR_ORG/aegis/internal/classifier"
	"github.com/YOUR_ORG/aegis/internal/auditor"
	"github.com/YOUR_ORG/aegis/internal/sanitizer"
	"github.com/YOUR_ORG/aegis/pkg/types"
)

// Proxy is the main AEGIS request handler.
type Proxy struct {
	classifier *classifier.Classifier
	auditor    *auditor.Auditor
	sanitizer  *sanitizer.Sanitizer
	thresholds types.ConfidenceThresholds
	// TODO: audit logger
	// TODO: notifier (hold-and-notify)
	// TODO: metrics
}

// Config for the proxy.
type Config struct {
	ListenAddr string                   `yaml:"listen_addr"`
	Thresholds types.ConfidenceThresholds `yaml:"thresholds"`
	AgentURL   string                   `yaml:"agent_url"` // Upstream AI agent
}

// New creates a Proxy with all three layers.
func New(
	cls *classifier.Classifier,
	aud *auditor.Auditor,
	san *sanitizer.Sanitizer,
	cfg Config,
) *Proxy {
	thresholds := cfg.Thresholds
	if thresholds.AutoProceed == 0 {
		thresholds = types.DefaultThresholds()
	}

	return &Proxy{
		classifier: cls,
		auditor:    aud,
		sanitizer:  san,
		thresholds: thresholds,
	}
}

// HandleRequest processes a single request through the three-layer pipeline.
//
// Flow:
//  1. Layer 1: Classify input
//  2. If benign + high confidence → forward to agent
//  3. If flagged or low confidence → Layer 2: Auditor evaluation
//  4. Apply confidence-gated decision (pass/hold/block)
//  5. If passed → forward to agent → Layer 3: Sanitize output
//  6. Log audit record
func (p *Proxy) HandleRequest(ctx context.Context, requestID string, input string) (*Response, error) {
	start := time.Now()
	isPHITouching := false // TODO: Determine from request context

	record := &types.AuditRecord{
		RequestID:    requestID,
		Timestamp:    time.Now(),
		IsPHITouching: isPHITouching,
	}

	// ── Layer 1: Input Classification ──
	l1Result, err := p.classifier.Classify(ctx, input)
	if err != nil {
		slog.Error("layer1_classify_failed", "request_id", requestID, "error", err)
		record.Layer1 = &types.ClassificationResult{Class: types.ClassBenign, Confidence: 0}
		record.Decision = types.VerdictBlock // Fail closed
		// TODO: Log audit record
		return &Response{Verdict: types.VerdictBlock, Reason: "classification error"}, nil
	}
	record.Layer1 = l1Result

	// Fast path: benign + high confidence → forward
	threshold := p.thresholds.AutoProceed
	if isPHITouching {
		threshold = min(threshold*p.thresholds.PHIMultiplier, 1.0)
	}

	if l1Result.Class == types.ClassBenign && l1Result.Confidence >= threshold {
		// Forward to agent, then sanitize output
		agentResponse, err := p.forwardToAgent(ctx, input)
		if err != nil {
			record.Decision = types.VerdictError
			return nil, err
		}

		l3Result, err := p.sanitizer.Scan(ctx, agentResponse)
		if err != nil {
			slog.Error("layer3_scan_failed", "request_id", requestID, "error", err)
		}
		record.Layer3 = l3Result

		if l3Result != nil && l3Result.PHIDetected {
			record.Decision = types.VerdictBlock
			return &Response{Verdict: types.VerdictBlock, Reason: "phi_in_output"}, nil
		}

		record.Decision = types.VerdictPass
		record.TotalLatency = time.Since(start).Milliseconds()
		// TODO: Log audit record
		return &Response{Verdict: types.VerdictPass, Body: agentResponse}, nil
	}

	// ── Layer 2: Semantic Policy Enforcement ──
	l2Result, err := p.auditor.Evaluate(ctx, input, "", nil, l1Result)
	if err != nil {
		slog.Error("layer2_audit_failed", "request_id", requestID, "error", err)
		record.Decision = types.VerdictBlock // Fail closed
		return &Response{Verdict: types.VerdictBlock, Reason: "audit error"}, nil
	}
	record.Layer2 = l2Result

	// ── Confidence-Gated Decision ──
	decision := p.decide(l2Result, isPHITouching)
	record.Decision = decision
	record.TotalLatency = time.Since(start).Milliseconds()
	// TODO: Log audit record

	switch decision {
	case types.VerdictPass:
		agentResponse, err := p.forwardToAgent(ctx, input)
		if err != nil {
			return nil, err
		}
		// Still run Layer 3 on output
		l3Result, _ := p.sanitizer.Scan(ctx, agentResponse)
		record.Layer3 = l3Result
		if l3Result != nil && l3Result.PHIDetected {
			return &Response{Verdict: types.VerdictBlock, Reason: "phi_in_output"}, nil
		}
		return &Response{Verdict: types.VerdictPass, Body: agentResponse}, nil

	case types.VerdictHold:
		// TODO: Fire hold-and-notify, wait for human decision or timeout
		return &Response{Verdict: types.VerdictHold, Reason: "pending_human_review"}, nil

	case types.VerdictBlock:
		return &Response{Verdict: types.VerdictBlock, Reason: "policy_violation"}, nil

	default:
		return &Response{Verdict: types.VerdictBlock, Reason: "unknown_decision"}, nil
	}
}

// decide applies confidence-gated thresholds to the auditor result.
func (p *Proxy) decide(result *types.AuditResult, isPHITouching bool) types.Verdict {
	autoThreshold := p.thresholds.AutoProceed
	holdThreshold := p.thresholds.HoldAndNotify

	if isPHITouching {
		autoThreshold = min(autoThreshold*p.thresholds.PHIMultiplier, 1.0)
		holdThreshold = min(holdThreshold*p.thresholds.PHIMultiplier, 1.0)
	}

	if result.Verdict == types.VerdictPass && result.Confidence >= autoThreshold {
		return types.VerdictPass
	}
	if result.Confidence >= holdThreshold {
		return types.VerdictHold
	}
	return types.VerdictBlock
}

func (p *Proxy) forwardToAgent(ctx context.Context, input string) (string, error) {
	// TODO: HTTP call to upstream agent
	_ = ctx
	_ = input
	return "", nil
}

// Response from the proxy.
type Response struct {
	Verdict types.Verdict `json:"verdict"`
	Body    string        `json:"body,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
