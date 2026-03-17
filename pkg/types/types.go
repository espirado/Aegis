// Package types defines core domain types shared across AEGIS layers.
package types

import "time"

// Classification buckets for Layer 1.
type InputClass int

const (
	ClassBenign            InputClass = 0
	ClassDirectInjection   InputClass = 1
	ClassIndirectInjection InputClass = 2
	ClassJailbreak         InputClass = 3
	ClassPHIExtraction     InputClass = 4
)

func (c InputClass) String() string {
	switch c {
	case ClassBenign:
		return "BENIGN"
	case ClassDirectInjection:
		return "DIRECT_INJECTION"
	case ClassIndirectInjection:
		return "INDIRECT_INJECTION"
	case ClassJailbreak:
		return "JAILBREAK"
	case ClassPHIExtraction:
		return "PHI_EXTRACTION"
	default:
		return "UNKNOWN"
	}
}

// Verdict from the decision engine.
type Verdict string

const (
	VerdictPass  Verdict = "PASS"
	VerdictHold  Verdict = "HOLD"
	VerdictBlock Verdict = "BLOCK"
	VerdictError Verdict = "ERROR"
)

// ClassificationResult from Layer 1.
type ClassificationResult struct {
	Class      InputClass `json:"class"`
	Confidence float64    `json:"confidence"`
	LatencyMs  int64      `json:"latency_ms"`
}

// AuditResult from Layer 2.
type AuditResult struct {
	Verdict          Verdict  `json:"verdict"`
	Confidence       float64  `json:"confidence"`
	PolicyViolations []string `json:"policy_violations"`
	Reasoning        string   `json:"reasoning"`
	LatencyMs        int64    `json:"latency_ms"`
}

// SanitizationResult from Layer 3.
type SanitizationResult struct {
	PHIDetected         bool     `json:"phi_detected"`
	ExfiltrationAttempt bool     `json:"exfiltration_attempt"`
	EntitiesRedacted    int      `json:"entities_redacted"`
	PHITypes            []string `json:"phi_types,omitempty"`
	LatencyMs           int64    `json:"latency_ms"`
}

// AuditRecord is the immutable record of every request processed by AEGIS.
type AuditRecord struct {
	RequestID     string               `json:"request_id"`
	Timestamp     time.Time            `json:"timestamp"`
	Layer1        *ClassificationResult `json:"layer1"`
	Layer2        *AuditResult          `json:"layer2,omitempty"`
	Layer3        *SanitizationResult   `json:"layer3,omitempty"`
	Decision      Verdict              `json:"decision"`
	TotalLatency  int64                `json:"total_latency_ms"`
	HumanReview   *HumanReviewRecord   `json:"human_review,omitempty"`
	IsPHITouching bool                 `json:"is_phi_touching"`
}

// HumanReviewRecord captures the outcome of hold-and-notify escalation.
type HumanReviewRecord struct {
	Reviewer       string `json:"reviewer"`
	Action         string `json:"action"` // APPROVE, REJECT, TIMEOUT_PROCEED
	ResponseTimeMs *int64 `json:"response_time_ms,omitempty"`
}

// ConfidenceThresholds defines the gating thresholds.
type ConfidenceThresholds struct {
	AutoProceed   float64 `json:"auto_proceed" yaml:"auto_proceed"`
	HoldAndNotify float64 `json:"hold_and_notify" yaml:"hold_and_notify"`
	PHIMultiplier float64 `json:"phi_multiplier" yaml:"phi_multiplier"`
}

// DefaultThresholds returns the standard confidence gates.
func DefaultThresholds() ConfidenceThresholds {
	return ConfidenceThresholds{
		AutoProceed:   0.85,
		HoldAndNotify: 0.60,
		PHIMultiplier: 1.5,
	}
}
