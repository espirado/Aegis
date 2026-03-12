// Package sanitizer implements Layer 3: Output Sanitization.
//
// Scans AI agent responses for PHI leakage across all channels:
//   - Direct PHI in response text (NER + regex for 18 HIPAA identifiers)
//   - Indirect exfiltration via URL parameters
//   - PHI hidden in markdown links
//   - PHI in tool-call arguments
//   - PHI in encoded formats (base64, URL encoding)
package sanitizer

import (
	"context"
	"fmt"
	"time"

	"github.com/YOUR_ORG/aegis/pkg/types"
)

// Sanitizer performs Layer 3 output inspection.
type Sanitizer struct {
	// TODO: ONNX NER model for clinical entity recognition
	// TODO: Compiled regex patterns for 18 HIPAA identifiers
	// TODO: Exfiltration detection patterns
}

// Config for the sanitizer.
type Config struct {
	NERModelPath   string `yaml:"ner_model_path"`
	RedactMode     string `yaml:"redact_mode"` // "redact" (replace with [REDACTED]) or "block" (reject entire response)
}

// New creates a Sanitizer.
func New(cfg Config) (*Sanitizer, error) {
	// TODO: Load NER ONNX model
	// TODO: Compile regex patterns from pkg/phi/patterns.go
	return &Sanitizer{}, nil
}

// Scan inspects an agent response for PHI leakage.
func (s *Sanitizer) Scan(ctx context.Context, response string) (*types.SanitizationResult, error) {
	start := time.Now()

	// TODO: Run NER model on response text
	// TODO: Run regex patterns for 18 HIPAA identifiers
	// TODO: Check for indirect exfiltration:
	//   - Parse URLs, check query params for PHI patterns
	//   - Parse markdown links, check href and text
	//   - Parse JSON tool-call arguments
	//   - Detect base64-encoded strings, decode and scan
	//   - Detect URL-encoded strings, decode and scan

	_ = ctx
	_ = response

	latency := time.Since(start).Milliseconds()

	return &types.SanitizationResult{
		PHIDetected:        false,
		ExfiltrationAttempt: false,
		EntitiesRedacted:   0,
		LatencyMs:          latency,
	}, fmt.Errorf("sanitizer: not implemented")
}

// Redact replaces detected PHI entities with [REDACTED] markers.
func (s *Sanitizer) Redact(response string, entities []DetectedEntity) string {
	// TODO: Replace each entity span with [REDACTED-{TYPE}]
	// Process in reverse order to preserve offsets
	return response
}

// DetectedEntity represents a PHI entity found in output.
type DetectedEntity struct {
	Type       string `json:"type"`        // HIPAA identifier type
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Confidence float64 `json:"confidence"`
	Channel    string `json:"channel"` // "direct", "url_param", "markdown", "tool_arg", "base64"
}
