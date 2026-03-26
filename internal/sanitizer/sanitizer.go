// Package sanitizer implements Layer 3: Output Sanitization.
//
// Scans AI agent responses for PHI leakage across all channels:
//   - Direct PHI in response text (regex for 18 HIPAA identifiers)
//   - Indirect exfiltration via URL parameters, markdown links,
//     code blocks, base64-encoded content, and tool-call arguments
package sanitizer

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/espirado/aegis/pkg/phi"
	"github.com/espirado/aegis/pkg/types"
)

// Sanitizer performs Layer 3 output inspection.
type Sanitizer struct {
	patterns      []phi.Pattern
	inputPatterns []phi.Pattern
	redactMode    string
}

// Config for the sanitizer.
type Config struct {
	NERModelPath string `yaml:"ner_model_path"`
	RedactMode   string `yaml:"redact_mode"` // "redact" or "block"
}

// New creates a Sanitizer with compiled regex patterns.
func New(cfg Config) (*Sanitizer, error) {
	patterns := phi.Patterns()

	mode := cfg.RedactMode
	if mode == "" {
		mode = "block"
	}

	slog.Info("sanitizer initialized",
		"regex_patterns", len(patterns),
		"redact_mode", mode,
	)

	return &Sanitizer{
		patterns:      patterns,
		inputPatterns: phi.InputPatterns(),
		redactMode:    mode,
	}, nil
}

// Scan inspects an agent response for PHI leakage.
func (s *Sanitizer) Scan(ctx context.Context, response string) (*types.SanitizationResult, error) {
	start := time.Now()
	_ = ctx

	var allEntities []DetectedEntity

	// Direct regex scan on response text
	directEntities := s.scanDirect(response)
	allEntities = append(allEntities, directEntities...)

	// Indirect exfiltration scan (URLs, markdown, code, base64)
	exfilEntities := scanExfiltration(response, s.patterns)
	allEntities = append(allEntities, exfilEntities...)

	// Deduplicate overlapping entities
	allEntities = deduplicateEntities(allEntities)

	phiTypes := uniquePHITypes(allEntities)
	hasExfil := false
	for _, e := range allEntities {
		if e.Channel != "direct" {
			hasExfil = true
			break
		}
	}

	return &types.SanitizationResult{
		PHIDetected:        len(allEntities) > 0,
		ExfiltrationAttempt: hasExfil,
		EntitiesRedacted:   len(allEntities),
		PHITypes:           phiTypes,
		LatencyMs:          time.Since(start).Milliseconds(),
	}, nil
}

// Redact replaces detected PHI entities with [REDACTED-TYPE] markers.
func (s *Sanitizer) Redact(response string, entities []DetectedEntity) string {
	if len(entities) == 0 {
		return response
	}

	// Sort by start position descending so replacements don't shift offsets
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].StartChar > entities[j].StartChar
	})

	result := response
	for _, e := range entities {
		if e.StartChar >= 0 && e.EndChar <= len(result) && e.StartChar < e.EndChar {
			replacement := "[REDACTED-" + e.Type + "]"
			result = result[:e.StartChar] + replacement + result[e.EndChar:]
		}
	}

	return result
}

// ScanAndRedact combines scanning and optional redaction in one call.
func (s *Sanitizer) ScanAndRedact(ctx context.Context, response string) (string, *types.SanitizationResult, []DetectedEntity, error) {
	result, err := s.Scan(ctx, response)
	if err != nil {
		return response, result, nil, err
	}

	if !result.PHIDetected {
		return response, result, nil, nil
	}

	var allEntities []DetectedEntity
	allEntities = append(allEntities, s.scanDirect(response)...)
	allEntities = append(allEntities, scanExfiltration(response, s.patterns)...)
	allEntities = deduplicateEntities(allEntities)

	if s.redactMode == "redact" {
		redacted := s.Redact(response, allEntities)
		return redacted, result, allEntities, nil
	}

	return "", result, allEntities, nil
}

func (s *Sanitizer) scanDirect(text string) []DetectedEntity {
	var entities []DetectedEntity

	for _, p := range s.patterns {
		locs := p.Regex.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			entities = append(entities, DetectedEntity{
				Type:       string(p.Type),
				StartChar:  loc[0],
				EndChar:    loc[1],
				Confidence: 1.0,
				Channel:    "direct",
			})
		}
	}

	return entities
}

func deduplicateEntities(entities []DetectedEntity) []DetectedEntity {
	if len(entities) <= 1 {
		return entities
	}

	sort.Slice(entities, func(i, j int) bool {
		if entities[i].StartChar != entities[j].StartChar {
			return entities[i].StartChar < entities[j].StartChar
		}
		return entities[i].EndChar > entities[j].EndChar
	})

	var result []DetectedEntity
	result = append(result, entities[0])
	for i := 1; i < len(entities); i++ {
		last := result[len(result)-1]
		if entities[i].StartChar >= last.EndChar {
			result = append(result, entities[i])
		} else if entities[i].Type != last.Type || entities[i].Channel != last.Channel {
			result = append(result, entities[i])
		}
	}

	return result
}

func uniquePHITypes(entities []DetectedEntity) []string {
	seen := make(map[string]bool)
	var result []string
	for _, e := range entities {
		if !seen[e.Type] {
			seen[e.Type] = true
			result = append(result, e.Type)
		}
	}
	return result
}

// DetectedEntity represents a PHI entity found in output.
type DetectedEntity struct {
	Type       string  `json:"type"`
	StartChar  int     `json:"start_char"`
	EndChar    int     `json:"end_char"`
	Confidence float64 `json:"confidence"`
	Channel    string  `json:"channel"` // "direct", "url_param", "markdown", "tool_arg", "base64", "code_block"
}

// RedactMode returns the configured redaction mode.
func (s *Sanitizer) RedactMode() string {
	return s.redactMode
}

// ScanText is a convenience method for checking a string for PHI.
func (s *Sanitizer) ScanText(text string) []DetectedEntity {
	var entities []DetectedEntity
	entities = append(entities, s.scanDirect(text)...)
	entities = append(entities, scanExfiltration(text, s.patterns)...)
	return deduplicateEntities(entities)
}

// ScanInputText detects patient identifiers using the targeted input
// patterns. Operational data (service dates, NPIs, codes) is preserved.
func (s *Sanitizer) ScanInputText(text string) []DetectedEntity {
	var entities []DetectedEntity
	for _, p := range s.inputPatterns {
		locs := p.Regex.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			entities = append(entities, DetectedEntity{
				Type:       string(p.Type),
				StartChar:  loc[0],
				EndChar:    loc[1],
				Confidence: 1.0,
				Channel:    "direct",
			})
		}
	}
	return deduplicateEntities(entities)
}

// ContainsPHI returns true if the text contains any PHI patterns.
func (s *Sanitizer) ContainsPHI(text string) bool {
	for _, p := range s.patterns {
		if p.Regex.MatchString(text) {
			return true
		}
	}
	return false
}

// Mask replaces a detected value with asterisks, preserving length hints.
func Mask(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}
