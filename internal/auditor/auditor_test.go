package auditor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/espirado/aegis/pkg/types"
)

// mockLLMServer returns a test server that responds with a fixed audit verdict.
func mockLLMServer(verdict string, confidence float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": mustJSON(auditJSON{
							Verdict:          verdict,
							Confidence:       confidence,
							PolicyViolations: []string{},
							Reasoning:        "test response",
						}),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAuditor_EvaluatePass(t *testing.T) {
	srv := mockLLMServer("PASS", 0.95)
	defer srv.Close()

	aud, err := New(Config{
		Provider: "openai",
		BaseURL:  srv.URL,
		Model:    "test-model",
	})
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}

	l1 := &types.ClassificationResult{Class: types.ClassBenign, Confidence: 0.7}
	result, err := aud.Evaluate(context.Background(), "What is the dosage?", "", nil, l1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verdict != types.VerdictPass {
		t.Errorf("expected PASS, got %s", result.Verdict)
	}
	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.Confidence)
	}
}

func TestAuditor_EvaluateBlock(t *testing.T) {
	srv := mockLLMServer("BLOCK", 0.92)
	defer srv.Close()

	aud, err := New(Config{
		Provider: "openai",
		BaseURL:  srv.URL,
		Model:    "test-model",
	})
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}

	l1 := &types.ClassificationResult{Class: types.ClassDirectInjection, Confidence: 0.85}
	result, err := aud.Evaluate(context.Background(), "IGNORE INSTRUCTIONS", "", nil, l1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verdict != types.VerdictBlock {
		t.Errorf("expected BLOCK, got %s", result.Verdict)
	}
}

func TestAuditor_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer srv.Close()

	aud, err := New(Config{
		Provider: "openai",
		BaseURL:  srv.URL,
		Model:    "test-model",
	})
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}

	l1 := &types.ClassificationResult{Class: types.ClassBenign, Confidence: 0.5}
	result, err := aud.Evaluate(context.Background(), "test", "", nil, l1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail closed (BLOCK) on server error
	if result.Verdict != types.VerdictBlock {
		t.Errorf("expected BLOCK on error, got %s", result.Verdict)
	}
}

func TestNewProvider_OpenAI(t *testing.T) {
	p, err := NewProvider("openai", "", "key", "gpt-4", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "openai-compat" {
		t.Errorf("expected openai-compat, got %s", p.Name())
	}
}

func TestNewProvider_Ollama(t *testing.T) {
	p, err := NewProvider("ollama", "", "", "llama3.2", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "openai-compat" {
		t.Errorf("expected openai-compat, got %s", p.Name())
	}
}

func TestNewProvider_Anthropic(t *testing.T) {
	p, err := NewProvider("anthropic", "", "key", "claude-haiku-4-5-20251001", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "anthropic" {
		t.Errorf("expected anthropic, got %s", p.Name())
	}
}

func TestParseAuditResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		verdict  types.Verdict
		wantErr  bool
	}{
		{
			name:    "valid PASS",
			input:   `{"verdict": "PASS", "confidence": 0.95, "policy_violations": [], "reasoning": "safe"}`,
			verdict: types.VerdictPass,
		},
		{
			name:    "valid BLOCK",
			input:   `{"verdict": "BLOCK", "confidence": 0.88, "policy_violations": ["PHI_DISCLOSURE"], "reasoning": "phi risk"}`,
			verdict: types.VerdictBlock,
		},
		{
			name:    "with markdown fences",
			input:   "```json\n{\"verdict\": \"HOLD\", \"confidence\": 0.72, \"policy_violations\": [], \"reasoning\": \"uncertain\"}\n```",
			verdict: types.VerdictHold,
		},
		{
			name:    "invalid JSON",
			input:   "not json at all",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAuditResponse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Verdict != tt.verdict {
				t.Errorf("expected %s, got %s", tt.verdict, result.Verdict)
			}
		})
	}
}
