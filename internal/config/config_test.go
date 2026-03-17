package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aegis.yaml")
	content := `
proxy:
  listen_addr: ":8080"
  agent_url: "http://localhost:9000"
thresholds:
  auto_proceed: 0.85
  hold_and_notify: 0.60
  phi_multiplier: 1.5
classifier:
  model_path: "ml/models/classifier_v1.onnx"
  vocab_path: "ml/models/vocab.txt"
auditor:
  provider: "ollama"
  model: "llama3.2"
sanitizer:
  redact_mode: "block"
metrics:
  enabled: true
logging:
  level: "info"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Proxy.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.Proxy.ListenAddr)
	}
	if cfg.Auditor.Provider != "ollama" {
		t.Errorf("expected ollama, got %s", cfg.Auditor.Provider)
	}
	if cfg.Thresholds.AutoProceed != 0.85 {
		t.Errorf("expected 0.85, got %f", cfg.Thresholds.AutoProceed)
	}
}

func TestLoad_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "minimal.yaml")
	content := `
thresholds:
  auto_proceed: 0.90
  hold_and_notify: 0.50
sanitizer:
  redact_mode: "redact"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Proxy.ListenAddr != ":8080" {
		t.Errorf("expected default :8080, got %s", cfg.Proxy.ListenAddr)
	}
	if cfg.Classifier.MaxInputLen != 128 {
		t.Errorf("expected default 128, got %d", cfg.Classifier.MaxInputLen)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default info, got %s", cfg.Logging.Level)
	}
}

func TestLoad_InvalidThresholds(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	content := `
thresholds:
  auto_proceed: 0.50
  hold_and_notify: 0.80
sanitizer:
  redact_mode: "block"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected validation error for auto_proceed <= hold_and_notify")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aegis.yaml")
	content := `
thresholds:
  auto_proceed: 0.85
  hold_and_notify: 0.60
sanitizer:
  redact_mode: "block"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	t.Setenv("AEGIS_AUDITOR_API_KEY", "test-key-123")
	t.Setenv("AEGIS_AGENT_URL", "http://custom-agent:9000")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Auditor.APIKey != "test-key-123" {
		t.Errorf("expected API key from env, got %q", cfg.Auditor.APIKey)
	}
	if cfg.Proxy.AgentURL != "http://custom-agent:9000" {
		t.Errorf("expected agent URL from env, got %q", cfg.Proxy.AgentURL)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
