// Package config loads and validates AEGIS configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level AEGIS configuration.
type Config struct {
	Proxy      ProxyConfig      `yaml:"proxy"`
	Thresholds ThresholdsConfig `yaml:"thresholds"`
	Classifier ClassifierConfig `yaml:"classifier"`
	Auditor    AuditorConfig    `yaml:"auditor"`
	Sanitizer  SanitizerConfig  `yaml:"sanitizer"`
	Notify     NotifyConfig     `yaml:"notify"`
	Audit      AuditConfig      `yaml:"audit"`
	Metrics    MetricsConfig    `yaml:"metrics"`
	Logging    LoggingConfig    `yaml:"logging"`
}

type ProxyConfig struct {
	ListenAddr   string        `yaml:"listen_addr"`
	AgentURL     string        `yaml:"agent_url"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type ThresholdsConfig struct {
	AutoProceed   float64 `yaml:"auto_proceed"`
	HoldAndNotify float64 `yaml:"hold_and_notify"`
	PHIMultiplier float64 `yaml:"phi_multiplier"`
}

type ClassifierConfig struct {
	ModelPath        string        `yaml:"model_path"`
	VocabPath        string        `yaml:"vocab_path"`
	MaxInputLen      int           `yaml:"max_input_len"`
	InferenceTimeout time.Duration `yaml:"inference_timeout"`
}

type AuditorConfig struct {
	Provider string        `yaml:"provider"` // "openai", "anthropic", "ollama"
	BaseURL  string        `yaml:"base_url"`
	APIKey   string        `yaml:"api_key"`
	Model    string        `yaml:"model"`
	Timeout  time.Duration `yaml:"timeout"`
}

type SanitizerConfig struct {
	NERModelPath string `yaml:"ner_model_path"`
	RedactMode   string `yaml:"redact_mode"` // "redact" or "block"
}

type NotifyConfig struct {
	WebhookURL       string        `yaml:"webhook_url"`
	Timeout          time.Duration `yaml:"timeout"`
	DefaultOnTimeout string        `yaml:"default_on_timeout"` // "proceed" or "block"
}

type AuditConfig struct {
	Output              string `yaml:"output"` // "stdout", "file", or "both"
	FilePath            string `yaml:"file_path"`
	RedactFlaggedContent bool  `yaml:"redact_flagged_content"`
}

type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "json" or "text"
}

// Load reads configuration from a YAML file and applies environment overrides.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	applyEnvOverrides(cfg)
	setDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AEGIS_AUDITOR_API_KEY"); v != "" {
		cfg.Auditor.APIKey = v
	}
	if v := os.Getenv("AEGIS_AUDITOR_BASE_URL"); v != "" {
		cfg.Auditor.BaseURL = v
	}
	if v := os.Getenv("AEGIS_NOTIFY_WEBHOOK"); v != "" {
		cfg.Notify.WebhookURL = v
	}
	if v := os.Getenv("AEGIS_AGENT_URL"); v != "" {
		cfg.Proxy.AgentURL = v
	}
}

func setDefaults(cfg *Config) {
	if cfg.Proxy.ListenAddr == "" {
		cfg.Proxy.ListenAddr = ":8080"
	}
	if cfg.Proxy.ReadTimeout == 0 {
		cfg.Proxy.ReadTimeout = 30 * time.Second
	}
	if cfg.Proxy.WriteTimeout == 0 {
		cfg.Proxy.WriteTimeout = 30 * time.Second
	}
	if cfg.Thresholds.AutoProceed == 0 {
		cfg.Thresholds.AutoProceed = 0.85
	}
	if cfg.Thresholds.HoldAndNotify == 0 {
		cfg.Thresholds.HoldAndNotify = 0.60
	}
	if cfg.Thresholds.PHIMultiplier == 0 {
		cfg.Thresholds.PHIMultiplier = 1.5
	}
	if cfg.Classifier.MaxInputLen == 0 {
		cfg.Classifier.MaxInputLen = 128
	}
	if cfg.Classifier.InferenceTimeout == 0 {
		cfg.Classifier.InferenceTimeout = 10 * time.Millisecond
	}
	if cfg.Auditor.Timeout == 0 {
		cfg.Auditor.Timeout = 5 * time.Second
	}
	if cfg.Auditor.Provider == "" {
		cfg.Auditor.Provider = "openai"
	}
	if cfg.Sanitizer.RedactMode == "" {
		cfg.Sanitizer.RedactMode = "block"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Metrics.ListenAddr == "" {
		cfg.Metrics.ListenAddr = ":9090"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
}

func validate(cfg *Config) error {
	if cfg.Thresholds.AutoProceed <= cfg.Thresholds.HoldAndNotify {
		return fmt.Errorf("auto_proceed (%f) must be > hold_and_notify (%f)",
			cfg.Thresholds.AutoProceed, cfg.Thresholds.HoldAndNotify)
	}
	if cfg.Sanitizer.RedactMode != "redact" && cfg.Sanitizer.RedactMode != "block" {
		return fmt.Errorf("redact_mode must be 'redact' or 'block', got %q", cfg.Sanitizer.RedactMode)
	}
	return nil
}
