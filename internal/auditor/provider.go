package auditor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LLMProvider abstracts an LLM chat completion backend.
type LLMProvider interface {
	ChatCompletion(ctx context.Context, systemPrompt, userMessage string) (string, error)
	Name() string
}

// --- OpenAI-compatible provider ---
// Works with: OpenAI, Ollama, vLLM, llama.cpp, LM Studio, and any
// server exposing /v1/chat/completions in the OpenAI format.

type OpenAICompatProvider struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

func NewOpenAICompatProvider(baseURL, apiKey, model string, timeout time.Duration) *OpenAICompatProvider {
	return &OpenAICompatProvider{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{Timeout: timeout},
	}
}

func (p *OpenAICompatProvider) Name() string { return "openai-compat" }

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *OpenAICompatProvider) ChatCompletion(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMessage},
		},
		Temperature: 0.0,
		MaxTokens:   512,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("openai: marshal request: %w", err)
	}

	url := p.baseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("openai: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("openai: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai: status %d: %s", resp.StatusCode, string(respBody))
	}

	var result openAIResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("openai: unmarshal response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("openai: api error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response (no choices)")
	}

	return result.Choices[0].Message.Content, nil
}

// --- Anthropic provider ---

type AnthropicProvider struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

func NewAnthropicProvider(baseURL, apiKey, model string, timeout time.Duration) *AnthropicProvider {
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	return &AnthropicProvider{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{Timeout: timeout},
	}
}

func (p *AnthropicProvider) Name() string { return "anthropic" }

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *AnthropicProvider) ChatCompletion(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 512,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userMessage},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("anthropic: marshal request: %w", err)
	}

	url := p.baseURL + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("anthropic: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("anthropic: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic: status %d: %s", resp.StatusCode, string(respBody))
	}

	var result anthropicResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("anthropic: unmarshal response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("anthropic: api error: %s", result.Error.Message)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("anthropic: empty response")
	}

	return result.Content[0].Text, nil
}

// NewProvider creates the appropriate LLM provider from config.
func NewProvider(provider, baseURL, apiKey, model string, timeout time.Duration) (LLMProvider, error) {
	switch provider {
	case "openai":
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return NewOpenAICompatProvider(baseURL, apiKey, model, timeout), nil

	case "ollama":
		if baseURL == "" {
			baseURL = "http://localhost:11434/v1"
		}
		return NewOpenAICompatProvider(baseURL, apiKey, model, timeout), nil

	case "anthropic":
		return NewAnthropicProvider(baseURL, apiKey, model, timeout), nil

	default:
		// Treat unknown providers as OpenAI-compatible (covers vLLM, llama.cpp, LM Studio)
		if baseURL == "" {
			return nil, fmt.Errorf("auditor: base_url required for provider %q", provider)
		}
		return NewOpenAICompatProvider(baseURL, apiKey, model, timeout), nil
	}
}
