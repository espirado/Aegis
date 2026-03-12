// Package classifier implements Layer 1: Input Classification.
//
// Uses an ONNX model to classify incoming prompts into one of five
// categories: benign, direct injection, indirect injection, jailbreak,
// or PHI extraction probe.
//
// Design constraints:
//   - Inference must complete in < 10ms p50
//   - Runs on CPU (no GPU dependency in production proxy)
//   - Model loaded once at startup, immutable at runtime
package classifier

import (
	"context"
	"fmt"
	"time"

	"github.com/YOUR_ORG/aegis/pkg/types"
)

// Classifier performs Layer 1 input classification.
type Classifier struct {
	// TODO: ONNX runtime session
	// TODO: Tokenizer
	modelPath string
	maxLen    int
}

// Config for the classifier.
type Config struct {
	ModelPath     string `yaml:"model_path"`
	MaxInputLen   int    `yaml:"max_input_len"`    // Truncate inputs beyond this
	InferenceTimeout time.Duration `yaml:"inference_timeout"` // Hard limit on inference time
}

// New creates a Classifier, loading the ONNX model from disk.
func New(cfg Config) (*Classifier, error) {
	if cfg.ModelPath == "" {
		return nil, fmt.Errorf("classifier: model_path is required")
	}
	if cfg.MaxInputLen == 0 {
		cfg.MaxInputLen = 512
	}

	// TODO: Load ONNX model via onnxruntime-go
	// TODO: Validate model input/output shapes
	// TODO: Warm up with a test inference

	return &Classifier{
		modelPath: cfg.ModelPath,
		maxLen:    cfg.MaxInputLen,
	}, nil
}

// Classify runs the input through the ONNX model and returns the
// classification result with confidence score.
func (c *Classifier) Classify(ctx context.Context, input string) (*types.ClassificationResult, error) {
	start := time.Now()

	// TODO: Tokenize input
	// TODO: Truncate/pad to maxLen
	// TODO: Run ONNX inference
	// TODO: Softmax over logits → class + confidence

	_ = ctx    // Will be used for cancellation
	_ = input  // Will be tokenized

	latency := time.Since(start).Milliseconds()

	// Placeholder — replace with real inference
	return &types.ClassificationResult{
		Class:      types.ClassBenign,
		Confidence: 0.0,
		LatencyMs:  latency,
	}, fmt.Errorf("classifier: not implemented — load ONNX model")
}

// Close releases ONNX runtime resources.
func (c *Classifier) Close() error {
	// TODO: Release ONNX session
	return nil
}
