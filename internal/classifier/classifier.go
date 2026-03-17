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
	"log/slog"
	"math"
	"time"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/espirado/aegis/pkg/types"
)

const numClasses = 5

// Classifier performs Layer 1 input classification via ONNX Runtime.
type Classifier struct {
	session   *ort.DynamicAdvancedSession
	tokenizer *WordPieceTokenizer
	maxLen    int
}

// Config for the classifier.
type Config struct {
	ModelPath        string        `yaml:"model_path"`
	VocabPath        string        `yaml:"vocab_path"`
	MaxInputLen      int           `yaml:"max_input_len"`
	InferenceTimeout time.Duration `yaml:"inference_timeout"`
}

// New creates a Classifier, loading the ONNX model and tokenizer.
func New(cfg Config) (*Classifier, error) {
	if cfg.ModelPath == "" {
		return nil, fmt.Errorf("classifier: model_path is required")
	}
	if cfg.VocabPath == "" {
		return nil, fmt.Errorf("classifier: vocab_path is required")
	}
	if cfg.MaxInputLen == 0 {
		cfg.MaxInputLen = 128
	}

	tokenizer, err := NewWordPieceTokenizer(cfg.VocabPath, cfg.MaxInputLen)
	if err != nil {
		return nil, fmt.Errorf("classifier: load tokenizer: %w", err)
	}
	slog.Info("classifier tokenizer loaded", "vocab_size", tokenizer.VocabSize(), "max_len", cfg.MaxInputLen)

	inputNames := []string{"input_ids", "attention_mask"}
	outputNames := []string{"logits"}
	session, err := ort.NewDynamicAdvancedSession(
		cfg.ModelPath,
		inputNames,
		outputNames,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("classifier: load ONNX model: %w", err)
	}
	slog.Info("classifier ONNX model loaded", "model_path", cfg.ModelPath)

	c := &Classifier{
		session:   session,
		tokenizer: tokenizer,
		maxLen:    cfg.MaxInputLen,
	}

	// Warm-up inference
	if _, err := c.Classify(context.Background(), "test"); err != nil {
		slog.Warn("classifier warm-up failed", "error", err)
	}

	return c, nil
}

// Classify runs the input through the ONNX model and returns the
// classification result with confidence score.
func (c *Classifier) Classify(ctx context.Context, input string) (*types.ClassificationResult, error) {
	start := time.Now()

	inputIDs, attentionMask := c.tokenizer.Encode(input)

	shape := ort.Shape{1, int64(c.maxLen)}
	inputIDsTensor, err := ort.NewTensor(shape, inputIDs)
	if err != nil {
		return nil, fmt.Errorf("classifier: create input_ids tensor: %w", err)
	}
	defer inputIDsTensor.Destroy()

	maskTensor, err := ort.NewTensor(shape, attentionMask)
	if err != nil {
		return nil, fmt.Errorf("classifier: create attention_mask tensor: %w", err)
	}
	defer maskTensor.Destroy()

	outputTensor, err := ort.NewEmptyTensor[float32](ort.Shape{1, numClasses})
	if err != nil {
		return nil, fmt.Errorf("classifier: create output tensor: %w", err)
	}
	defer outputTensor.Destroy()

	err = c.session.Run(
		[]ort.ArbitraryTensor{inputIDsTensor, maskTensor},
		[]ort.ArbitraryTensor{outputTensor},
	)
	if err != nil {
		return nil, fmt.Errorf("classifier: inference failed: %w", err)
	}

	logits := outputTensor.GetData()
	probs := softmax(logits)

	bestClass := 0
	bestProb := probs[0]
	for i := 1; i < len(probs); i++ {
		if probs[i] > bestProb {
			bestProb = probs[i]
			bestClass = i
		}
	}

	return &types.ClassificationResult{
		Class:      types.InputClass(bestClass),
		Confidence: float64(bestProb),
		LatencyMs:  time.Since(start).Milliseconds(),
	}, nil
}

// Close releases ONNX runtime resources.
func (c *Classifier) Close() error {
	if c.session != nil {
		c.session.Destroy()
	}
	return nil
}

func softmax(logits []float32) []float32 {
	maxVal := logits[0]
	for _, v := range logits[1:] {
		if v > maxVal {
			maxVal = v
		}
	}

	var sum float64
	probs := make([]float32, len(logits))
	for i, v := range logits {
		exp := math.Exp(float64(v - maxVal))
		probs[i] = float32(exp)
		sum += exp
	}

	for i := range probs {
		probs[i] = float32(float64(probs[i]) / sum)
	}

	return probs
}
