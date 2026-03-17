package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/espirado/aegis/internal/auditor"
	"github.com/espirado/aegis/pkg/types"
)

type evalSample struct {
	ID         string `json:"id"`
	Text       string `json:"text"`
	Label      int    `json:"label"`
	AttackType string `json:"attack_type"`
	Source     string `json:"source"`
}

type auditorEvalResults struct {
	Provider         string           `json:"provider"`
	Model            string           `json:"model"`
	TotalSamples     int              `json:"total_samples"`
	AttackSamples    int              `json:"attack_samples"`
	BenignSamples    int              `json:"benign_samples"`
	TruePositives    int              `json:"true_positives"`
	FalsePositives   int              `json:"false_positives"`
	TrueNegatives    int              `json:"true_negatives"`
	FalseNegatives   int              `json:"false_negatives"`
	Accuracy         float64          `json:"accuracy"`
	TPR              float64          `json:"true_positive_rate"`
	FPR              float64          `json:"false_positive_rate"`
	MeanLatencyMs    float64          `json:"mean_latency_ms"`
	P50LatencyMs     float64          `json:"p50_latency_ms"`
	P95LatencyMs     float64          `json:"p95_latency_ms"`
	ByType           map[string]typeResult `json:"by_type"`
	Errors           int              `json:"errors"`
	ErrorDetails     []string         `json:"error_details,omitempty"`
	Timestamp        string           `json:"timestamp"`
}

type typeResult struct {
	Total    int     `json:"total"`
	Blocked  int     `json:"blocked"`
	Passed   int     `json:"passed"`
	BlockRate float64 `json:"block_rate"`
}

func loadSamples(path string) ([]evalSample, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var samples []evalSample
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var s evalSample
		if err := json.Unmarshal(line, &s); err != nil {
			return nil, err
		}
		samples = append(samples, s)
	}
	return samples, nil
}

// TestAuditorEvalOllama evaluates the L2 auditor with a live Ollama/Llama backend.
// Skip with -short or if AEGIS_SKIP_OLLAMA=1 is set.
func TestAuditorEvalOllama(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Ollama evaluation in short mode")
	}
	if os.Getenv("AEGIS_SKIP_OLLAMA") == "1" {
		t.Skip("AEGIS_SKIP_OLLAMA=1, skipping")
	}

	root := projectRoot()

	advSamples, err := loadSamples(filepath.Join(root, "test", "fixtures", "adversarial_corpus.jsonl"))
	if err != nil {
		t.Fatalf("load adversarial corpus: %v", err)
	}
	benSamples, err := loadSamples(filepath.Join(root, "test", "fixtures", "benign_corpus.jsonl"))
	if err != nil {
		t.Fatalf("load benign corpus: %v", err)
	}

	// Use a subset for reasonable runtime: 30 attacks + 20 benign
	advSubset := advSamples
	if len(advSubset) > 30 {
		advSubset = advSubset[:30]
	}
	benSubset := benSamples
	if len(benSubset) > 20 {
		benSubset = benSubset[:20]
	}

	allSamples := append(advSubset, benSubset...)
	t.Logf("Evaluating %d samples (%d attack, %d benign)", len(allSamples), len(advSubset), len(benSubset))

	model := os.Getenv("AEGIS_OLLAMA_MODEL")
	if model == "" {
		model = "llama3.1:8b"
	}

	aud, err := auditor.New(auditor.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    model,
		Timeout:  60 * time.Second,
	})
	if err != nil {
		t.Fatalf("create auditor: %v", err)
	}

	results := auditorEvalResults{
		Provider:    "ollama",
		Model:       model,
		ByType:      make(map[string]typeResult),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	var latencies []float64
	var tp, fp, tn, fn, errCount int
	var errDetails []string

	for i, s := range allSamples {
		isAttack := s.Label != 0

		l1Class := types.InputClass(s.Label)
		l1Result := &types.ClassificationResult{
			Class:      l1Class,
			Confidence: 0.75,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		start := time.Now()
		auditResult, err := aud.Evaluate(ctx, s.Text, "", nil, l1Result)
		latMs := float64(time.Since(start).Milliseconds())
		cancel()

		if err != nil {
			errCount++
			errDetails = append(errDetails, fmt.Sprintf("%s: %v", s.ID, err))
			t.Logf("[%d/%d] %s ERROR: %v", i+1, len(allSamples), s.ID, err)
			continue
		}

		latencies = append(latencies, latMs)
		blocked := auditResult.Verdict == types.VerdictBlock || auditResult.Verdict == types.VerdictHold

		if isAttack {
			if blocked {
				tp++
			} else {
				fn++
				t.Logf("FALSE NEGATIVE: %s (type=%s verdict=%s reasoning=%s)",
					s.ID, s.AttackType, auditResult.Verdict, truncate(auditResult.Reasoning, 80))
			}
		} else {
			if blocked {
				fp++
				t.Logf("FALSE POSITIVE: %s (verdict=%s reasoning=%s)",
					s.ID, auditResult.Verdict, truncate(auditResult.Reasoning, 80))
			} else {
				tn++
			}
		}

		tr := results.ByType[s.AttackType]
		tr.Total++
		if blocked {
			tr.Blocked++
		} else {
			tr.Passed++
		}
		if tr.Total > 0 {
			tr.BlockRate = float64(tr.Blocked) / float64(tr.Total)
		}
		results.ByType[s.AttackType] = tr

		if (i+1)%10 == 0 {
			t.Logf("[%d/%d] processed (tp=%d fp=%d tn=%d fn=%d)", i+1, len(allSamples), tp, fp, tn, fn)
		}
	}

	total := tp + fp + tn + fn
	results.TotalSamples = total
	results.AttackSamples = tp + fn
	results.BenignSamples = tn + fp
	results.TruePositives = tp
	results.FalsePositives = fp
	results.TrueNegatives = tn
	results.FalseNegatives = fn
	results.Errors = errCount
	results.ErrorDetails = errDetails

	if total > 0 {
		results.Accuracy = float64(tp+tn) / float64(total)
	}
	if tp+fn > 0 {
		results.TPR = float64(tp) / float64(tp+fn)
	}
	if tn+fp > 0 {
		results.FPR = float64(fp) / float64(tn+fp)
	}

	if len(latencies) > 0 {
		results.MeanLatencyMs = mean(latencies)
		results.P50LatencyMs = percentile(latencies, 50)
		results.P95LatencyMs = percentile(latencies, 95)
	}

	t.Logf("\n═══ L2 AUDITOR EVALUATION ═══")
	t.Logf("Provider: %s  Model: %s", results.Provider, results.Model)
	t.Logf("Total: %d  Attacks: %d  Benign: %d  Errors: %d", results.TotalSamples, results.AttackSamples, results.BenignSamples, results.Errors)
	t.Logf("Accuracy: %.2f%%", results.Accuracy*100)
	t.Logf("TPR (attack block rate): %.2f%%", results.TPR*100)
	t.Logf("FPR (benign block rate): %.2f%%", results.FPR*100)
	t.Logf("Latency: mean=%.0fms p50=%.0fms p95=%.0fms", results.MeanLatencyMs, results.P50LatencyMs, results.P95LatencyMs)
	for atype, tr := range results.ByType {
		t.Logf("  %-25s block_rate=%.1f%% (%d/%d)", atype, tr.BlockRate*100, tr.Blocked, tr.Total)
	}

	resultsDir := filepath.Join(root, "ml", "eval", "results")
	os.MkdirAll(resultsDir, 0o755)
	outPath := filepath.Join(resultsDir, "l2_auditor.json")
	outData, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(outPath, outData, 0o644)
	t.Logf("Results written to %s", outPath)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	idx := int(p / 100 * float64(len(sorted)-1))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
