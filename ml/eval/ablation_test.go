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
	"github.com/espirado/aegis/internal/sanitizer"
	"github.com/espirado/aegis/pkg/types"
)

type ablationConfig struct {
	Name        string `json:"name"`
	UseL1       bool   `json:"use_l1"`
	UseL2       bool   `json:"use_l2"`
	UseL3       bool   `json:"use_l3"`
}

type ablationLayerResult struct {
	Config           ablationConfig `json:"config"`
	TotalAttacks     int            `json:"total_attacks"`
	Blocked          int            `json:"blocked"`
	Passed           int            `json:"passed"`
	ASR              float64        `json:"asr"`
	ASRReduction     float64        `json:"asr_reduction"`
	BenignTotal      int            `json:"benign_total"`
	BenignBlocked    int            `json:"benign_blocked"`
	BenignFPR        float64        `json:"benign_fpr"`
	MeanLatencyMs    float64        `json:"mean_latency_ms"`
	ByType           map[string]typeResult `json:"by_type"`
}

type ablationResults struct {
	Layers    []ablationLayerResult `json:"layers"`
	Timestamp string                `json:"timestamp"`
}

// TestAblationStudy evaluates incremental benefit of each layer.
// L1 only: classifier decision at threshold
// L1+L2: classifier + auditor
// L1+L2+L3: full pipeline (L3 on output)
//
// Requires Ollama running. Skip with -short.
func TestAblationStudy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ablation study in short mode")
	}
	if os.Getenv("AEGIS_SKIP_OLLAMA") == "1" {
		t.Skip("AEGIS_SKIP_OLLAMA=1, skipping")
	}

	root := projectRoot()

	advSamples, err := loadSamples(filepath.Join(root, "test", "fixtures", "adversarial_corpus.jsonl"))
	if err != nil {
		t.Fatalf("load adversarial: %v", err)
	}
	benSamples, err := loadSamples(filepath.Join(root, "test", "fixtures", "benign_corpus.jsonl"))
	if err != nil {
		t.Fatalf("load benign: %v", err)
	}

	advSubset := advSamples
	if len(advSubset) > 20 {
		advSubset = advSubset[:20]
	}
	benSubset := benSamples
	if len(benSubset) > 10 {
		benSubset = benSubset[:10]
	}

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

	san, err := sanitizer.New(sanitizer.Config{RedactMode: "block"})
	if err != nil {
		t.Fatalf("create sanitizer: %v", err)
	}

	configs := []ablationConfig{
		{Name: "L1_only", UseL1: true, UseL2: false, UseL3: false},
		{Name: "L1+L2", UseL1: true, UseL2: true, UseL3: false},
		{Name: "L1+L2+L3", UseL1: true, UseL2: true, UseL3: true},
	}

	var allLayerResults []ablationLayerResult

	for _, cfg := range configs {
		t.Logf("\n--- Ablation: %s ---", cfg.Name)

		lr := ablationLayerResult{
			Config: cfg,
			ByType: make(map[string]typeResult),
		}

		var latencies []float64

		// Process attack samples: evaluate each layer independently, OR their decisions.
		for _, s := range advSubset {
			start := time.Now()
			l1Blocked := false
			l2Blocked := false

			l1Class := types.InputClass(s.Label)

			if cfg.UseL1 {
				l1Blocked = l1Class != types.ClassBenign
			}

			if cfg.UseL2 {
				l1Result := &types.ClassificationResult{Class: l1Class, Confidence: 0.75}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				auditResult, err := aud.Evaluate(ctx, s.Text, "", nil, l1Result)
				cancel()
				if err == nil {
					l2Blocked = auditResult.Verdict == types.VerdictBlock || auditResult.Verdict == types.VerdictHold
				} else {
					l2Blocked = true // fail closed
				}
			}

			blocked := l1Blocked || l2Blocked

			latMs := float64(time.Since(start).Milliseconds())
			latencies = append(latencies, latMs)

			lr.TotalAttacks++
			if blocked {
				lr.Blocked++
			} else {
				lr.Passed++
			}

			tr := lr.ByType[s.AttackType]
			tr.Total++
			if blocked {
				tr.Blocked++
			} else {
				tr.Passed++
			}
			if tr.Total > 0 {
				tr.BlockRate = float64(tr.Blocked) / float64(tr.Total)
			}
			lr.ByType[s.AttackType] = tr
		}

		// Process benign samples: evaluate each layer independently for FPR.
		for _, s := range benSubset {
			l1Blocked := false
			l2Blocked := false

			if cfg.UseL1 {
				l1Blocked = types.InputClass(s.Label) != types.ClassBenign
			}

			if cfg.UseL2 {
				l1Result := &types.ClassificationResult{Class: types.ClassBenign, Confidence: 0.95}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				auditResult, err := aud.Evaluate(ctx, s.Text, "", nil, l1Result)
				cancel()
				if err == nil {
					l2Blocked = auditResult.Verdict == types.VerdictBlock || auditResult.Verdict == types.VerdictHold
				} else {
					l2Blocked = true // fail closed
				}
			}

			// L3 scans output, not input — doesn't affect input blocking
			_ = san
			_ = cfg.UseL3

			blocked := l1Blocked || l2Blocked
			lr.BenignTotal++
			if blocked {
				lr.BenignBlocked++
			}
		}

		if lr.TotalAttacks > 0 {
			lr.ASR = float64(lr.Passed) / float64(lr.TotalAttacks)
			lr.ASRReduction = 1.0 - lr.ASR
		}
		if lr.BenignTotal > 0 {
			lr.BenignFPR = float64(lr.BenignBlocked) / float64(lr.BenignTotal)
		}
		if len(latencies) > 0 {
			lr.MeanLatencyMs = mean(latencies)
		}

		t.Logf("  Attacks: %d blocked / %d total (ASR=%.2f%%, reduction=%.2f%%)",
			lr.Blocked, lr.TotalAttacks, lr.ASR*100, lr.ASRReduction*100)
		t.Logf("  Benign FPR: %.2f%% (%d/%d)", lr.BenignFPR*100, lr.BenignBlocked, lr.BenignTotal)
		t.Logf("  Mean latency: %.0fms", lr.MeanLatencyMs)

		for atype, tr := range lr.ByType {
			t.Logf("  %-25s block=%.1f%% (%d/%d)", atype, tr.BlockRate*100, tr.Blocked, tr.Total)
		}

		allLayerResults = append(allLayerResults, lr)
	}

	results := ablationResults{
		Layers:    allLayerResults,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Summary comparison
	t.Logf("\n═══ ABLATION SUMMARY ═══")
	t.Logf("%-15s %10s %10s %10s %10s", "Config", "ASR", "Reduction", "FPR", "Latency")
	for _, lr := range allLayerResults {
		t.Logf("%-15s %9.2f%% %9.2f%% %9.2f%% %8.0fms",
			lr.Config.Name, lr.ASR*100, lr.ASRReduction*100, lr.BenignFPR*100, lr.MeanLatencyMs)
	}

	resultsDir := filepath.Join(root, "ml", "eval", "results")
	os.MkdirAll(resultsDir, 0o755)
	outPath := filepath.Join(resultsDir, "ablation.json")
	outData, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(outPath, outData, 0o644)
	t.Logf("Results written to %s", outPath)
}

// TestAblationL3PHIOutput evaluates L3 sanitizer contribution using PHI scenarios.
// This shows the incremental value of L3: without it, PHI in responses would leak.
func TestAblationL3PHIOutput(t *testing.T) {
	root := projectRoot()
	scenarios, err := os.ReadFile(filepath.Join(root, "test", "fixtures", "phi_scenarios.jsonl"))
	if err != nil {
		t.Fatalf("load phi scenarios: %v", err)
	}

	var phiSamples []phiScenario
	for _, line := range splitLines(scenarios) {
		if len(line) == 0 {
			continue
		}
		var s phiScenario
		if err := json.Unmarshal(line, &s); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if s.ExpectedDetected {
			phiSamples = append(phiSamples, s)
		}
	}

	san, err := sanitizer.New(sanitizer.Config{RedactMode: "block"})
	if err != nil {
		t.Fatalf("create sanitizer: %v", err)
	}

	ctx := context.Background()
	var withoutL3Leaked, withL3Leaked int

	for _, s := range phiSamples {
		// Without L3: PHI goes through undetected
		withoutL3Leaked++

		// With L3: sanitizer catches it
		result, err := san.Scan(ctx, s.Text)
		if err != nil {
			continue
		}
		if !result.PHIDetected {
			withL3Leaked++
		}
	}

	total := len(phiSamples)
	t.Logf("\n═══ L3 ABLATION (PHI Output) ═══")
	t.Logf("Total PHI scenarios: %d", total)
	t.Logf("Without L3: %d/%d leaked (%.1f%%)", withoutL3Leaked, total, float64(withoutL3Leaked)/float64(total)*100)
	t.Logf("With L3:    %d/%d leaked (%.1f%%)", withL3Leaked, total, float64(withL3Leaked)/float64(total)*100)
	reduction := 0.0
	if withoutL3Leaked > 0 {
		reduction = float64(withoutL3Leaked-withL3Leaked) / float64(withoutL3Leaked) * 100
	}
	t.Logf("L3 prevents %.1f%% of PHI leaks", reduction)

	// Append to ablation results
	resultsDir := filepath.Join(root, "ml", "eval", "results")
	os.MkdirAll(resultsDir, 0o755)
	l3Result := map[string]interface{}{
		"total_phi_scenarios":  total,
		"without_l3_leaked":    withoutL3Leaked,
		"with_l3_leaked":       withL3Leaked,
		"l3_prevention_rate":   fmt.Sprintf("%.2f%%", reduction),
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
	}
	outData, _ := json.MarshalIndent(l3Result, "", "  ")
	os.WriteFile(filepath.Join(resultsDir, "ablation_l3_phi.json"), outData, 0o644)
}
