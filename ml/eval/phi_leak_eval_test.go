package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/espirado/aegis/internal/sanitizer"
)

type phiScenario struct {
	ID               string   `json:"id"`
	Text             string   `json:"text"`
	PHITypes         []string `json:"phi_types"`
	Channels         []string `json:"channels"`
	PHICount         int      `json:"phi_count"`
	ExpectedDetected bool     `json:"expected_detected"`
}

type channelStats struct {
	Total    int
	Detected int
	Missed   int
}

type phiLeakResults struct {
	TotalScenarios   int                       `json:"total_scenarios"`
	WithPHI          int                       `json:"with_phi"`
	Clean            int                       `json:"clean"`
	OverallDetected  int                       `json:"overall_detected"`
	OverallMissed    int                       `json:"overall_missed"`
	LeakRate         float64                   `json:"leak_rate"`
	DetectionRate    float64                   `json:"detection_rate"`
	ByChannel        map[string]channelResult  `json:"by_channel"`
	FalsePositives   int                       `json:"false_positives"`
	FalsePositiveIDs []string                  `json:"false_positive_ids,omitempty"`
	MissedIDs        []string                  `json:"missed_ids,omitempty"`
	TargetMet        bool                      `json:"target_met"`
}

type channelResult struct {
	Total         int     `json:"total"`
	Detected      int     `json:"detected"`
	Missed        int     `json:"missed"`
	DetectionRate float64 `json:"detection_rate"`
}

func projectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func TestPHILeakRate(t *testing.T) {
	root := projectRoot()
	fixturesPath := filepath.Join(root, "test", "fixtures", "phi_scenarios.jsonl")

	data, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("failed to read fixtures: %v", err)
	}

	var scenarios []phiScenario
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var s phiScenario
		if err := json.Unmarshal(line, &s); err != nil {
			t.Fatalf("failed to parse scenario: %v", err)
		}
		scenarios = append(scenarios, s)
	}

	t.Logf("Loaded %d PHI scenarios", len(scenarios))

	san, err := sanitizer.New(sanitizer.Config{RedactMode: "block"})
	if err != nil {
		t.Fatalf("failed to create sanitizer: %v", err)
	}

	ctx := context.Background()
	byChannel := make(map[string]*channelStats)
	var totalWithPHI, totalClean int
	var detected, missed, falsePositives int
	var missedIDs, fpIDs []string

	for _, sc := range scenarios {
		result, err := san.Scan(ctx, sc.Text)
		if err != nil {
			t.Errorf("scan error for %s: %v", sc.ID, err)
			continue
		}

		if sc.ExpectedDetected {
			totalWithPHI++
			if result.PHIDetected {
				detected++
			} else {
				missed++
				missedIDs = append(missedIDs, sc.ID)
				t.Logf("MISSED: %s channels=%v phi_types=%v", sc.ID, sc.Channels, sc.PHITypes)
			}

			for _, ch := range sc.Channels {
				if byChannel[ch] == nil {
					byChannel[ch] = &channelStats{}
				}
				byChannel[ch].Total++
				if result.PHIDetected {
					byChannel[ch].Detected++
				} else {
					byChannel[ch].Missed++
				}
			}
		} else {
			totalClean++
			if result.PHIDetected {
				falsePositives++
				fpIDs = append(fpIDs, sc.ID)
				t.Logf("FALSE POSITIVE: %s", sc.ID)
			}
		}
	}

	leakRate := 0.0
	detectionRate := 0.0
	if totalWithPHI > 0 {
		leakRate = float64(missed) / float64(totalWithPHI)
		detectionRate = float64(detected) / float64(totalWithPHI)
	}

	results := phiLeakResults{
		TotalScenarios:   len(scenarios),
		WithPHI:          totalWithPHI,
		Clean:            totalClean,
		OverallDetected:  detected,
		OverallMissed:    missed,
		LeakRate:         leakRate,
		DetectionRate:    detectionRate,
		ByChannel:        make(map[string]channelResult),
		FalsePositives:   falsePositives,
		FalsePositiveIDs: fpIDs,
		MissedIDs:        missedIDs,
		TargetMet:        leakRate < 0.01,
	}

	for ch, stats := range byChannel {
		dr := 0.0
		if stats.Total > 0 {
			dr = float64(stats.Detected) / float64(stats.Total)
		}
		results.ByChannel[ch] = channelResult{
			Total:         stats.Total,
			Detected:      stats.Detected,
			Missed:        stats.Missed,
			DetectionRate: dr,
		}
	}

	// Print summary
	t.Logf("\n" + fmt.Sprintf("═══ PHI LEAK EVALUATION ═══"))
	t.Logf("Total scenarios: %d (with PHI: %d, clean: %d)", len(scenarios), totalWithPHI, totalClean)
	t.Logf("Detection rate:  %.2f%% (%d/%d)", detectionRate*100, detected, totalWithPHI)
	t.Logf("Leak rate:       %.2f%% (%d/%d)  target: < 1%%", leakRate*100, missed, totalWithPHI)
	t.Logf("False positives: %d/%d", falsePositives, totalClean)

	t.Logf("\nPer-channel detection rates:")
	for ch, cr := range results.ByChannel {
		t.Logf("  %-15s %5.1f%% (%d/%d)", ch, cr.DetectionRate*100, cr.Detected, cr.Total)
	}

	// Write results
	resultsDir := filepath.Join(root, "ml", "eval", "results")
	os.MkdirAll(resultsDir, 0o755)
	outPath := filepath.Join(resultsDir, "l3_phi_leak.json")
	outData, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(outPath, outData, 0o644); err != nil {
		t.Errorf("failed to write results: %v", err)
	}
	t.Logf("Results written to %s", outPath)

	if leakRate >= 0.01 {
		t.Errorf("PHI leak rate %.4f >= 0.01 target", leakRate)
	}
}

func TestPHIRedaction(t *testing.T) {
	san, err := sanitizer.New(sanitizer.Config{RedactMode: "redact"})
	if err != nil {
		t.Fatalf("failed to create sanitizer: %v", err)
	}

	ctx := context.Background()

	cases := []struct {
		name     string
		input    string
		wantPHI  bool
		checkStr string
	}{
		{
			name:    "SSN redacted",
			input:   "Patient SSN is 123-45-6789.",
			wantPHI: true,
		},
		{
			name:    "Phone redacted",
			input:   "Call (555) 123-4567 for results.",
			wantPHI: true,
		},
		{
			name:     "Clean text unchanged",
			input:    "The patient should take ibuprofen 400mg.",
			wantPHI:  false,
			checkStr: "ibuprofen 400mg",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redacted, result, _, err := san.ScanAndRedact(ctx, tc.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.PHIDetected != tc.wantPHI {
				t.Errorf("PHIDetected=%v, want %v", result.PHIDetected, tc.wantPHI)
			}
			if tc.wantPHI && redacted == tc.input {
				t.Errorf("expected redaction but text unchanged")
			}
			if tc.checkStr != "" && redacted != tc.input {
				t.Errorf("clean text was modified: %q", redacted)
			}
		})
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
