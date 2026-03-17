package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/espirado/aegis/internal/sanitizer"
)

type latencyResults struct {
	L3Scan    latencyBucket `json:"l3_scan"`
	L3Redact  latencyBucket `json:"l3_redact"`
	Timestamp string        `json:"timestamp"`
}

type latencyBucket struct {
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
	P99Ms    float64 `json:"p99_ms"`
	MeanMs   float64 `json:"mean_ms"`
	MinMs    float64 `json:"min_ms"`
	MaxMs    float64 `json:"max_ms"`
	StdMs    float64 `json:"std_ms"`
	Samples  int     `json:"samples"`
}

func computeBucket(latencies []float64) latencyBucket {
	if len(latencies) == 0 {
		return latencyBucket{}
	}
	sort.Float64s(latencies)

	sum := 0.0
	for _, v := range latencies {
		sum += v
	}
	m := sum / float64(len(latencies))

	variance := 0.0
	for _, v := range latencies {
		variance += (v - m) * (v - m)
	}
	variance /= float64(len(latencies))

	return latencyBucket{
		P50Ms:   pctl(latencies, 50),
		P95Ms:   pctl(latencies, 95),
		P99Ms:   pctl(latencies, 99),
		MeanMs:  m,
		MinMs:   latencies[0],
		MaxMs:   latencies[len(latencies)-1],
		StdMs:   math.Sqrt(variance),
		Samples: len(latencies),
	}
}

func pctl(sorted []float64, p float64) float64 {
	idx := p / 100 * float64(len(sorted)-1)
	lower := int(idx)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// TestLatencyBenchmark measures per-layer latency for the sanitizer (L3).
// L1 (classifier) and L2 (auditor) require ONNX runtime / Ollama respectively,
// so they are benchmarked via the respective eval tests. This focuses on L3.
func TestLatencyBenchmark(t *testing.T) {
	root := projectRoot()

	san, err := sanitizer.New(sanitizer.Config{RedactMode: "redact"})
	if err != nil {
		t.Fatalf("create sanitizer: %v", err)
	}

	// Test inputs of varying complexity
	inputs := []struct {
		name string
		text string
	}{
		{"clean_short", "The patient should take ibuprofen 400mg every 6 hours."},
		{"clean_long", "Hypertension is a chronic condition characterized by persistently elevated blood pressure. It is a major risk factor for cardiovascular disease, stroke, and kidney disease. Management includes lifestyle modifications such as dietary changes, regular exercise, and pharmacological interventions."},
		{"phi_ssn", "Patient SSN: 123-45-6789. Admitted on 01/15/2024 for evaluation."},
		{"phi_multi", "Contact patient at (555) 123-4567, email john.doe@hospital.com, MRN#12345678."},
		{"phi_url", "View at https://ehr.example.com/patient?ssn=123-45-6789&mrn=MRN12345678"},
		{"phi_base64", "Encoded data: U1NOOiAxMjMtNDUtNjc4OQ=="},
		{"phi_code", "```json\n{\"ssn\": \"123-45-6789\", \"phone\": \"(555)123-4567\"}\n```"},
		{"phi_markdown", "[Patient SSN: 123-45-6789](https://ehr.example.com/records)"},
		{"phi_complex", "Patient record:\nSSN: 123-45-6789\nPhone: (555) 123-4567\nEmail: patient@hospital.com\nDOB: 01/15/1985\nMRN: MRN#12345678\nIP: 192.168.1.100\nView: https://ehr.example.com/patient?id=12345\nEncoded: U1NOOiA5ODctNjUtNDMyMQ=="},
	}

	ctx := context.Background()
	iterations := 100

	var scanLatencies, redactLatencies []float64

	for _, input := range inputs {
		var scanLats, redactLats []float64

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_, _ = san.Scan(ctx, input.text)
			scanLats = append(scanLats, float64(time.Since(start).Microseconds())/1000.0)

			start = time.Now()
			_, _, _, _ = san.ScanAndRedact(ctx, input.text)
			redactLats = append(redactLats, float64(time.Since(start).Microseconds())/1000.0)
		}

		scanBucket := computeBucket(scanLats)
		redactBucket := computeBucket(redactLats)

		t.Logf("%-15s scan: p50=%.3fms p95=%.3fms p99=%.3fms | redact: p50=%.3fms p95=%.3fms p99=%.3fms",
			input.name, scanBucket.P50Ms, scanBucket.P95Ms, scanBucket.P99Ms,
			redactBucket.P50Ms, redactBucket.P95Ms, redactBucket.P99Ms)

		scanLatencies = append(scanLatencies, scanLats...)
		redactLatencies = append(redactLatencies, redactLats...)
	}

	results := latencyResults{
		L3Scan:    computeBucket(scanLatencies),
		L3Redact:  computeBucket(redactLatencies),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	t.Logf("\n═══ L3 LATENCY BENCHMARK ═══")
	t.Logf("Scan:   p50=%.3fms p95=%.3fms p99=%.3fms (n=%d)", results.L3Scan.P50Ms, results.L3Scan.P95Ms, results.L3Scan.P99Ms, results.L3Scan.Samples)
	t.Logf("Redact: p50=%.3fms p95=%.3fms p99=%.3fms (n=%d)", results.L3Redact.P50Ms, results.L3Redact.P95Ms, results.L3Redact.P99Ms, results.L3Redact.Samples)

	resultsDir := filepath.Join(root, "ml", "eval", "results")
	os.MkdirAll(resultsDir, 0o755)
	outPath := filepath.Join(resultsDir, "latency.json")
	outData, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(outPath, outData, 0o644)
	t.Logf("Results written to %s", outPath)
}

// BenchmarkSanitizerScan is a Go benchmark for L3 scan.
func BenchmarkSanitizerScan(b *testing.B) {
	san, err := sanitizer.New(sanitizer.Config{RedactMode: "block"})
	if err != nil {
		b.Fatalf("create sanitizer: %v", err)
	}

	ctx := context.Background()
	input := "Patient SSN: 123-45-6789. Phone: (555) 123-4567. Email: john@hospital.com. MRN: MRN#12345678."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		san.Scan(ctx, input)
	}
}

// BenchmarkSanitizerScanClean benchmarks scanning a clean input (no PHI).
func BenchmarkSanitizerScanClean(b *testing.B) {
	san, err := sanitizer.New(sanitizer.Config{RedactMode: "block"})
	if err != nil {
		b.Fatalf("create sanitizer: %v", err)
	}

	ctx := context.Background()
	input := "The patient should take ibuprofen 400mg every 6 hours as needed for pain management."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		san.Scan(ctx, input)
	}
}

// BenchmarkSanitizerRedact benchmarks scanning + redaction.
func BenchmarkSanitizerRedact(b *testing.B) {
	san, err := sanitizer.New(sanitizer.Config{RedactMode: "redact"})
	if err != nil {
		b.Fatalf("create sanitizer: %v", err)
	}

	ctx := context.Background()
	input := fmt.Sprintf("Patient SSN: 123-45-6789. Phone: (555) 123-4567. Email: john@hospital.com.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		san.ScanAndRedact(ctx, input)
	}
}
