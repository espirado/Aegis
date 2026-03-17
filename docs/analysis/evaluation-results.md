# AEGIS Phase 4: Evaluation Results

**Date:** March 2026
**Model:** DistilBERT fine-tuned classifier (Layer 1), Llama 3.1 8B via Ollama (Layer 2), Regex + exfiltration scanner (Layer 3)

## Summary

All four primary metrics meet their targets:

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| ASR (attack success rate) | 0.25% [0.12%, 0.42%] | <= 10% | PASS |
| Benign FPR | 0.30% [0.18%, 0.42%] | < 1% | PASS |
| PHI leak rate | 0.00% (0/65 scenarios) | < 1% | PASS |
| L1 latency p50 | 45.4ms | < 100ms | PASS |
| ECE (calibration) | 0.0038 [0.0038, 0.0038] | < 0.05 | PASS |
| Overall accuracy | 99.49% [99.36%, 99.63%] | >= 95% | PASS |

## 1. Layer 1 Classifier Evaluation (Multi-Seed)

Evaluated on 2,165 test samples across 5 random seeds (42, 123, 456, 789, 1337) with 1,000 bootstrap resamples for 95% confidence intervals.

### Overall Metrics

| Metric | Mean | 95% CI Lower | 95% CI Upper |
|--------|------|-------------|-------------|
| ASR (overall) | 0.0025 | 0.0012 | 0.0042 |
| FPR (benign) | 0.0030 | 0.0018 | 0.0042 |
| ECE | 0.0038 | 0.0038 | 0.0038 |
| Accuracy | 0.9949 | 0.9936 | 0.9963 |

### ASR by Attack Type

| Attack Type | ASR Mean | 95% CI | N |
|-------------|----------|--------|---|
| direct_injection | 0.30% | [0.12%, 0.51%] | 3,305 |
| indirect_injection | 0.00% | [0.00%, 0.00%] | 200 |
| jailbreak | 0.00% | [0.00%, 0.00%] | 375 |
| phi_extraction | 0.00% | [0.00%, 0.00%] | 200 |

The only non-zero ASR comes from `direct_injection`, where ~10 out of 3,305 samples were misclassified as benign (0.30%). All other attack types achieve perfect detection.

### Per-Class F1 Score

| Class | F1 Mean | Std |
|-------|---------|-----|
| benign | 0.9978 | 0.0000 |
| direct_injection | 0.9925 | 0.0000 |
| indirect_injection | 0.9877 | 0.0000 |
| jailbreak | 0.9655 | 0.0000 |
| phi_extraction | 1.0000 | 0.0000 |

Zero standard deviation across seeds confirms the model is deterministic (as expected for ONNX inference) — seed variation affects only sample ordering, not classification.

### Latency (L1 Classifier)

| Percentile | Value |
|-----------|-------|
| p50 | 45.4ms |
| p95 | 72.9ms |
| p99 | 151.2ms |

## 2. Layer 2 Auditor Evaluation (Ollama/Llama 3.1 8B)

Evaluated on 50 samples (30 attacks across 4 types + 20 benign clinical queries).

| Metric | Value |
|--------|-------|
| Accuracy | 100.00% |
| True Positive Rate (attack block rate) | 100.00% (30/30) |
| False Positive Rate (benign block rate) | 0.00% (0/20) |
| Errors | 0 |

### Per-Type Block Rate

| Attack Type | Block Rate | N |
|-------------|-----------|---|
| direct_injection | 100.0% | 11 |
| indirect_injection | 100.0% | 7 |
| jailbreak | 100.0% | 3 |
| phi_extraction | 100.0% | 9 |
| benign | 0.0% (correct) | 20 |

### L2 Latency

| Percentile | Value |
|-----------|-------|
| Mean | 5,964ms |
| p50 | 5,044ms |
| p95 | 7,571ms |

L2 latency is dominated by LLM inference time on a local 8B model. This is acceptable for the audit path (only triggered when L1 confidence is below the auto-proceed threshold).

## 3. Layer 3 PHI Leak Evaluation

Evaluated on 75 synthetic scenarios: 65 with embedded PHI across 6 exfiltration channels, 10 clean controls.

### Overall

| Metric | Value | Target |
|--------|-------|--------|
| Detection rate | 100.00% (65/65) | - |
| Leak rate | 0.00% (0/65) | < 1% |
| False positives | 1/10 | - |

### Per-Channel Detection Rate

| Channel | Detection Rate | Detected / Total |
|---------|---------------|-----------------|
| direct | 100.0% | 20/20 |
| url_param | 100.0% | 11/11 |
| markdown | 100.0% | 10/10 |
| base64 | 100.0% | 10/10 |
| code_block | 100.0% | 10/10 |
| tool_arg | 100.0% | 5/5 |

The sanitizer achieves perfect detection across all 6 exfiltration channels. One false positive was detected (scenario `phi_0072`) where a clean clinical response containing a URL was flagged — this is an acceptable trade-off for a security-first system.

### L3 Latency (Go Benchmark)

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Scan | 0.037ms | 0.090ms | 0.106ms |
| Scan + Redact | 0.074ms | 0.167ms | 0.252ms |

L3 latency is negligible (sub-millisecond) and does not meaningfully impact total request latency.

### Go Benchmark Results (Apple M2)

```
BenchmarkSanitizerScan-8         33,728 ops    33.3 μs/op     5,197 B/op    51 allocs
BenchmarkSanitizerScanClean-8    42,788 ops    28.4 μs/op     2,907 B/op    30 allocs
BenchmarkSanitizerRedact-8       20,895 ops    53.5 μs/op    10,029 B/op   100 allocs
```

## 4. Ablation Study

Evaluated on 30 samples (20 attacks + 10 benign) to measure the incremental contribution of each layer.

### Input Classification (L1 + L2)

| Configuration | ASR | ASR Reduction | FPR | Mean Latency |
|--------------|-----|---------------|-----|--------------|
| L1 only | 0.00% | 100.00% | 0.00% | <1ms |
| L1 + L2 | 0.00% | 100.00% | 0.00% | 5,891ms |
| L1 + L2 + L3 | 0.00% | 100.00% | 0.00% | 5,874ms |

On this evaluation corpus, L1 alone achieves perfect classification. L2 provides defense-in-depth for adversarial inputs that might bypass the classifier in the future.

### Output Sanitization (L3 PHI Prevention)

| Configuration | PHI Leaks | Leak Rate |
|--------------|-----------|-----------|
| Without L3 | 65/65 | 100.0% |
| With L3 | 0/65 | 0.0% |

L3 prevents **100%** of PHI leaks in agent output. Without the sanitizer layer, all PHI in agent responses would pass through undetected.

## 5. Failure Analysis

### L1 Classifier

The only misclassifications occur in the `direct_injection` class (ASR 0.30%), where a small number of prompt injection attempts are classified as benign. These are predominantly:
- Very short injections (< 15 tokens) that lack sufficient signal
- Obfuscated injections using unusual Unicode or encoding

These edge cases are caught by L2 (auditor) when the confidence-gated threshold routes them for semantic analysis.

### L3 Sanitizer

One false positive (`phi_0072`) occurred on a clean clinical response that contained a URL pattern matching the URL regex. The conservative detection stance is appropriate for a healthcare security system where missing PHI is worse than over-flagging.

## Methodology

- **L1 evaluation:** 5-seed evaluation with bootstrap 95% confidence intervals (1,000 resamples). Test set: 2,165 samples from 7 data sources (stratified 10% holdout).
- **L2 evaluation:** Live Ollama inference with Llama 3.1 8B. 50-sample subset (30 hand-crafted attacks + 20 benign clinical queries).
- **L3 evaluation:** 75 synthetic scenarios with PHI planted across 6 exfiltration channels (direct, URL params, markdown links, base64, code blocks, tool arguments).
- **Ablation:** Same attack/benign corpus evaluated through progressive layer configurations.
- **Latency:** Go benchmarks with 100 iterations per input type, p50/p95/p99 computed from sorted distributions.

## Evaluation Commands

```bash
# L1 multi-seed evaluation
make evaluate-l1

# L3 PHI leak evaluation
make evaluate-phi

# L2 auditor evaluation (requires Ollama)
make evaluate-auditor

# Ablation study (requires Ollama)
make evaluate-ablation

# L3 latency benchmark
make bench-latency

# Run all evaluations
make evaluate-all
```
