# AEGIS Research & Analysis Plan

## Research Questions

### RQ1: Input Classification Effectiveness
**Can a lightweight ONNX classifier reliably distinguish adversarial prompts from legitimate clinical queries?**

- Metric: F1 score per class (benign, direct injection, indirect injection, jailbreak, PHI extraction)
- Target: ≥ 0.95 F1 on benign class (false positive < 1%), ≥ 0.90 F1 on attack classes
- Baseline: No classifier (100% attack success rate)
- Ablation: Compare ONNX classifier vs. regex-only vs. embedding similarity

### RQ2: Layered Defense Effectiveness
**Does the three-layer architecture reduce attack success rate by ≥ 90% compared to single-layer defenses?**

- Metric: Attack success rate (ASR) = attacks that bypass all layers / total attack attempts
- Target: ASR ≤ 10% (90% reduction from no-defense baseline)
- Comparison: L1 only, L1+L2, L1+L2+L3 (progressive ablation)
- Dataset: Tensor Trust + HackAPrompt + custom healthcare red-team

### RQ3: PHI Leak Prevention
**Does Layer 3 catch ≥ 95% of PHI exfiltration attempts, including indirect channels?**

- Metric: PHI leak rate = undetected PHI exposures / total PHI-containing scenarios
- Target: ≤ 5% leak rate
- Channels tested: direct output, URL params, markdown links, tool args, base64 encoding, code blocks
- Dataset: MIMIC-III synthetic scenarios + SENTINEL PHI benchmark subset

### RQ4: False Positive Impact
**Does AEGIS maintain < 1% false positive rate on legitimate clinical queries?**

- Metric: FPR = legitimate queries blocked or held / total legitimate queries
- Target: < 1%
- Dataset: MedQA (12,723 questions) + PubMedQA (1,000 expert-annotated)
- Critical because: false positives = delayed patient care

### RQ5: Latency Budget
**Does the full three-layer pipeline stay within sub-100ms p50 overhead?**

- Metric: p50, p95, p99 latency overhead (AEGIS path minus direct-to-agent path)
- Target: < 100ms p50, < 200ms p95
- Measurement: End-to-end proxy latency instrumented with Prometheus histograms
- Note: L2 auditor is only invoked on flagged inputs, so amortized overhead is lower

### RQ6: Auditor Hardening
**Is the hardened L2 auditor resistant to attacks that fool the primary agent?**

- Metric: Auditor bypass rate = attacks that fool both L1+agent AND L2 / attacks that fool L1+agent
- Target: < 5% dual bypass rate
- Method: Adversarial examples specifically crafted to fool layered defenses

---

## Experiment Plan

### Phase 1: Classifier Training (Weeks 1–3)

| Step | Task | Output |
|------|------|--------|
| 1.1 | Download and preprocess Tensor Trust, HackAPrompt, MedQA, PubMedQA | `data/processed/` splits |
| 1.2 | Generate healthcare-specific adversarial examples via red-teaming | `data/processed/healthcare_adversarial.jsonl` |
| 1.3 | Train classifier (DistilBERT → ONNX export) | `ml/models/classifier_v1.onnx` |
| 1.4 | Calibrate confidence thresholds on validation set | Threshold config in `configs/` |
| 1.5 | Evaluate FPR on MedQA + PubMedQA holdout | FPR report |

### Phase 2: PHI Detection Pipeline (Weeks 2–4)

| Step | Task | Output |
|------|------|--------|
| 2.1 | Download MIMIC-III (requires PhysioNet credentials) | `data/raw/mimic-iii/` |
| 2.2 | Train clinical NER model on MIMIC-III de-id annotations | `ml/models/phi_ner_v1.onnx` |
| 2.3 | Implement regex patterns for 18 HIPAA identifiers | `pkg/phi/patterns.go` |
| 2.4 | Build indirect exfiltration detector (URL, markdown, tool args) | `internal/sanitizer/exfiltration.go` |
| 2.5 | Evaluate on synthetic PHI scenarios | PHI leak rate report |

### Phase 3: Proxy Integration (Weeks 3–5)

| Step | Task | Output |
|------|------|--------|
| 3.1 | Build Go proxy skeleton with Layer 1 ONNX inference | Working L1 proxy |
| 3.2 | Integrate Layer 2 LLM auditor (API-based) | L1 + L2 proxy |
| 3.3 | Integrate Layer 3 output sanitizer | Full three-layer proxy |
| 3.4 | Implement confidence-gated routing + hold-and-notify | Complete decision engine |
| 3.5 | Add structured audit logging + Prometheus metrics | Observable proxy |

### Phase 4: Evaluation (Weeks 5–7)

| Step | Task | Output |
|------|------|--------|
| 4.1 | Run full attack corpus through three-layer pipeline | ASR results |
| 4.2 | Run MedQA + PubMedQA through pipeline | FPR results |
| 4.3 | Run PHI scenarios through pipeline | PHI leak rate results |
| 4.4 | Latency benchmarking (p50/p95/p99) | Latency report |
| 4.5 | Ablation study: L1 only → L1+L2 → L1+L2+L3 | Layer contribution analysis |
| 4.6 | Auditor hardening evaluation | Dual bypass rate |

### Phase 5: Paper Writing (Weeks 6–8)

| Step | Task | Output |
|------|------|--------|
| 5.1 | Draft results tables and figures | `docs/analysis/results/` |
| 5.2 | Write paper sections | Paper draft |
| 5.3 | Internal review + revisions | Final draft |

---

## Analysis Procedures

### Classifier Performance Analysis
```
For each class c in {benign, direct, indirect, jailbreak, phi_extract}:
    Compute: precision(c), recall(c), F1(c)
    Compute: confusion matrix
    Compute: calibration curve (reliability diagram)
    Compute: ECE (expected calibration error)
    
Report: macro F1, per-class F1, FPR on benign class
```

### Attack Success Rate Analysis
```
For each attack_type in {tensor_trust, hackaprompt, custom_healthcare}:
    For each defense_config in {none, L1_only, L1_L2, L1_L2_L3}:
        ASR = count(attack_succeeded) / count(total_attacks)
    
Report: ASR per attack_type × defense_config matrix
Report: ASR reduction = (ASR_none - ASR_full) / ASR_none
```

### PHI Leak Rate Analysis
```
For each channel in {direct, url_param, markdown, tool_arg, base64, code_block}:
    leak_rate = count(undetected_phi) / count(total_phi_scenarios)
    
Report: per-channel leak rate, aggregate leak rate
Report: breakdown by HIPAA identifier type
```

### Latency Analysis
```
For each request in benchmark_corpus:
    baseline_latency = direct_to_agent_time
    aegis_latency = proxy_to_agent_to_proxy_time
    overhead = aegis_latency - baseline_latency
    
Report: p50, p95, p99 overhead
Report: overhead breakdown by layer (L1, L2, L3)
Report: amortized overhead (weighted by L2 invocation rate)
```

### Calibration Analysis
```
For the L1 classifier:
    Bin predictions by confidence
    Compute ECE = Σ (|bin_accuracy - bin_confidence|) × bin_weight
    Plot reliability diagram
    Compare: before/after Platt scaling or temperature scaling
    
Critical because: confidence thresholds gate real decisions
```

---

## Statistical Rigor

- All experiments run with **5 random seeds**, report mean ± std
- Significance testing: McNemar's test for classifier comparisons
- Confidence intervals: Bootstrap 95% CI for all primary metrics
- Effect sizes: Cohen's d for latency comparisons
- Multiple comparison correction: Bonferroni for per-class metrics
