# AEGIS Work Plan & Roadmap

## Project Phases

```
Phase 1: Foundation        ████████░░░░░░░░░░░░  Weeks 1–3
Phase 2: PHI Pipeline      ░░░░████████░░░░░░░░  Weeks 2–4
Phase 3: Proxy Integration ░░░░░░████████░░░░░░  Weeks 3–5
Phase 4: Evaluation        ░░░░░░░░░░████████░░  Weeks 5–7
Phase 5: Paper             ░░░░░░░░░░░░░░████░░  Weeks 6–8
```

---

## Phase 1: Foundation (Weeks 1–3)

**Owner:** ML lead
**Goal:** Working input classifier with calibrated confidence thresholds.

### Week 1
- [ ] Set up repo, CI, linting, pre-commit hooks
- [ ] Run `scripts/data/download_all.sh` — get Tensor Trust, HackAPrompt, MedQA, PubMedQA
- [ ] Exploratory data analysis on attack datasets (notebook)
- [ ] Define feature extraction pipeline (tokenization, embedding strategy)

### Week 2
- [ ] Train v1 classifier (DistilBERT fine-tune, 5-class)
- [ ] Export to ONNX
- [ ] Evaluate on holdout: per-class F1, confusion matrix
- [ ] Measure FPR on MedQA/PubMedQA — must be < 1%

### Week 3
- [ ] Calibrate confidence thresholds (Platt scaling)
- [ ] Plot reliability diagrams
- [ ] Generate healthcare-specific adversarial examples via red-teaming
- [ ] Retrain on augmented dataset, re-evaluate
- [ ] **Checkpoint:** Classifier v1 with ECE < 0.05 and FPR < 1%

---

## Phase 2: PHI Detection Pipeline (Weeks 2–4)

**Owner:** ML lead + Go lead (parallel with Phase 1)
**Goal:** PHI detection covering all 18 HIPAA identifiers + indirect exfiltration.

### Week 2
- [ ] Apply for MIMIC-III access (if not already credentialed)
- [ ] Implement regex patterns for 18 HIPAA identifiers in Go
- [ ] Unit test regex patterns against known PHI samples

### Week 3
- [ ] Train clinical NER model on MIMIC-III de-identification annotations
- [ ] Export NER model to ONNX
- [ ] Build indirect exfiltration detector: URL params, markdown, tool args, base64

### Week 4
- [ ] Integration test: run NER + regex + exfiltration detector on synthetic scenarios
- [ ] Measure PHI detection rate per channel and per identifier type
- [ ] **Checkpoint:** PHI pipeline catching ≥ 95% of synthetic leaks

---

## Phase 3: Proxy Integration (Weeks 3–5)

**Owner:** Go lead
**Goal:** Working three-layer proxy with confidence-gated routing.

### Week 3
- [ ] Implement Go proxy skeleton (`cmd/aegis/`, `internal/proxy/`)
- [ ] Embed ONNX runtime, load classifier model
- [ ] Wire Layer 1: classify → route (benign forward, flagged → L2)
- [ ] Add request/response logging middleware

### Week 4
- [ ] Implement Layer 2: LLM auditor client (API call to Claude Haiku or equivalent)
- [ ] Build hardened auditor prompt template (no tools, no memory)
- [ ] Implement confidence-gated decision engine
- [ ] Implement hold-and-notify flow (webhook-based alert, 30s timeout)

### Week 5
- [ ] Wire Layer 3: output sanitizer (NER + regex + exfiltration)
- [ ] Add Prometheus metrics: latency histograms, classification counters, escalation rate
- [ ] Structured JSON audit log output
- [ ] End-to-end integration test: attack prompt → block, benign prompt → pass
- [ ] **Checkpoint:** Full proxy passing integration tests

---

## Phase 4: Evaluation (Weeks 5–7)

**Owner:** Both leads
**Goal:** Quantified results for all four primary metrics.

### Week 5
- [ ] Set up evaluation harness: automated test runner with result collection
- [ ] Run attack corpus (Tensor Trust + HackAPrompt + custom) through full pipeline
- [ ] Compute ASR per attack type × defense config (ablation)

### Week 6
- [ ] Run MedQA + PubMedQA through pipeline → FPR measurement
- [ ] Run PHI scenarios through pipeline → leak rate measurement
- [ ] Latency benchmarking: p50/p95/p99, per-layer breakdown
- [ ] Auditor hardening evaluation: dual bypass rate

### Week 7
- [ ] Statistical analysis: bootstrap CIs, significance tests
- [ ] Generate all results tables and figures
- [ ] Identify failure cases, document in `docs/analysis/failure-analysis.md`
- [ ] **Checkpoint:** All four metrics meet targets (or documented why not)

---

## Phase 5: Paper (Weeks 6–8)

**Owner:** Andrew (primary), collaborators review
**Goal:** Submission-ready paper.

### Week 6–7
- [ ] Draft: Introduction, Related Work (adapt from proposal)
- [ ] Draft: Methodology (three-layer architecture)
- [ ] Draft: Experimental Setup (datasets, metrics, baselines)

### Week 7–8
- [ ] Draft: Results + Discussion
- [ ] Generate camera-ready figures
- [ ] Internal review round
- [ ] Revisions
- [ ] **Checkpoint:** Paper ready for submission

---

## Milestone Summary

| Milestone | Week | Deliverable | Go/No-Go Criteria |
|-----------|------|-------------|-------------------|
| M1: Classifier v1 | 3 | ONNX model + calibration report | FPR < 1%, ECE < 0.05 |
| M2: PHI Pipeline | 4 | NER + regex + exfiltration detector | ≥ 95% detection on synthetic |
| M3: Full Proxy | 5 | Three-layer proxy passing integration tests | End-to-end test suite green |
| M4: Evaluation | 7 | Results for all four primary metrics | Targets met or gaps documented |
| M5: Paper | 8 | Submission-ready draft | Internal review approved |

---

## Task Ownership

| Area | Primary Owner | Reviewer |
|------|---------------|----------|
| ML training (classifier, NER) | ML Lead | Andrew |
| Go proxy + Layer 1 inference | Go Lead | Andrew |
| Layer 2 auditor prompt engineering | Andrew | ML Lead |
| Layer 3 sanitizer (Go) | Go Lead | ML Lead |
| Evaluation harness | Both | Andrew |
| Paper writing | Andrew | Both |
| CI/CD + infrastructure | Go Lead | Andrew |

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| MIMIC-III access delayed | Blocks PHI training | Medium | Start with synthetic PHI data, add MIMIC-III when available |
| L2 auditor latency too high | Blows latency budget | Medium | Cache frequent patterns, use smaller model, only invoke on flagged |
| FPR > 1% on clinical queries | Core metric miss | Low | Threshold tuning, MedQA-specific calibration, ensemble |
| Classifier overfits to Tensor Trust distribution | Poor generalization | Medium | Cross-dataset evaluation, healthcare-specific augmentation |
| 77.5% false positive rate from SENTINEL carries over | Undermines credibility | High | Three-layer design specifically targets this — track per-phase |
