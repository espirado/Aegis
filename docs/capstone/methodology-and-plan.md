# AEGIS: Methodology Design Plan & Week-by-Week Action Plan

**Project:** AEGIS — Adversarial Enforcement and Guardrail Interception System for Healthcare AI Agents
**Team:** Andrew Espira, Umut Baris Basol
**Program:** Capstone: Big Data & Data Science, Saint Peter's University
**Date:** March 2026

---

## 1. Methodology Overview

Our methodology follows a six-step iterative data science lifecycle, adapted for building and evaluating a real-time security system for healthcare AI agents.

```
Step 1                Step 2                Step 3
Project               Data Mining &         Data
Understanding         Processing            Exploration
    │                     │                     │
    ▼                     ▼                     ▼
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Threat  │────────▶│ Dataset │────────▶│ Attack  │
│ Modeling│         │ Curation│         │ Pattern │
│ & Lit   │         │ & Prep  │         │ Analysis│
│ Review  │         │         │         │         │
└─────────┘         └─────────┘         └─────────┘
                                             │
    ┌────────────────────────────────────────┘
    ▼
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Three-  │────────▶│ Evaluate│────────▶│Dashboard│
│ Layer   │         │ & Ablate│         │ & Live  │
│ Defense │         │         │         │ Agents  │
│ System  │         │         │         │         │
└─────────┘         └─────────┘         └─────────┘
    ▲                     ▲                     ▲
Step 4                Step 5                Step 6
Model Building &      Interpret             Deployment &
Training              Results               Integration
```

### Step 1: Project Understanding
- Literature review of prompt injection attacks in healthcare AI (Yoo et al., JAMA 2025; OWASP LLM Top 10)
- Threat modeling: identify attack surfaces for AI agents with tool access and patient data
- Gap analysis: evaluate SENTINEL benchmark findings (52.3% red-tier security probe rate)
- Define research questions (RQ1–RQ6) and target metrics

### Step 2: Data Mining & Processing
- Curate multi-source attack dataset: Tensor Trust (GitHub), HackAPrompt (HuggingFace), deepset/prompt-injections, jailbreak-classification, ChatGPT-Jailbreak-Prompts
- Curate benign clinical dataset: MedQA-USMLE (12,723 questions), PubMedQA (1,000 expert-annotated)
- Generate synthetic indirect injection and PHI extraction samples
- Preprocess into unified JSONL format with stratified 80/10/10 train/val/test splits

### Step 3: Data Exploration
- Exploratory analysis of attack patterns (token-level features, injection techniques)
- Class distribution analysis and data augmentation strategy
- PHI pattern analysis across 18 HIPAA identifiers
- Cross-dataset overlap and generalization assessment

### Step 4: Model Building & Training
- **Layer 1 (Input Classifier):** Fine-tune DistilBERT for 5-class classification, export to ONNX
- **Layer 2 (Semantic Auditor):** Multi-model LLM auditor with hardened system prompt (supports OpenAI, Anthropic, Ollama/Llama)
- **Layer 3 (Output Sanitizer):** Regex-based PHI detection for 18 HIPAA identifiers + indirect exfiltration scanner (6 channels)
- **Proxy Integration:** Go HTTP proxy with confidence-gated routing, audit logging, Prometheus metrics

### Step 5: Interpret Results
- Multi-seed evaluation with bootstrap 95% confidence intervals
- Ablation study: L1 only vs L1+L2 vs L1+L2+L3
- PHI leak rate evaluation across 6 exfiltration channels
- Latency benchmarking: per-layer p50/p95/p99
- Statistical rigor: 5 seeds, 1,000 bootstrap resamples, McNemar's test

### Step 6: Deployment & Integration
- Build live monitoring dashboard (real-time metrics, decision feed, PHI detection heatmap)
- Integrate with SENTINEL MCP tools for live agent reasoning audit
- Connect to existing AI agents via agentgateway for end-to-end testing
- Production hardening and performance optimization

---

## 2. Job Delegation

| Area | Andrew Espira | Umut Baris Basol |
|------|:---:|:---:|
| **Literature review & threat modeling** | Lead | Review |
| **Dataset curation & preprocessing** | Lead | Support |
| **Classifier training (DistilBERT/ONNX)** | Lead | Review |
| **Go proxy implementation** | Lead | Review |
| **L2 auditor (multi-model LLM)** | Lead | Support |
| **L3 sanitizer (PHI detection)** | Lead | Support |
| **Evaluation harness (Python)** | Lead | Support |
| **Evaluation harness (Go tests)** | Lead | Review |
| **Dashboard development** | Support | Lead |
| **SENTINEL/MCP integration** | Support | Lead |
| **Live agent testing & validation** | Shared | Shared |
| **Statistical analysis & visualization** | Support | Lead |
| **Paper writing — Introduction & Related Work** | Lead | Review |
| **Paper writing — Methodology** | Lead | Review |
| **Paper writing — Results & Discussion** | Shared | Shared |
| **Paper writing — Figures & Tables** | Support | Lead |
| **Presentation preparation** | Shared | Shared |

---

## 3. Week-by-Week Action Plan

### Week 3 (March 10–16) — COMPLETED

**Theme: Foundation & Classifier Training**

| Task | Owner | Status |
|------|-------|--------|
| Repository setup, CI, linting, project structure | Andrew | DONE |
| Download and curate 7 datasets (Tensor Trust, HackAPrompt, deepset, MedQA, PubMedQA, jailbreak-classification, ChatGPT-Jailbreak-Prompts) | Andrew | DONE |
| Data preprocessing pipeline (`scripts/data/preprocess.py`) | Andrew | DONE |
| Train DistilBERT 5-class classifier on 21,643 samples | Andrew | DONE |
| Export classifier to ONNX (`ml/models/classifier_v1.onnx`) | Andrew | DONE |
| Data augmentation: +25x direct injection samples → F1 from 86.79% to 99.32% | Andrew | DONE |
| Document classifier-v1 results (`docs/analysis/classifier-v1-results.md`) | Andrew | DONE |
| Literature review: prompt injection in healthcare AI | Umut | DONE |

**Deliverables:** classifier_v1.onnx (99.49% accuracy, 98.89% macro F1, 0.44% FPR, 0.0049 ECE)

---

### Week 4 (March 17–23) — COMPLETED

**Theme: Three-Layer Proxy Implementation**

| Task | Owner | Status |
|------|-------|--------|
| Go proxy skeleton with chi router, config loading, graceful shutdown | Andrew | DONE |
| Pure Go WordPiece tokenizer for ONNX classifier inference | Andrew | DONE |
| L1 classifier integration (ONNX Runtime in Go) | Andrew | DONE |
| L2 auditor with LLMProvider interface (OpenAI, Anthropic, Ollama) | Andrew | DONE |
| L3 sanitizer: 18 HIPAA regex patterns + 6-channel exfiltration detector | Andrew | DONE |
| Confidence-gated decision engine (auto-proceed / hold / block) | Andrew | DONE |
| Structured audit logging + Prometheus metrics | Andrew | DONE |
| PHI NER model export (StanfordAIMI/stanford-deidentifier-base → ONNX) | Andrew | DONE |
| Unit tests for all layers (29 tests passing) | Andrew | DONE |
| Review proxy architecture and security design | Umut | DONE |

**Deliverables:** Full three-layer Go proxy, multi-model auditor, PHI sanitizer, 29 unit tests

---

### Week 5 (March 24–30) — COMPLETED

**Theme: Evaluation Suite**

| Task | Owner | Status |
|------|-------|--------|
| Create evaluation test fixtures (210 adversarial + 75 PHI + 111 benign samples) | Andrew | DONE |
| Enhance evaluate.py with multi-seed support + bootstrap 95% CIs | Andrew | DONE |
| Run L1 multi-seed evaluation (5 seeds × 2,165 samples) | Andrew | DONE |
| Build Go PHI leak evaluation harness (6 channels) | Andrew | DONE |
| Build Go L2 auditor evaluation with live Ollama/Llama 3.1 8B | Andrew | DONE |
| Build ablation study framework (L1 → L1+L2 → L1+L2+L3) | Andrew | DONE |
| Build Go latency benchmark (p50/p95/p99) | Andrew | DONE |
| Document evaluation results (`docs/analysis/evaluation-results.md`) | Andrew | DONE |
| Review evaluation methodology and statistical approach | Umut | DONE |

**Deliverables:** All targets met — ASR 0.25%, FPR 0.30%, PHI leak 0%, L1 p50 45.4ms, ECE 0.0038

---

### Week 6 (March 31 – April 6) — IN PROGRESS

**Theme: Dashboard & Monitoring**

| Task | Owner | Status |
|------|-------|--------|
| Design dashboard UI wireframes (decision feed, metrics panels, PHI heatmap) | Umut | TODO |
| Implement real-time monitoring dashboard (connect to Prometheus metrics) | Umut | TODO |
| Dashboard: classification distribution chart (live) | Umut | TODO |
| Dashboard: per-layer latency visualization | Umut | TODO |
| Dashboard: PHI detection heatmap by type and channel | Umut | TODO |
| Dashboard: audit log viewer with filtering | Umut | TODO |
| Connect dashboard to AEGIS proxy metrics endpoint (`:9090/metrics`) | Andrew | TODO |
| Add WebSocket/SSE endpoint for live decision feed | Andrew | TODO |
| Integration test: dashboard + proxy end-to-end | Shared | TODO |

**Deliverables:** Live monitoring dashboard connected to AEGIS proxy

---

### Week 7 (April 7–13)

**Theme: SENTINEL/MCP Integration & Live Agent Testing**

| Task | Owner | Status |
|------|-------|--------|
| Integrate AEGIS proxy with SENTINEL MCP tools | Umut | TODO |
| Connect to agentgateway for MCP client routing | Umut | TODO |
| Configure AEGIS as upstream security layer for SENTINEL | Andrew | TODO |
| Deploy test healthcare AI agent (Ollama-based) | Andrew | TODO |
| Run live agent scenario: benign clinical queries | Shared | TODO |
| Run live agent scenario: adversarial prompts (injection, jailbreak) | Shared | TODO |
| Run live agent scenario: PHI extraction and exfiltration | Shared | TODO |
| Collect live metrics and audit logs from integrated system | Shared | TODO |
| Document integration architecture | Andrew | TODO |

**Deliverables:** AEGIS + SENTINEL integrated, tested with live AI agent

---

### Week 8 (April 14–20)

**Theme: Extended Evaluation & Results Compilation**

| Task | Owner | Status |
|------|-------|--------|
| Run extended evaluation on live agent interactions (100+ scenarios) | Shared | TODO |
| Compute live-agent ASR, FPR, PHI leak rate | Andrew | TODO |
| Latency measurement under realistic load (concurrent requests) | Andrew | TODO |
| Generate publication-ready figures and charts | Umut | TODO |
| Compile all results into final results tables | Umut | TODO |
| Failure case analysis with concrete examples | Andrew | TODO |
| Comparison with baseline (no defense) and single-layer alternatives | Shared | TODO |
| Statistical analysis: McNemar's test, Cohen's d for latency | Umut | TODO |

**Deliverables:** Complete results package with figures, tables, statistical analysis

---

### Week 9 (April 21–27)

**Theme: Paper Draft**

| Task | Owner | Status |
|------|-------|--------|
| Draft: Abstract | Andrew | TODO |
| Draft: Introduction (threat landscape, motivation) | Andrew | TODO |
| Draft: Related Work (prompt injection defenses, PHI protection) | Andrew | TODO |
| Draft: Methodology (three-layer architecture, confidence gating) | Andrew | TODO |
| Draft: Experimental Setup (datasets, metrics, baselines) | Umut | TODO |
| Draft: Results (tables, figures, ablation, statistical tests) | Umut | TODO |
| Draft: Discussion (limitations, failure analysis, future work) | Shared | TODO |
| Draft: Conclusion | Andrew | TODO |
| Internal review round 1 | Shared | TODO |

**Deliverables:** Complete first draft of paper

---

### Week 10 (April 28 – May 4)

**Theme: Paper Polishing**

| Task | Owner | Status |
|------|-------|--------|
| Address review feedback from round 1 | Shared | TODO |
| Polish all figures for camera-ready quality | Umut | TODO |
| Ensure all citations are complete and properly formatted | Umut | TODO |
| Proofread and edit for clarity, grammar, flow | Andrew | TODO |
| Verify all numbers in paper match evaluation JSON results | Shared | TODO |
| Format per submission guidelines | Andrew | TODO |
| Internal review round 2 (final) | Shared | TODO |

**Deliverables:** Polished paper draft

---

### Week 11 (May 5–11)

**Theme: Presentation & Submission**

| Task | Owner | Status |
|------|-------|--------|
| Create presentation slides (15–20 slides) | Shared | TODO |
| Prepare live demo: AEGIS proxy blocking attacks in real-time | Andrew | TODO |
| Prepare live demo: dashboard showing metrics and decisions | Umut | TODO |
| Practice presentation (2 rehearsals) | Shared | TODO |
| Final paper revisions if needed | Andrew | TODO |
| Submit paper | Andrew | TODO |
| Deliver presentation | Shared | TODO |

**Deliverables:** Final paper submitted, presentation delivered

---

## 4. Milestone Summary

| Milestone | Week | Owner | Deliverable | Status |
|-----------|------|-------|-------------|--------|
| M1: Classifier v1 | 3 | Andrew | ONNX model (99.49% acc, 0.44% FPR) | DONE |
| M2: Three-Layer Proxy | 4 | Andrew | Go proxy + 29 unit tests | DONE |
| M3: Evaluation Suite | 5 | Andrew | All 4 metrics meet targets | DONE |
| M4: Dashboard | 6 | Umut | Live monitoring UI | TODO |
| M5: Live Agent Integration | 7 | Shared | AEGIS + SENTINEL + agentgateway | TODO |
| M6: Extended Evaluation | 8 | Shared | Publication-ready results | TODO |
| M7: Paper Draft | 9 | Shared | Complete first draft | TODO |
| M8: Paper Final | 10 | Shared | Polished paper | TODO |
| M9: Presentation | 11 | Shared | Slides + live demo | TODO |

---

## 5. Current Results (as of Week 5)

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Attack success rate | 0.25% [0.12%, 0.42%] | <= 10% | PASS |
| Benign false positive rate | 0.30% [0.18%, 0.42%] | < 1% | PASS |
| PHI leak rate | 0.00% (6 channels, 65 scenarios) | < 1% | PASS |
| L1 classifier latency p50 | 45.4ms | < 100ms | PASS |
| ECE (calibration error) | 0.0038 | < 0.05 | PASS |
| L2 auditor accuracy | 100% (Llama 3.1 8B, 50 samples) | — | PASS |
| L3 sanitizer latency p50 | 0.037ms | — | PASS |
| Overall classifier accuracy | 99.49% [99.36%, 99.63%] | >= 95% | PASS |

---

## 6. Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Proxy & Core Logic | Go 1.22, chi router | HTTP proxy, request routing |
| ML Training | Python, PyTorch, HuggingFace | Classifier fine-tuning |
| Inference | ONNX Runtime (Go bindings) | Sub-100ms classification |
| L2 Auditor | OpenAI / Anthropic / Ollama APIs | Semantic policy enforcement |
| PHI Detection | Go regex + NER | 18 HIPAA identifier detection |
| Monitoring | Prometheus, Grafana | Metrics and alerting |
| Dashboard | HTML/JS (real-time) | Live decision observatory |
| MCP Integration | SENTINEL + agentgateway | Agent governance |
| Evaluation | Python (numpy, sklearn), Go testing | Statistical evaluation |

---

## 7. Dataset Summary

| Dataset | Source | Samples | Use |
|---------|--------|---------|-----|
| Tensor Trust | GitHub (HumanCompatibleAI) | 5,000+ | Direct injection attacks |
| HackAPrompt | HuggingFace (gated) | 5,000 | Competition injection attacks |
| deepset/prompt-injections | HuggingFace | 662 | Injection + benign pairs |
| jackhhao/jailbreak-classification | HuggingFace | 1,000+ | Jailbreak prompts |
| rubend18/ChatGPT-Jailbreak-Prompts | HuggingFace | 78 | Jailbreak templates |
| MedQA-USMLE | HuggingFace (GBaker) | 12,723 | Benign clinical queries |
| PubMedQA | GitHub | 1,000 | Benign biomedical queries |
| Synthetic indirect injection | Generated | 400 | Hidden instruction attacks |
| Synthetic PHI extraction | Generated | 400 | PHI probing prompts |
| **Total** | | **21,643** | Train/val/test (80/10/10) |

---

## 8. Reference Articles

1. Yoo et al. (2025). "Prompt Injection Attacks on Large Language Models in Healthcare." *JAMA Network Open*.
2. OWASP (2025). "OWASP Top 10 for LLM Applications v2.0."
3. Perez & Ribeiro (2022). "Ignore This Title and HackAPrompt." *NeurIPS Workshop*.
4. Greshake et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications." *AISec*.
5. Liu et al. (2024). "Prompt Injection Attack Against LLM-Integrated Applications." *USENIX Security*.
6. Wei et al. (2023). "Jailbroken: How Does LLM Safety Training Fail?" *NeurIPS*.
7. Toyer et al. (2024). "Tensor Trust: Interpretable Prompt Injection Attacks." *ICLR*.
8. Schulhoff et al. (2023). "HackAPrompt: An LLM Prompt Injection Competition." *ACL*.
9. US HHS (2024). "HIPAA Privacy Rule — Safe Harbor De-identification." 45 CFR § 164.514.
10. Johnson et al. (2016). "MIMIC-III: A Freely Accessible Critical Care Database." *Scientific Data*.
