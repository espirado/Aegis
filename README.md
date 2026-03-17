# AEGIS: Adversarial Enforcement and Guardrail Interception System

**Real-time security proxy for healthcare AI agents.**

AEGIS is a three-layer inline proxy that intercepts, classifies, and sanitizes interactions between users and medical AI agents. It detects prompt injection, prevents PHI exfiltration, and enforces HIPAA-aligned security policies—all within a sub-100ms p50 latency budget.

Born from [SENTINEL](https://github.com/YOUR_ORG/sentinel) benchmarks where **52.3% of security probes hit red tier** and agents leaked patient data without hesitation.

---

## Why This Exists

| Metric | Source |
|--------|--------|
| 94.4% prompt injection success rate against medical LLMs | Yoo et al., JAMA Network Open 2025 |
| 259M individuals affected by healthcare data breaches in 2024 | HHS / AHA 2026 |
| 71% of healthcare workers use personal AI accounts without HIPAA protections | Khan et al., 2025 |
| 52.3% security probe red-tier rate in SENTINEL benchmarks | SENTINEL (this project's predecessor) |

Static keyword filters and single-agent wrappers were never designed for agentic AI with tool access, memory, and multi-step reasoning. AEGIS replaces them.

## Architecture

```
┌──────────┐     ┌─────────────────────────────────────────────┐     ┌──────────┐
│          │     │                AEGIS PROXY                   │     │          │
│  User /  │────▶│  L1: Input       L2: Semantic    L3: Output │────▶│    AI    │
│  Client  │◀────│  Classifier      Policy Engine   Sanitizer  │◀────│  Agent   │
│          │     │   (ONNX)          (Hardened LLM)  (NER+Regex)│     │          │
└──────────┘     └──────────────┬────────────────────────────────┘     └──────────┘
                                │
                         ┌──────▼──────┐
                         │  Audit Log  │
                         │  + Metrics  │
                         │  + Alerts   │
                         └─────────────┘
```

**Confidence-Gated Autonomy:**
- `≥ 0.85` → Auto-proceed (logged)
- `0.60 – 0.85` → Hold-and-notify (30s human review window)
- `< 0.60` → Immediate block + escalation
- PHI-touching operations: thresholds × 1.5

See [docs/architecture/](docs/architecture/) for detailed design documents.

## Current Status

**Phase 1 (Classifier Training) — Complete.**
**Phase 2+3 (Three-Layer Proxy) — Complete.**
**Phase 4 (Evaluation) — Complete.** All four primary metrics meet their targets.

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| ASR (attack success rate) | 0.25% [0.12%, 0.42%] | <= 10% | PASS |
| Benign FPR | 0.30% [0.18%, 0.42%] | < 1% | PASS |
| PHI leak rate | 0.00% (65 scenarios, 6 channels) | < 1% | PASS |
| L1 latency p50 | 45.4ms | < 100ms | PASS |
| ECE (calibration) | 0.0038 | < 0.05 | PASS |
| L2 auditor accuracy | 100% (50 samples, Llama 3.1 8B) | — | PASS |
| Overall accuracy | 99.49% [99.36%, 99.63%] | >= 95% | PASS |

Results from 5-seed evaluation with bootstrap 95% CIs (1,000 resamples). See [docs/analysis/evaluation-results.md](docs/analysis/evaluation-results.md) for the full evaluation report and [docs/analysis/classifier-v1-results.md](docs/analysis/classifier-v1-results.md) for the training report.

## Repository Structure

```
aegis/
├── cmd/aegis/              # Go entrypoint
├── internal/               # Go internal packages (proxy, classifier, auditor, sanitizer)
│   ├── proxy/              # HTTP/gRPC proxy + request routing
│   ├── classifier/         # Layer 1: ONNX input classification
│   ├── auditor/            # Layer 2: Hardened LLM policy engine
│   ├── sanitizer/          # Layer 3: NER + regex output scanning
│   ├── config/             # Configuration loading + validation
│   ├── audit/              # Structured audit logging
│   ├── notify/             # Hold-and-notify + escalation
│   └── metrics/            # Prometheus metrics
├── pkg/                    # Shared types and utilities
│   ├── types/              # Core domain types
│   ├── policy/             # Policy rule definitions (HIPAA, OWASP)
│   └── phi/                # PHI detection patterns + 18 HIPAA identifiers
├── ml/                     # Python ML training + evaluation
│   ├── training/           # Classifier training pipeline
│   ├── eval/               # Evaluation scripts (ASR, FPR, latency)
│   ├── models/             # Exported ONNX models (gitignored, downloaded via scripts)
│   └── notebooks/          # Research notebooks
├── scripts/
│   ├── data/               # Dataset download + preprocessing scripts
│   └── setup/              # Environment setup scripts
├── test/                   # Test suites
│   ├── unit/               # Unit tests (Go + Python)
│   ├── integration/        # Integration tests
│   ├── adversarial/        # Red-team test scenarios
│   └── fixtures/           # Test fixtures + SENTINEL benchmark data
├── data/                   # Local data directory (gitignored)
│   ├── raw/                # Downloaded datasets
│   ├── processed/          # Preprocessed datasets
│   └── splits/             # Train/val/test splits
├── configs/                # Configuration files
├── deployments/            # Docker + Kubernetes manifests
├── docs/                   # All project documentation
│   ├── architecture/       # System architecture + design decisions
│   ├── design/             # Detailed component designs
│   ├── analysis/           # Research analysis plans
│   ├── guides/             # Coding standards, contribution guides
│   └── references/         # Papers, links, prior work
└── .github/                # Issue templates, PR templates, CI workflows
```

## Target Metrics

| Metric | Target | How We Measure |
|--------|--------|----------------|
| Attack success rate reduction | ≥ 90% | Tensor Trust + HackAPrompt + custom red-team |
| False positive rate on clinical queries | < 1% | MedQA + PubMedQA benign corpus |
| Latency overhead | < 100ms p50 | End-to-end proxy latency minus baseline |
| PHI leak prevention | ≥ 95% | MIMIC-III synthetic scenarios + SENTINEL PHI corpus |

## Getting Started

```bash
# Clone
git clone https://github.com/espirado/Aegis.git
cd aegis

# Setup environment
make setup

# Download datasets (requires credentials for MIMIC-III)
make download-data

# Run tests
make test

# Start proxy (dev mode)
make run-dev
```

See [docs/guides/getting-started.md](docs/guides/getting-started.md) for full setup instructions.

## Tech Stack

- **Proxy + Core Logic:** Go
- **ML Training + Evaluation:** Python (PyTorch, ONNX, scikit-learn)
- **Inference:** ONNX Runtime (embedded in Go proxy)
- **Observability:** Prometheus, structured JSON logging
- **CI/CD:** GitHub Actions
- **Deployment:** Docker, Kubernetes

## Related Work

- **SENTINEL** — Mid-reasoning interception framework for auditing medical AI clinical logic. AEGIS's predecessor. [Preprint on TechRxiv].
- **Kustode** — Multi-tenant healthcare RCM platform where AEGIS will be deployed in production.

## License

TBD — See [LICENSE](LICENSE) for details.

## Citation

```bibtex
@misc{espira2026aegis,
  title={AEGIS: Adversarial Enforcement and Guardrail Interception System for Healthcare AI Agents},
  author={Espira, Andrew},
  year={2026},
  institution={Saint Peter's University}
}
```
