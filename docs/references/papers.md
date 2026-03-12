# AEGIS References & Prior Work

## Core Papers

| Paper | Relevance to AEGIS | Key Finding |
|-------|--------------------|-------------|
| Yoo et al. (2025) — JAMA Network Open | Motivating attack data | 94.4% prompt injection success rate against medical LLMs |
| Chen et al. (2025) — arXiv:2504.03759 | Attack taxonomy | Four attack categories: false facts, hijacked recommendations, data theft, malicious links |
| Zhang et al. (2024) — NeurIPS | Knowledge base poisoning | Single-token trigger corrupts 82% of retrievals |
| Toyer et al. (2023) — arXiv:2311.01011 | Training data (Tensor Trust) | Game-based injection attack/defense corpus |
| Kim et al. (2024) — NeurIPS | Clinical baseline (MDAgents) | Adaptive multi-agent collaboration improves accuracy 11.8% |
| Kim et al. (2025a) — arXiv:2506.12482 | Layered oversight design (TAO) | Lower-tier agent removal causes biggest safety drop |
| OWASP Foundation (2025) | Policy framework | Top 10 for LLM Applications + agentic AI threat taxonomy |
| Nagaraja et al. (2025) — SCITEPRESS | Threat modeling | STRIDE mapped to LLM healthcare systems |
| Shah et al. (2024) — arXiv:2411.09523 | Threat taxonomy | Input-driven, model-driven, combined threat classification |
| Dacosta et al. (2024) | Training data (CICIoMT2024) | 18 IoMT attack categories across 40 devices |
| Khan et al. (2025) | Problem motivation | 71% healthcare workers use personal AI without HIPAA protections |
| Adabara et al. (2025) | Architectural patterns | Layered architectures for trustworthy multi-institutional healthcare AI |
| AHA (2026) | Problem motivation | 259M individuals affected by healthcare data breaches in 2024 |

## Datasets

| Dataset | URL | License | Use in AEGIS |
|---------|-----|---------|--------------|
| Tensor Trust | tensortrust.ai/dataset | MIT | L1 classifier training (attack class) |
| HackAPrompt | huggingface.co/datasets/hackaprompt | Apache 2.0 | L1 classifier training (attack class) |
| MedQA | github.com/jind11/MedQA | MIT | FPR evaluation (benign class) |
| PubMedQA | pubmedqa.github.io | MIT | FPR evaluation (benign class) |
| CICIoMT2024 | unb.ca/cic/datasets/iomt-dataset-2024.html | Research | Network-level attack correlation |
| MIMIC-III | physionet.org/content/mimiciii | PhysioNet Credentialed | PHI NER training |

## SENTINEL Benchmark Context

AEGIS builds on empirical findings from the SENTINEL benchmark (150 scenarios):
- **52.3% security probe red-tier rate** — agents fail basic security checks
- **77.5% false positive rate** on red-tier flags — current detection is too noisy
- **PHI leakage red-tier rates: 20–75%** across scenario types
- **Cascading error / failover: 100% red-tier** — agents don't fail safely
- **Sub-100ms latency overhead** proven feasible in SENTINEL's architecture

These findings directly inform AEGIS's three-layer design and target metrics.
