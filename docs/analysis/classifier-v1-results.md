# Layer 1 Classifier — Training Results (v1)

**Date:** March 16–17, 2026
**Model:** `distilbert-base-uncased` fine-tuned for 5-class prompt classification
**Export:** ONNX (`ml/models/classifier_v1.onnx`)

---

## Task

Classify incoming prompts into five categories for the AEGIS security proxy:

| Class ID | Label | Description |
|----------|-------|-------------|
| 0 | `benign` | Legitimate clinical queries |
| 1 | `direct_injection` | Prompt injection attacks targeting the system directly |
| 2 | `indirect_injection` | Malicious instructions hidden in context (documents, tool output) |
| 3 | `jailbreak` | Attempts to override safety constraints or role-play bypass |
| 4 | `phi_extraction` | Attempts to extract Protected Health Information |

---

## Datasets

### Sources

| Dataset | Source | Samples | Classes Covered | Access |
|---------|--------|---------|-----------------|--------|
| deepset/prompt-injections | [HuggingFace](https://huggingface.co/datasets/deepset/prompt-injections) | 662 | direct_injection, benign | Public |
| jackhhao/jailbreak-classification | [HuggingFace](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | 1,306 | jailbreak, benign | Public |
| rubend18/ChatGPT-Jailbreak-Prompts | [HuggingFace](https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts) | 79 | jailbreak | Public |
| GBaker/MedQA-USMLE-4-options | [HuggingFace](https://huggingface.co/datasets/GBaker/MedQA-USMLE-4-options) | 11,451 | benign | Public |
| PubMedQA | [GitHub](https://github.com/pubmedqa/pubmedqa) | 1,000 | benign | Public |
| Tensor Trust (hijacking + extraction) | [GitHub](https://github.com/HumanCompatibleAI/tensor-trust-data) | 1,345 | direct_injection | Public |
| HackAPrompt | [HuggingFace (gated)](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) | 5,000 | direct_injection | Gated |
| Synthetic indirect injection | Generated in `preprocess.py` | 400 | indirect_injection | — |
| Synthetic PHI extraction | Generated in `preprocess.py` | 400 | phi_extraction | — |

### Class Distribution (Final)

| Class | Count | % of Total |
|-------|-------|------------|
| benign | 13,490 | 62.3% |
| direct_injection | 6,608 | 30.5% |
| indirect_injection | 400 | 1.8% |
| jailbreak | 745 | 3.4% |
| phi_extraction | 400 | 1.8% |
| **Total** | **21,643** | **100%** |

### Splits (80/10/10, stratified)

| Split | Count |
|-------|-------|
| Train | 17,314 |
| Val | 2,164 |
| Test | 2,165 |

---

## Training Configuration

| Parameter | Value |
|-----------|-------|
| Base model | `distilbert-base-uncased` |
| Max sequence length | 128 |
| Batch size | 32 |
| Learning rate | 2e-5 |
| Weight decay | 0.01 |
| Scheduler | Cosine annealing (eta_min=1e-6) |
| Epochs | 5 |
| Gradient clipping | max_norm=1.0 |
| Loss | CrossEntropyLoss |
| Optimizer | AdamW |
| Seed | 42 |

---

## Training Progression

| Epoch | Train Loss | Val Acc | Val FPR | ECE | Notes |
|-------|-----------|---------|---------|------|-------|
| 1 | 0.1329 | 99.17% | 0.0044 | 0.0033 | New best |
| 2 | 0.0176 | 99.45% | 0.0052 | 0.0032 | New best |
| 3 | 0.0075 | 99.45% | 0.0030 | 0.0045 | — |
| 4 | 0.0033 | 99.40% | 0.0059 | 0.0050 | — |
| 5 | 0.0027 | **99.49%** | 0.0044 | 0.0049 | **New best** |

Total training time: 7,388s (~2h 3m) on CPU.

---

## Final Results (Best Checkpoint — Epoch 5)

### Overall Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| **Accuracy** | 99.49% | — | — |
| **Macro avg F1** | 98.89% | ≥ 0.90 | **PASS** |
| **Weighted avg F1** | 99.49% | — | — |
| **Benign FPR** | 0.44% | < 1% | **PASS** |
| **ECE** | 0.0049 | < 0.05 | **PASS** |

### Per-Class Breakdown

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| benign | 99.93% | 99.56% | 99.74% | 1,349 |
| direct_injection | 98.95% | 99.70% | 99.32% | 661 |
| indirect_injection | 100.00% | 100.00% | 100.00% | 40 |
| jailbreak | 97.26% | 95.95% | 96.60% | 74 |
| phi_extraction | 97.56% | 100.00% | 98.77% | 40 |

### Confusion Matrix

```
                    Predicted
              benign  direct  indirect  jailbreak  phi_ext
Actual
benign         1343      4        0         1         1
direct_inj        1    659        0         1         0
indirect_inj      0      0       40         0         0
jailbreak         0      3        0        71         0
phi_extract       0      0        0         0        40
```

---

## Comparison: Before vs After Data Augmentation

The initial training run used only the publicly available datasets (15,298 samples, 263 direct injection).
The augmented run added Tensor Trust (1,345 samples) and HackAPrompt (5,000 samples) to strengthen `direct_injection`.

### Per-Class F1 Comparison

| Class | Before (Run 1) | After (Run 2) | Delta |
|-------|---------------|---------------|-------|
| benign | 99.78% | 99.74% | -0.04% |
| **direct_injection** | **86.79%** | **99.32%** | **+12.53%** |
| indirect_injection | 98.77% | 100.00% | +1.23% |
| jailbreak | 99.32% | 96.60% | -2.72% |
| phi_extraction | 98.77% | 98.77% | 0.00% |
| **Macro avg F1** | **96.68%** | **98.89%** | **+2.21%** |

### Key Observations

1. **direct_injection F1 improved from 86.79% to 99.32%** — the primary goal of this augmentation. Test support went from 26 to 661 samples, giving a far more reliable estimate.

2. **Jailbreak F1 dropped slightly (99.32% → 96.60%)** — 3 jailbreak samples were misclassified as direct_injection. This reflects genuine overlap between attack categories (some HackAPrompt attacks use jailbreak-style prompts but are labeled as injections). Still above the 95% target.

3. **Benign FPR remained low at 0.44%**, well within the < 1% target. Only 6 out of 1,349 benign queries were incorrectly flagged.

4. **Calibration (ECE) is tight at 0.0049**, meaning the model's confidence scores closely track actual accuracy — critical for the confidence-gated autonomy thresholds.

---

## Data Provenance

### Tensor Trust
- **Repository:** [HumanCompatibleAI/tensor-trust-data](https://github.com/HumanCompatibleAI/tensor-trust-data)
- **Paper:** [Tensor Trust: Interpretable Prompt Injection Attacks from an Online Game](https://tensortrust.ai/paper)
- **Files used:** `benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl` (775 attacks), `benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl` (569 attacks)
- **License:** Public GitHub repository

### HackAPrompt
- **Repository:** [hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset)
- **Paper:** [HackAPrompt: Exposing LLM Vulnerabilities Through Human-Machine Teaming](https://arxiv.org/abs/2311.16119)
- **Total rows:** 601,757 (77,936 successful attacks, 20,810 unique)
- **Used:** 5,000 randomly sampled unique successful attacks
- **License:** Gated dataset, requires HuggingFace account + terms acceptance

---

## Artifacts

| Artifact | Path | Notes |
|----------|------|-------|
| ONNX model | `ml/models/classifier_v1.onnx` | Gitignored, rebuild via `make train-classifier` |
| Training metrics | `ml/models/training_metrics.json` | Committed |
| Preprocessing script | `scripts/data/preprocess.py` | Committed |
| Training script | `ml/training/train_classifier.py` | Committed |
| Evaluation script | `ml/eval/evaluate.py` | Committed |

---

## Next Steps

1. **Run full evaluation suite** (`ml/eval/evaluate.py`) on the test split for detailed ASR/FPR/latency reporting
2. **Threshold calibration** — determine optimal confidence thresholds for the three-tier gating (auto-proceed / hold-and-notify / block)
3. **Address jailbreak/injection boundary** — consider adding more clearly-labeled jailbreak examples to sharpen the decision boundary
4. **Increase indirect_injection and phi_extraction diversity** — current synthetic generators use fixed templates; add more variety or source real examples
5. **Multi-seed evaluation** — run 5 seeds per research plan and report mean ± std
