# Getting Started

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.22+ | [go.dev/doc/install](https://go.dev/doc/install) |
| Python | 3.11+ | [python.org](https://www.python.org/downloads/) |
| Docker | 24+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Make | Any | Pre-installed on macOS/Linux |
| ONNX Runtime | 1.17+ | Installed via `ml/requirements.txt` |

## Setup

### 1. Clone and Install

```bash
git clone https://github.com/YOUR_ORG/aegis.git
cd aegis

# Go dependencies
go mod download

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r ml/requirements.txt

# Pre-commit hooks
make setup-hooks
```

### 2. Download Datasets

```bash
# Download all public datasets (Tensor Trust, HackAPrompt, MedQA, PubMedQA)
make download-data

# MIMIC-III requires separate credentials
# 1. Register at https://physionet.org/
# 2. Complete CITI training
# 3. Request access to MIMIC-III
# 4. Set PHYSIONET_USER and PHYSIONET_PASS env vars
# 5. Run:
make download-mimic
```

### 3. Verify

```bash
# Run all tests
make test

# Run Go tests only
make test-go

# Run Python tests only  
make test-py

# Lint everything
make lint
```

### 4. Run the Proxy (Dev Mode)

```bash
# Requires a trained classifier model in ml/models/
# For first-time setup without a model, use the mock classifier:
AEGIS_CLASSIFIER_MODE=mock make run-dev

# The proxy starts on :8080
# Health check: curl http://localhost:8080/healthz
```

## Project Map

If you're working on **ML/classifier training:** Start in `ml/` and `scripts/data/`.
If you're working on **Go proxy code:** Start in `cmd/aegis/` and `internal/`.
If you're working on **evaluation:** Start in `ml/eval/` and `test/adversarial/`.
If you're working on **documentation:** Start in `docs/`.

## Key Files to Read First

1. [README.md](../README.md) — Project overview
2. [docs/architecture/system-architecture.md](architecture/system-architecture.md) — How the system works
3. [docs/design/threat-model.md](design/threat-model.md) — What we're defending against
4. [docs/analysis/research-plan.md](analysis/research-plan.md) — What experiments we're running
5. [docs/ROADMAP.md](ROADMAP.md) — What's due when
6. [docs/guides/coding-standards.md](guides/coding-standards.md) — How to write code for this project
