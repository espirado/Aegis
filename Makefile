.PHONY: help setup setup-hooks test test-go test-py lint lint-go lint-py \
       download-data download-mimic preprocess-data \
       train-classifier evaluate evaluate-l1 evaluate-phi evaluate-auditor \
       evaluate-ablation bench-latency evaluate-all \
       run-dev run-proxy run-mock-agent test-live build docker-build clean

# ─────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────
setup: ## Full project setup
	go mod download
	python3 -m venv .venv
	.venv/bin/pip install -r ml/requirements.txt
	@echo "Setup complete. Activate venv: source .venv/bin/activate"

setup-hooks: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	cp .github/hooks/pre-commit .git/hooks/pre-commit 2>/dev/null || true
	chmod +x .git/hooks/pre-commit 2>/dev/null || true

# ─────────────────────────────────────────────────────────
# Testing
# ─────────────────────────────────────────────────────────
test: test-go test-py ## Run all tests

test-go: ## Run Go tests
	go test ./... -v -race -count=1

test-py: ## Run Python tests
	.venv/bin/python -m pytest test/ ml/ -v --tb=short

# ─────────────────────────────────────────────────────────
# Linting
# ─────────────────────────────────────────────────────────
lint: lint-go lint-py ## Run all linters

lint-go: ## Lint Go code
	gofmt -l .
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed"

lint-py: ## Lint Python code
	.venv/bin/ruff check ml/ scripts/ test/
	.venv/bin/mypy ml/ --ignore-missing-imports

# ─────────────────────────────────────────────────────────
# Data
# ─────────────────────────────────────────────────────────
download-data: ## Download public datasets
	chmod +x scripts/data/download_all.sh
	./scripts/data/download_all.sh

download-mimic: ## Download MIMIC-III (requires credentials)
	chmod +x scripts/data/download_mimic.sh
	./scripts/data/download_mimic.sh

preprocess-data: ## Preprocess datasets into unified format
	.venv/bin/python scripts/data/preprocess.py --data-dir data/raw --output-dir data/processed

# ─────────────────────────────────────────────────────────
# ML Training & Evaluation
# ─────────────────────────────────────────────────────────
train-classifier: ## Train Layer 1 classifier
	.venv/bin/python ml/training/train_classifier.py \
		--train-path data/processed/train.jsonl \
		--val-path data/processed/val.jsonl \
		--output-dir ml/models/

evaluate: ## Run single-seed evaluation (quick)
	.venv/bin/python ml/eval/evaluate.py \
		--model-path ml/models/classifier_v1.onnx \
		--test-path data/processed/test.jsonl

evaluate-l1: ## Run L1 multi-seed evaluation with bootstrap CIs
	.venv/bin/python ml/eval/evaluate.py \
		--model-path ml/models/classifier_v1.onnx \
		--test-path data/processed/test.jsonl \
		--seeds 42,123,456,789,1337 \
		--bootstrap-n 1000 \
		--tokenizer-name distilbert-base-uncased

evaluate-phi: ## Run L3 PHI leak rate evaluation
	go test ./ml/eval/ -run "TestPHILeakRate|TestPHIRedaction|TestAblationL3PHIOutput" -v -count=1

evaluate-auditor: ## Run L2 auditor evaluation (requires Ollama)
	go test ./ml/eval/ -run TestAuditorEvalOllama -v -count=1 -timeout 30m

evaluate-ablation: ## Run ablation study (requires Ollama)
	go test ./ml/eval/ -run TestAblationStudy -v -count=1 -timeout 30m

bench-latency: ## Run L3 latency benchmark
	go test ./ml/eval/ -run TestLatencyBenchmark -v -count=1
	go test ./ml/eval/ -run "^$$" -bench "BenchmarkSanitizer" -benchmem -count=3

evaluate-all: evaluate-l1 evaluate-phi evaluate-auditor evaluate-ablation bench-latency ## Run all evaluations

# ─────────────────────────────────────────────────────────
# Build & Run
# ─────────────────────────────────────────────────────────
build: ## Build AEGIS proxy binary
	go build -o bin/aegis ./cmd/aegis/

run-dev: ## Run proxy in development mode
	go run ./cmd/aegis/

run-proxy: ## Run AEGIS proxy (auto-detects ORT lib)
	AEGIS_ORT_LIB_PATH=$$(find /opt/homebrew/lib /usr/local/lib -name 'libonnxruntime.dylib' 2>/dev/null | head -1) \
		go run ./cmd/aegis/

run-mock-agent: ## Run mock healthcare agent on :9000 (needs Ollama)
	go run ./cmd/mock-agent/

test-live: ## Run live smoke tests against running proxy
	@chmod +x scripts/test_live.sh
	@./scripts/test_live.sh

docker-build: ## Build Docker image
	docker build -t aegis:dev -f deployments/docker/Dockerfile .

# ─────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf ml/models/*.onnx
	rm -rf ml/eval/results/
	rm -rf data/processed/
	go clean ./...
