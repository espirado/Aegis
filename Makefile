.PHONY: help setup setup-hooks test test-go test-py lint lint-go lint-py \
       download-data download-mimic preprocess-data \
       train-classifier evaluate \
       run-dev build docker-build clean

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

evaluate: ## Run full evaluation suite
	.venv/bin/python ml/eval/evaluate.py \
		--model-path ml/models/classifier_v1.onnx \
		--test-path data/processed/test.jsonl

# ─────────────────────────────────────────────────────────
# Build & Run
# ─────────────────────────────────────────────────────────
build: ## Build AEGIS proxy binary
	go build -o bin/aegis ./cmd/aegis/

run-dev: ## Run proxy in development mode
	go run ./cmd/aegis/

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
