# AEGIS Coding Standards & Style Guide

## General Principles

1. **Clarity over cleverness.** Code is read 10× more than it's written.
2. **Fail loudly.** Silent failures in a security system are unacceptable. Every error must be logged and surfaced.
3. **No silent drops.** Every request must produce an audit record, even if processing fails.
4. **Immutable audit trail.** Audit records are append-only. Never mutate or delete.
5. **Defense in depth.** Don't rely on any single layer. Assume each layer can be bypassed.

---

## Go Standards

### Project Layout
Follow [Standard Go Project Layout](https://github.com/golang-standards/project-layout):
- `cmd/` — Main applications
- `internal/` — Private packages (not importable by external code)
- `pkg/` — Public packages (importable by other projects)

### Formatting & Linting
- `gofmt` — non-negotiable, enforced in CI
- `golangci-lint` with config in `.golangci.yml`
- Enabled linters: `errcheck`, `govet`, `staticcheck`, `gosec`, `ineffassign`, `unused`

### Error Handling
```go
// GOOD: Wrap errors with context
if err != nil {
    return fmt.Errorf("layer1 classify request %s: %w", req.ID, err)
}

// BAD: Bare error return
if err != nil {
    return err
}

// BAD: Ignoring errors (gosec will catch this)
result, _ := classifier.Classify(input)
```

### Logging
- Use structured logging (`slog` or `zerolog`)
- Every log line MUST include `request_id`
- Security-relevant events use level `WARN` or `ERROR`
- **Never log raw PHI.** Hash or redact before logging.

```go
// GOOD
slog.Warn("phi_detected_in_output",
    "request_id", req.ID,
    "phi_types", detectedTypes,
    "action", "redacted",
)

// BAD — logs actual patient data
slog.Warn("found patient name", "name", patientName)
```

### Testing
- Table-driven tests for all classification logic
- `_test.go` files next to the code they test
- Test file naming: `{file}_test.go`
- Use `testify/assert` for assertions
- Adversarial test cases go in `test/adversarial/`

### Concurrency
- Use `context.Context` for cancellation and timeouts
- L2 auditor calls MUST have a timeout (default 5s)
- Hold-and-notify MUST have a timeout (default 30s)
- Never use bare goroutines — always use `errgroup` or similar

### Security-Specific Rules
- **No dynamic SQL.** All queries parameterized.
- **No `fmt.Sprintf` in prompts.** Use typed template builders.
- **No user input in log format strings.**
- **Auditor system prompt is a constant**, not configurable at runtime.
- **ONNX model path is validated** — no path traversal.

---

## Python Standards

### Environment
- Python 3.11+
- Dependencies in `ml/requirements.txt` (pinned versions)
- Virtual environment via `venv` (not conda)

### Formatting & Linting
- `ruff` for linting and formatting (replaces black + isort + flake8)
- `mypy` for type checking (strict mode)
- Config in `pyproject.toml`

### Code Style
```python
# GOOD: Type hints on all public functions
def train_classifier(
    train_path: Path,
    val_path: Path,
    output_dir: Path,
    epochs: int = 10,
    seed: int = 42,
) -> dict[str, float]:
    """Train the 5-class input classifier.
    
    Returns dict of evaluation metrics.
    """

# BAD: No types, no docstring
def train(train, val, out, epochs=10):
    ...
```

### Data Handling
- All data paths go through `configs/` — no hardcoded paths
- Raw data in `data/raw/`, processed in `data/processed/`, splits in `data/splits/`
- Data loading functions return typed dataclasses, not raw dicts
- **Never commit data files.** All data is gitignored and downloaded via scripts.

### Experiment Tracking
- Every training run logs: hyperparameters, metrics, random seed, git commit hash
- Results saved as JSON in `ml/eval/results/`
- Notebooks are for exploration only — final analysis scripts must be reproducible `.py` files

### Model Export
- All models exported to ONNX before integration
- Export script validates: input/output shapes, inference time, output equivalence with PyTorch
- ONNX models go in `ml/models/` (gitignored, downloaded or rebuilt via scripts)

---

## Git Standards

### Branch Naming
```
feature/layer1-classifier
feature/layer2-auditor
feature/layer3-sanitizer
fix/phi-regex-ssn-pattern
experiment/calibration-platt-scaling
docs/threat-model-update
```

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(classifier): add indirect injection class to training pipeline
fix(sanitizer): handle base64-encoded PHI in markdown links
test(proxy): add integration test for hold-and-notify timeout
docs(architecture): update Layer 2 auditor hardening rationale
experiment(eval): run ablation L1-only vs L1+L2 on tensor-trust
```

### Pull Request Requirements
1. Description of what changed and why
2. Link to relevant issue
3. All CI checks passing
4. At least one reviewer approval
5. No decrease in test coverage
6. For security-relevant changes: explicit review of attack surface impact

### What NOT to Commit
- `.env` files or any credentials
- Data files (use download scripts)
- Model files (use build/download scripts)
- IDE-specific files (`.idea/`, `.vscode/` — add to `.gitignore`)
- MIMIC-III data (license prohibits redistribution)

---

## Security Review Checklist

For any PR touching Layers 1–3 or the decision engine:

- [ ] Does this change affect the classification boundary? If yes, re-run FPR evaluation.
- [ ] Does this change affect the confidence threshold logic? If yes, document the impact on hold/block rates.
- [ ] Could an attacker exploit this change to bypass a layer?
- [ ] Does this change introduce any new logging that might inadvertently capture PHI?
- [ ] Is the audit log still immutable and complete after this change?
- [ ] Has the adversarial test suite been updated to cover the new behavior?

---

## Configuration Management

- All config in `configs/*.yaml` — no config in code
- Environment-specific overrides via `AEGIS_CONFIG_PATH` env var
- Secrets (API keys, credentials) via environment variables only — never in config files
- Config schema validated at startup — proxy refuses to start with invalid config
