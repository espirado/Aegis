# Contributing to AEGIS

## Welcome

AEGIS is a joint research project building a real-time security proxy for healthcare AI agents. This guide ensures all collaborators are aligned on objectives, workflow, and standards.

## Project Objectives

1. **Build a three-layer inline proxy** (input classification → semantic policy enforcement → output sanitization) that intercepts adversarial attacks on healthcare AI agents
2. **Achieve four quantified targets:** ≥90% attack success rate reduction, <1% false positive rate on clinical queries, <100ms p50 latency, ≥95% PHI leak prevention
3. **Produce a publication-quality paper** with reproducible experiments and results
4. **Ship production-ready code** deployable in Kustode's healthcare infrastructure

## Before You Start

1. Read the [System Architecture](docs/architecture/system-architecture.md)
2. Read the [Threat Model](docs/design/threat-model.md)
3. Read the [Research Plan](docs/analysis/research-plan.md)
4. Read the [Coding Standards](docs/guides/coding-standards.md)
5. Review the [Roadmap](docs/ROADMAP.md) and find your assigned tasks

## Development Setup

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_ORG/aegis.git
cd aegis

# 2. Install Go (1.22+)
# https://go.dev/doc/install

# 3. Install Python (3.11+) and create venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r ml/requirements.txt

# 4. Install pre-commit hooks
make setup-hooks

# 5. Download datasets
make download-data

# 6. Verify setup
make test
```

## Workflow

### 1. Pick a Task
- Check the [Roadmap](docs/ROADMAP.md) for current phase tasks
- Check GitHub Issues for unassigned items
- Assign yourself before starting

### 2. Branch and Build
```bash
git checkout -b feature/your-feature-name
# ... do the work ...
make lint
make test
```

### 3. Submit a PR
- Fill out the PR template
- Link the issue
- Request review from the relevant owner (see Roadmap task ownership)
- For security-relevant changes, complete the security review checklist

### 4. Review Cycle
- Address review comments
- Squash commits before merge
- Delete branch after merge

## What Needs Review

| Change Type | Reviewer Required |
|-------------|-------------------|
| ML training / model changes | ML Lead + Andrew |
| Go proxy / layer logic | Go Lead + Andrew |
| Confidence threshold changes | Both leads + Andrew |
| Audit log schema changes | Both leads |
| Config changes | Whoever owns the component |
| Documentation | Any collaborator |

## Communication

- **Issues:** All work items tracked as GitHub Issues
- **PRs:** All code changes go through PRs — no direct pushes to `main`
- **Decisions:** Architecture decisions documented in `docs/design/` as ADRs (Architecture Decision Records)
- **Questions:** Open a Discussion on GitHub or message in the project channel

## Sensitive Data Rules

**Critical — violating these rules is grounds for removal from the project.**

1. **Never commit real patient data.** All PHI in test fixtures must be synthetic.
2. **Never commit MIMIC-III data.** License prohibits redistribution. Download via script with your own credentials.
3. **Never log real PHI.** Hash or redact before logging, even in dev.
4. **Never commit API keys, tokens, or credentials.** Use environment variables.
5. **Never share MIMIC-III credentials.** Each collaborator must apply independently at PhysioNet.

## Intellectual Property

- All contributions to this repo are covered under the project's license
- Research contributions will be acknowledged in publications
- Discuss authorship expectations with Andrew before significant research contributions

## Code of Conduct

Be professional. Be constructive. Focus on the work. If you disagree on a technical approach, open an issue with your reasoning and propose alternatives. Andrew makes final calls on architecture decisions.
