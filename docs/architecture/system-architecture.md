# AEGIS System Architecture

## Overview

AEGIS is a stateless inline proxy deployed between clients and healthcare AI agents. Every request and response passes through a three-layer inspection pipeline. The system is designed for:

1. **Zero-bypass**: No path around the proxy exists in production
2. **Sub-100ms p50 latency overhead**: Security cannot break clinical workflows
3. **Full auditability**: Every decision is logged with reasoning
4. **Confidence-gated autonomy**: Automated decisions only when confidence is high

## High-Level Data Flow

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                        AEGIS PROXY                          │
                    │                                                             │
 Client ──────────▶│  ┌──────────┐    ┌──────────────┐    ┌─────────────────┐   │──────────▶ AI Agent
 Request           │  │ Layer 1  │───▶│   Layer 2    │───▶│   Forward to    │   │  (if cleared)
                   │  │ Input    │    │   Semantic   │    │   Agent         │   │
                   │  │ Classify │    │   Policy     │    │                 │   │
                   │  └────┬─────┘    └──────┬───────┘    └────────┬────────┘   │
                   │       │                 │                      │            │
                   │       │                 │                      ▼            │
 Client ◀─────────│       │                 │              ┌───────────────┐    │◀────────── AI Agent
 Response          │       │                 │              │   Layer 3     │    │  Response
                   │       │                 │              │   Output      │    │
                   │       │                 │              │   Sanitize    │    │
                   │       ▼                 ▼              └───────┬───────┘    │
                   │  ┌─────────────────────────────────────────────▼──────────┐ │
                   │  │                    Audit Log                           │ │
                   │  │  (decision, confidence, flags, latency, request_id)   │ │
                   │  └───────────────────────────────────────────────────────┘ │
                   └─────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
                                    ┌───────────────────┐
                                    │  Prometheus /      │
                                    │  Alert Manager /   │
                                    │  Hold-and-Notify   │
                                    └───────────────────┘
```

## Layer 1: Input Classification

**Purpose:** Fast, cheap first-pass classification of every inbound prompt.

**Implementation:**
- ONNX model loaded into Go process via ONNX Runtime C API
- Runs on CPU — no GPU dependency in the proxy
- Inference target: < 10ms p50

**Classification Buckets:**
| Class | ID | Description |
|-------|----|-------------|
| `BENIGN` | 0 | Normal clinical query |
| `DIRECT_INJECTION` | 1 | Explicit instruction override ("ignore previous instructions...") |
| `INDIRECT_INJECTION` | 2 | Injection via tool output, context, or retrieved documents |
| `JAILBREAK` | 3 | Persona hijacking, roleplay attacks, encoding tricks |
| `PHI_EXTRACTION` | 4 | Probing for patient data ("list all patients with...") |

**Training Data:**
- Tensor Trust injection corpus (attack/defense pairs)
- HackAPrompt competition dataset
- Custom healthcare adversarial examples (red-teamed from SENTINEL)
- MedQA + PubMedQA as negative class (must not be flagged)

**Decision Logic:**
```
if class == BENIGN and confidence >= 0.85:
    → forward to agent (logged)
if class != BENIGN or confidence < 0.85:
    → route to Layer 2
```

## Layer 2: Semantic Policy Enforcement

**Purpose:** Deep inspection of flagged inputs using an LLM auditor.

**Implementation:**
- Hardened LLM (small model, e.g., Claude Haiku or fine-tuned Llama)
- **No tool access** — cannot be tricked into executing actions
- **No conversation memory** — each evaluation is stateless
- **Locked system prompt** — immutable, not injectable
- Receives: the flagged prompt, the agent's system prompt, the agent's available tools

**Policy Rules:**
Derived from two sources:
1. **HIPAA Technical Safeguards** (45 CFR § 164.312) — access control, audit controls, transmission security
2. **OWASP Top 10 for LLM Applications** — prompt injection, insecure output handling, excessive agency

**Auditor Checks:**
- Could this prompt cause unauthorized PHI disclosure?
- Could this prompt trigger tool misuse (unauthorized API calls, data exfiltration)?
- Could this prompt tamper with clinical recommendations?
- Does this prompt attempt to override the agent's safety instructions?

**Output:** Structured verdict with confidence score and reasoning.

```json
{
  "verdict": "BLOCK",
  "confidence": 0.42,
  "policy_violations": ["PHI_DISCLOSURE", "TOOL_MISUSE"],
  "reasoning": "Prompt attempts to extract patient list via SQL injection in tool parameter",
  "layer1_class": "INDIRECT_INJECTION",
  "layer1_confidence": 0.73
}
```

## Confidence-Gated Autonomy

| Confidence | Standard Action | PHI-Touching Action (× 1.5) |
|------------|----------------|------------------------------|
| ≥ 0.85 | Auto-proceed (logged) | Requires ≥ 0.9425 to auto-proceed |
| 0.60 – 0.85 | Hold-and-notify (30s human window) | Hold-and-notify |
| < 0.60 | Immediate block + escalation | Immediate block + escalation |

**Hold-and-Notify Flow:**
1. Request paused, audit entry created
2. Alert fires to on-call security reviewer (Slack, PagerDuty, or webhook)
3. Reviewer has 30-second window to APPROVE or REJECT
4. If no response in 30s: request proceeds with `ENHANCED_AUDIT` flag
5. If REJECT: request blocked, user receives policy violation message

**Rationale for 30s timeout default-to-proceed:** In clinical workflows, blocking a legitimate query has direct patient impact (delayed authorization). The enhanced audit logging on timeout creates a forensic trail without breaking the workflow. This is configurable per deployment — high-security environments can default to block.

## Layer 3: Output Sanitization

**Purpose:** Catch PHI leakage and indirect exfiltration in agent responses.

**Implementation:**
- Clinical NER model for entity recognition (trained on MIMIC-III)
- Regex patterns for all 18 HIPAA identifiers
- Indirect exfiltration detection:
  - PHI in URL parameters
  - PHI in markdown link text or href
  - PHI in tool-call arguments
  - PHI in code blocks or encoded formats (base64, URL encoding)

**18 HIPAA Identifiers Scanned:**
1. Names
2. Geographic data (below state level)
3. Dates (except year) related to an individual
4. Phone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers
13. Device identifiers
14. Web URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photographs
18. Any other unique identifying number

## Audit Logging

Every request produces a structured audit record:

```json
{
  "request_id": "uuid",
  "timestamp": "2026-03-12T14:30:00Z",
  "layer1": {
    "class": "DIRECT_INJECTION",
    "confidence": 0.78,
    "latency_ms": 4
  },
  "layer2": {
    "verdict": "HOLD",
    "confidence": 0.72,
    "policy_violations": ["PROMPT_INJECTION"],
    "latency_ms": 45
  },
  "layer3": {
    "phi_detected": false,
    "exfiltration_attempt": false,
    "entities_redacted": 0,
    "latency_ms": 3
  },
  "decision": "HOLD_AND_NOTIFY",
  "total_latency_ms": 52,
  "human_review": {
    "reviewer": null,
    "action": "TIMEOUT_PROCEED",
    "response_time_ms": null
  }
}
```

## Deployment Model

```
┌─────────────────────────────────────────┐
│             Kubernetes Cluster           │
│                                         │
│  ┌─────────┐  ┌─────────┐  ┌────────┐ │
│  │  AEGIS   │  │  AEGIS   │  │ AEGIS  │ │
│  │  Proxy   │  │  Proxy   │  │ Proxy  │ │
│  │  Pod 1   │  │  Pod 2   │  │ Pod N  │ │
│  └────┬─────┘  └────┬─────┘  └───┬────┘ │
│       └──────────────┼────────────┘      │
│                      ▼                   │
│              ┌──────────────┐            │
│              │   AI Agent   │            │
│              │   Service    │            │
│              └──────────────┘            │
│                      │                   │
│              ┌──────────────┐            │
│              │  Prometheus  │            │
│              │  + Loki      │            │
│              └──────────────┘            │
└─────────────────────────────────────────┘
```

- Stateless proxy pods scale horizontally
- ONNX model baked into container image
- LLM auditor called via API (Claude Haiku or self-hosted)
- No persistent state in proxy — all audit logs shipped to external store

## Threat Model

See [docs/design/threat-model.md](../design/threat-model.md) for the full STRIDE-mapped threat model.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Go for proxy | Performance-critical path, strong concurrency, single binary deployment |
| Python for ML | Training ecosystem, PyTorch/HuggingFace/ONNX export pipeline |
| ONNX for inference | Embedded in Go, no Python runtime in production, cross-platform |
| Hardened auditor (no tools, no memory) | Prevents auditor compromise via sophisticated multi-layer attacks |
| 30s hold timeout | Balances security with clinical workflow requirements |
| 1.5× PHI multiplier | Higher bar for operations touching patient data |
| Structured audit logs | Forensic trail for HIPAA compliance, enables post-hoc analysis |
