# AEGIS Threat Model

Mapped to [STRIDE](https://en.wikipedia.org/wiki/STRIDE_(security)) extended for agentic AI, informed by Nagaraja et al. (2025) and OWASP Top 10 for LLM Applications.

## Scope

This threat model covers the AEGIS proxy and its interactions with:
- End users (clinicians, billing staff, administrators)
- Upstream AI agents (LLMs with tool access in healthcare workflows)
- External data sources (knowledge bases, retrieved documents, tool outputs)

## Attack Surface Map

```
            Attacker Vectors
            ─────────────────
                    │
    ┌───────────────┼───────────────────┐
    │               │                   │
    ▼               ▼                   ▼
┌────────┐   ┌────────────┐   ┌─────────────────┐
│ Direct │   │  Indirect  │   │  Infrastructure  │
│ Input  │   │  Context   │   │  Compromise      │
│        │   │  Poisoning │   │                  │
└────────┘   └────────────┘   └─────────────────┘
```

## STRIDE Mapping

### S — Spoofing

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Attacker impersonates authorized clinician | Pre-proxy (AuthN) | Out of scope — AEGIS assumes authenticated sessions |
| Attacker crafts prompt that makes agent respond as different persona | L2 Auditor | Policy check for persona hijacking patterns |
| Compromised tool output spoofs trusted data source | L1 + L2 | Indirect injection classification + provenance checking |

### T — Tampering

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Prompt injection modifies agent behavior | L1 Classifier | Five-class classification catches direct/indirect injection |
| Poisoned knowledge base entry corrupts retrieval (Zhang, 2024: 82% corruption from single token) | L2 Auditor | Policy check for contradictory or suspicious retrieved context |
| Attacker modifies clinical recommendation in agent output | L3 Sanitizer | Output consistency check against input intent |
| Adversarial input designed to fool both L1 classifier and L2 auditor | L1 + L2 | Ensemble disagreement detection, auditor hardening |

### R — Repudiation

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Attacker claims they never sent malicious prompt | Audit Log | Immutable structured audit log with request hashes |
| Human reviewer denies approving flagged request | Hold-and-Notify | Reviewer action logged with timestamp and identity |
| Agent output modified after AEGIS inspection | L3 + Audit | Response hash stored in audit record |

### I — Information Disclosure

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Direct PHI extraction ("list all patients with...") | L1 Classifier | PHI_EXTRACTION class detection |
| Indirect PHI exfiltration via URL params, markdown, tool args | L3 Sanitizer | Pattern matching for encoded PHI in output channels |
| PHI leaked in LLM reasoning traces | L3 Sanitizer | NER + 18 HIPAA identifier regex on full response |
| PHI exposure through agent's chain-of-thought | L3 Sanitizer | Scan reasoning blocks, not just final output |
| Auditor itself leaking prompt content in logs | Audit Config | Audit log redaction policy — flagged content hashed, not stored verbatim |

### D — Denial of Service

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Flood of adversarial prompts to overwhelm L2 auditor | L1 + Rate Limiting | L1 classifier filters before expensive L2 calls; per-client rate limits |
| Hold-and-notify flood exhausts human reviewers | Notify System | Auto-escalation after N pending reviews; circuit breaker |
| Crafted input that causes ONNX model to hang | L1 Classifier | Inference timeout (10ms hard limit), input length cap |

### E — Elevation of Privilege

| Threat | AEGIS Layer | Mitigation |
|--------|-------------|------------|
| Prompt injection grants agent unauthorized tool access | L2 Auditor | Policy check against agent's declared tool permissions |
| Confused deputy: agent uses legitimate tools for unauthorized purposes | L2 + L3 | Intent vs. action consistency check |
| Attacker escalates from read-only to write operations via injection | L2 Auditor | Operation-level policy enforcement |
| AEGIS bypass: request routed around proxy | Infrastructure | Network policy: agent only accepts traffic from AEGIS pods |

## Agentic-Specific Threats (OWASP Extension)

| OWASP Category | AEGIS Coverage |
|----------------|----------------|
| LLM01: Prompt Injection | L1 (classification) + L2 (semantic analysis) |
| LLM02: Insecure Output Handling | L3 (sanitization) |
| LLM06: Excessive Agency | L2 (tool permission policy) |
| LLM07: System Prompt Leakage | L3 (output scan for system prompt fragments) |
| Goal Manipulation | L2 (intent consistency checking) |
| Confused Deputy | L2 + L3 (action vs. permission validation) |
| Reflection Loop Traps | L2 (loop detection in multi-turn context) |

## Assumptions

1. Authentication and authorization happen upstream of AEGIS
2. TLS terminates at the proxy — all inspection happens on plaintext
3. The AI agent is treated as untrusted (it can be compromised)
4. The L2 auditor model is a smaller, more constrained model than the primary agent
5. Network policies enforce that the agent only accepts traffic from AEGIS

## Open Questions

- [ ] How to detect slow-burn attacks that stay under confidence thresholds across multiple requests?
- [ ] Should the auditor have access to request history for pattern detection, or does that create a new attack surface?
- [ ] What is the minimum viable auditor model size that maintains policy accuracy?
