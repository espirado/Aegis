## What

<!-- Brief description of the change -->

## Why

<!-- Link to issue, explain motivation -->

Closes #

## Layer Impact

<!-- Which AEGIS layers does this affect? -->
- [ ] Layer 1 (Input Classifier)
- [ ] Layer 2 (Semantic Auditor)
- [ ] Layer 3 (Output Sanitizer)
- [ ] Decision Engine / Thresholds
- [ ] Audit Logging
- [ ] ML Training / Evaluation
- [ ] Documentation only

## Testing

<!-- How was this tested? -->
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Adversarial tests added/updated (if security-relevant)
- [ ] Manual testing performed

## Security Review Checklist

<!-- Required for changes to Layers 1-3 or decision engine -->
- [ ] Does NOT affect classification boundary (or FPR re-evaluated)
- [ ] Does NOT affect confidence thresholds (or impact documented)
- [ ] No new PHI logging introduced
- [ ] Audit log remains immutable and complete
- [ ] Adversarial test suite covers new behavior
- [ ] N/A — documentation or non-security change
