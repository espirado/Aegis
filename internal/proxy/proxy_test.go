package proxy

import (
	"testing"

	"github.com/espirado/aegis/pkg/types"
)

func newTestProxy(thresholds types.ConfidenceThresholds) *Proxy {
	return &Proxy{thresholds: thresholds}
}

func TestDecide_L2PassNoViolations_HonorsVerdict(t *testing.T) {
	p := newTestProxy(types.DefaultThresholds())
	result := &types.AuditResult{
		Verdict:          types.VerdictPass,
		Confidence:       0.0, // Ollama sometimes returns 0
		PolicyViolations: []string{},
	}

	got := p.decide(result, false)
	if got != types.VerdictPass {
		t.Errorf("L2 PASS with no violations should be honored, got %s", got)
	}
}

func TestDecide_L2PassNoViolations_PHITouching(t *testing.T) {
	p := newTestProxy(types.DefaultThresholds())
	result := &types.AuditResult{
		Verdict:          types.VerdictPass,
		Confidence:       0.0,
		PolicyViolations: []string{},
	}

	got := p.decide(result, true)
	if got != types.VerdictPass {
		t.Errorf("L2 PASS with no violations should be honored even when PHI-touching, got %s", got)
	}
}

func TestDecide_L2PassWithViolations_DoesNotAutoPass(t *testing.T) {
	p := newTestProxy(types.DefaultThresholds())
	result := &types.AuditResult{
		Verdict:          types.VerdictPass,
		Confidence:       0.0,
		PolicyViolations: []string{"PHI_DISCLOSURE"},
	}

	got := p.decide(result, false)
	if got == types.VerdictPass {
		t.Error("L2 PASS with policy violations should NOT auto-pass")
	}
}

func TestDecide_L2Block_Blocked(t *testing.T) {
	p := newTestProxy(types.DefaultThresholds())
	result := &types.AuditResult{
		Verdict:          types.VerdictBlock,
		Confidence:       0.95,
		PolicyViolations: []string{"SAFETY_OVERRIDE"},
	}

	got := p.decide(result, false)
	if got == types.VerdictPass {
		t.Error("L2 BLOCK should never result in PASS")
	}
}

func TestDecide_L2Hold_HighConfidence(t *testing.T) {
	p := newTestProxy(types.DefaultThresholds())
	result := &types.AuditResult{
		Verdict:          types.VerdictHold,
		Confidence:       0.75,
		PolicyViolations: []string{"TOOL_MISUSE"},
	}

	got := p.decide(result, false)
	if got == types.VerdictPass {
		t.Error("L2 HOLD should not result in PASS")
	}
}

func TestDecide_PHIMultiplier_TightensThresholds(t *testing.T) {
	p := newTestProxy(types.ConfidenceThresholds{
		AutoProceed:   0.85,
		HoldAndNotify: 0.60,
		PHIMultiplier: 1.5,
	})
	result := &types.AuditResult{
		Verdict:          types.VerdictPass,
		Confidence:       0.80,
		PolicyViolations: []string{"SOME_POLICY"},
	}

	// Without PHI touching: confidence 0.80 < auto 0.85 but >= hold 0.60 → HOLD
	got := p.decide(result, false)
	if got != types.VerdictHold {
		t.Errorf("expected HOLD without PHI multiplier, got %s", got)
	}

	// With PHI touching: hold threshold becomes 0.90, confidence 0.80 < 0.90 → BLOCK
	got = p.decide(result, true)
	if got != types.VerdictBlock {
		t.Errorf("expected BLOCK with PHI multiplier, got %s", got)
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		v, lo, hi, want float64
	}{
		{0.5, 0, 1, 0.5},
		{-0.1, 0, 1, 0},
		{1.5, 0, 1, 1},
		{1.275, 0, 1, 1}, // 0.85 * 1.5
	}
	for _, tt := range tests {
		got := clamp(tt.v, tt.lo, tt.hi)
		if got != tt.want {
			t.Errorf("clamp(%v, %v, %v) = %v, want %v", tt.v, tt.lo, tt.hi, got, tt.want)
		}
	}
}
