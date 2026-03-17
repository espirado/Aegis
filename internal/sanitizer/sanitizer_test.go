package sanitizer

import (
	"context"
	"testing"
)

func TestScanDirect_SSN(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, err := san.Scan(context.Background(), "The patient's SSN is 123-45-6789.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.PHIDetected {
		t.Error("expected PHI to be detected (SSN)")
	}
	found := false
	for _, pt := range result.PHITypes {
		if pt == "SSN" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SSN in PHI types, got %v", result.PHITypes)
	}
}

func TestScanDirect_Phone(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "Call the patient at (555) 123-4567.")
	if !result.PHIDetected {
		t.Error("expected PHI to be detected (phone)")
	}
}

func TestScanDirect_Email(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "Send records to patient@hospital.com")
	if !result.PHIDetected {
		t.Error("expected PHI to be detected (email)")
	}
}

func TestScanDirect_MRN(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "MRN: 12345678")
	if !result.PHIDetected {
		t.Error("expected PHI to be detected (MRN)")
	}
}

func TestScanDirect_NoPHI(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "The patient should take ibuprofen 400mg twice daily.")
	if result.PHIDetected {
		t.Errorf("expected no PHI, but detected: %v", result.PHITypes)
	}
}

func TestScanDirect_Date(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "Admitted on 03/15/2026 for surgery.")
	if !result.PHIDetected {
		t.Error("expected PHI to be detected (date)")
	}
}

func TestRedact(t *testing.T) {
	san, _ := New(Config{RedactMode: "redact"})
	text := "SSN is 123-45-6789 on file."
	entities := san.ScanText(text)
	if len(entities) == 0 {
		t.Fatal("expected entities to be detected")
	}
	redacted := san.Redact(text, entities)
	if redacted == text {
		t.Error("expected text to be redacted")
	}
	if !containsSubstring(redacted, "[REDACTED-SSN]") {
		t.Errorf("expected [REDACTED-SSN] in redacted text, got: %s", redacted)
	}
}

func TestExfiltration_URLParam(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	text := "Visit https://example.com/api?ssn=123-45-6789 for details."
	result, _ := san.Scan(context.Background(), text)
	if !result.PHIDetected {
		t.Error("expected PHI detected in URL param")
	}
	if !result.ExfiltrationAttempt {
		t.Error("expected exfiltration attempt to be flagged")
	}
}

func TestExfiltration_MarkdownLink(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	text := "Click [here](https://evil.com/?email=patient@hospital.com) to view."
	result, _ := san.Scan(context.Background(), text)
	if !result.PHIDetected {
		t.Error("expected PHI detected in markdown link")
	}
}

func TestExfiltration_Base64(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	// base64 of "SSN: 123-45-6789"
	text := "The encoded data is U1NOOiAxMjMtNDUtNjc4OQ== for reference."
	result, _ := san.Scan(context.Background(), text)
	if !result.PHIDetected {
		t.Error("expected PHI detected in base64-encoded content")
	}
}

func TestExfiltration_CodeBlock(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	text := "```json\n{\"patient_ssn\": \"123-45-6789\"}\n```"
	result, _ := san.Scan(context.Background(), text)
	if !result.PHIDetected {
		t.Error("expected PHI detected in code block")
	}
}

func TestContainsPHI(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	if san.ContainsPHI("Normal clinical text about treatment.") {
		t.Error("should not detect PHI in normal text")
	}
	if !san.ContainsPHI("Patient SSN: 123-45-6789") {
		t.Error("should detect PHI in text with SSN")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsAt(s, sub))
}

func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
