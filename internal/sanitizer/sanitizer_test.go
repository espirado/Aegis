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

func TestScanInputText_RedactsPatientIdentifiers(t *testing.T) {
	san, _ := New(Config{RedactMode: "redact"})
	text := "Patient: Maria Rodriguez, DOB: 03/15/1978, MRN: MRN-4421983, SSN: 456-78-9012"
	entities := san.ScanInputText(text)
	if len(entities) == 0 {
		t.Fatal("expected input entities to be detected")
	}

	typeSet := make(map[string]bool)
	for _, e := range entities {
		typeSet[e.Type] = true
	}
	for _, want := range []string{"SSN", "MRN", "DATE", "NAME"} {
		if !typeSet[want] {
			t.Errorf("expected %s in detected entities, got %v", want, typeSet)
		}
	}
}

func TestScanInputText_PreservesOperationalData(t *testing.T) {
	san, _ := New(Config{RedactMode: "redact"})
	text := "Date of Service: 02/28/2026, CPT 27447, Denial Date: 03/10/2026, NPI: 1234567890"
	entities := san.ScanInputText(text)
	if len(entities) != 0 {
		types := make([]string, len(entities))
		for i, e := range entities {
			types[i] = e.Type
		}
		t.Errorf("expected no input entities for operational data, but got %v", types)
	}
}

func TestScanInputText_RedactProducesCleanPrompt(t *testing.T) {
	san, _ := New(Config{RedactMode: "redact"})
	text := "Evaluate claim for Patient: Jane Doe, SSN: 111-22-3333, DOB: 01/15/1990, CPT 99213, Date of Service: 03/01/2026"

	entities := san.ScanInputText(text)
	redacted := san.Redact(text, entities)

	if containsSubstring(redacted, "111-22-3333") {
		t.Error("SSN should be redacted from input")
	}
	if containsSubstring(redacted, "01/15/1990") {
		t.Error("DOB should be redacted from input")
	}
	if !containsSubstring(redacted, "03/01/2026") {
		t.Error("Date of Service should be PRESERVED in input")
	}
	if !containsSubstring(redacted, "CPT 99213") {
		t.Error("CPT code should be PRESERVED in input")
	}
}

func TestScanDirect_MRN_DashFormat(t *testing.T) {
	san, _ := New(Config{RedactMode: "block"})
	result, _ := san.Scan(context.Background(), "MRN-4421983")
	if !result.PHIDetected {
		t.Error("expected PHI to be detected for dash-separated MRN")
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
