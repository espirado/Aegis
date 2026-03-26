package phi

import (
	"testing"
)

func TestInputPatterns_SSN(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "SSN", "Patient SSN: 123-45-6789")
	if !matched {
		t.Error("InputPatterns should detect SSN")
	}
}

func TestInputPatterns_MRN_Dash(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "MRN", "MRN-4421983")
	if !matched {
		t.Error("InputPatterns should detect MRN with dash separator")
	}
}

func TestInputPatterns_MRN_Colon(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "MRN", "MRN: 4421983")
	if !matched {
		t.Error("InputPatterns should detect MRN with colon separator")
	}
}

func TestInputPatterns_DOB(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "DATE", "DOB: 03/15/1978")
	if !matched {
		t.Error("InputPatterns should detect date of birth")
	}
}

func TestInputPatterns_DateOfBirth_LongForm(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "DATE", "Date of birth: 03/15/1978")
	if !matched {
		t.Error("InputPatterns should detect 'Date of birth:' prefix")
	}
}

func TestInputPatterns_ServiceDate_NotMatched(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "DATE", "Date of Service: 02/28/2026")
	if matched {
		t.Error("InputPatterns should NOT match operational dates like 'Date of Service'")
	}
}

func TestInputPatterns_DenialDate_NotMatched(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "DATE", "Denial Date: 03/10/2026")
	if matched {
		t.Error("InputPatterns should NOT match operational dates like 'Denial Date'")
	}
}

func TestInputPatterns_PatientName(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "NAME", "Patient: Maria Rodriguez")
	if !matched {
		t.Error("InputPatterns should detect patient name after 'Patient:' label")
	}
}

func TestInputPatterns_NPI_NotMatched(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "PHONE", "NPI: 1234567890")
	if matched {
		t.Error("InputPatterns should NOT match NPI numbers as phone numbers")
	}
}

func TestInputPatterns_Phone_WithContext(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "PHONE", "Phone: (555) 123-4567")
	if !matched {
		t.Error("InputPatterns should detect phone numbers with 'Phone:' label")
	}
}

func TestInputPatterns_Email(t *testing.T) {
	patterns := InputPatterns()
	matched := matchAny(patterns, "EMAIL", "Contact: patient@hospital.com")
	if !matched {
		t.Error("InputPatterns should detect email addresses")
	}
}

func TestInputPatterns_BillingQuery_Clean(t *testing.T) {
	patterns := InputPatterns()
	text := "What are the billing prices for an X-ray? CPT code 71046, Date of Service: 02/28/2026"
	for _, p := range patterns {
		if p.Regex.MatchString(text) {
			t.Errorf("InputPatterns should NOT flag benign billing query, but %s matched", p.Type)
		}
	}
}

func TestInputPatterns_ClaimWithPHI(t *testing.T) {
	text := "Patient: Maria Rodriguez, DOB: 03/15/1978, MRN: MRN-4421983, SSN: 456-78-9012"
	patterns := InputPatterns()
	var matched []string
	for _, p := range patterns {
		if p.Regex.MatchString(text) {
			matched = append(matched, string(p.Type))
		}
	}
	expected := map[string]bool{"SSN": false, "MRN": false, "DATE": false, "NAME": false}
	for _, m := range matched {
		expected[m] = true
	}
	for typ, found := range expected {
		if !found {
			t.Errorf("expected %s to be detected in claim text", typ)
		}
	}
}

func TestOutputPatterns_MRN_Dash(t *testing.T) {
	patterns := Patterns()
	matched := matchAny(patterns, "MRN", "MRN-4421983")
	if !matched {
		t.Error("Output Patterns should detect MRN with dash separator")
	}
}

func matchAny(patterns []Pattern, targetType string, text string) bool {
	for _, p := range patterns {
		if string(p.Type) == targetType && p.Regex.MatchString(text) {
			return true
		}
	}
	return false
}
