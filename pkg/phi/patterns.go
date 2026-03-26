// Package phi provides detection patterns for the 18 HIPAA identifiers.
//
// These patterns are used by Layer 3 (output sanitizer) and can also be
// used in Layer 1 preprocessing.
//
// Reference: 45 CFR § 164.514(b)(2) — Safe Harbor de-identification method
package phi

import "regexp"

// IdentifierType represents one of the 18 HIPAA identifiers.
type IdentifierType string

const (
	Name                IdentifierType = "NAME"
	GeographicData      IdentifierType = "GEOGRAPHIC"
	Date                IdentifierType = "DATE"
	PhoneNumber         IdentifierType = "PHONE"
	FaxNumber           IdentifierType = "FAX"
	EmailAddress        IdentifierType = "EMAIL"
	SSN                 IdentifierType = "SSN"
	MedicalRecordNumber IdentifierType = "MRN"
	HealthPlanBenefID   IdentifierType = "HEALTH_PLAN_ID"
	AccountNumber       IdentifierType = "ACCOUNT_NUMBER"
	CertificateLicense  IdentifierType = "CERTIFICATE_LICENSE"
	VehicleIdentifier   IdentifierType = "VEHICLE_ID"
	DeviceIdentifier    IdentifierType = "DEVICE_ID"
	WebURL              IdentifierType = "URL"
	IPAddress           IdentifierType = "IP_ADDRESS"
	BiometricID         IdentifierType = "BIOMETRIC"
	FullFacePhoto       IdentifierType = "PHOTO"
	UniqueIdentifier    IdentifierType = "OTHER_UNIQUE_ID"
)

// Pattern pairs an identifier type with its regex.
type Pattern struct {
	Type    IdentifierType
	Regex   *regexp.Regexp
	Comment string
}

// Patterns returns compiled regex patterns for detectable HIPAA identifiers.
// Some identifiers (Name, Geographic, Biometric, Photo) require NER — not regex.
func Patterns() []Pattern {
	return []Pattern{
		{
			Type:    SSN,
			Regex:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Comment: "Social Security Number (XXX-XX-XXXX)",
		},
		{
			Type:    SSN,
			Regex:   regexp.MustCompile(`\b\d{9}\b`),
			Comment: "SSN without dashes (9 consecutive digits)",
		},
		{
			Type:    PhoneNumber,
			Regex:   regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			Comment: "US phone number in various formats",
		},
		{
			Type:    FaxNumber,
			Regex:   regexp.MustCompile(`(?i)\bfax[:\s]*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			Comment: "Fax number (preceded by 'fax')",
		},
		{
			Type:    EmailAddress,
			Regex:   regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`),
			Comment: "Email address",
		},
		{
			Type:    MedicalRecordNumber,
			Regex:   regexp.MustCompile(`(?i)\b(?:mrn|medical\s*record)[:\s#\-]*\d{4,12}\b`),
			Comment: "Medical Record Number (prefixed with MRN or medical record)",
		},
		{
			Type:    HealthPlanBenefID,
			Regex:   regexp.MustCompile(`(?i)\b(?:member|beneficiary|plan)\s*(?:id|#|number)[:\s]*[A-Z0-9]{6,15}\b`),
			Comment: "Health plan beneficiary ID",
		},
		{
			Type:    AccountNumber,
			Regex:   regexp.MustCompile(`(?i)\baccount\s*(?:#|number|no)[:\s]*\d{6,17}\b`),
			Comment: "Account number",
		},
		{
			Type:    IPAddress,
			Regex:   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			Comment: "IPv4 address",
		},
		{
			Type:    Date,
			Regex:   regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b`),
			Comment: "Date in MM/DD/YYYY or MM-DD-YYYY format",
		},
		{
			Type:    Date,
			Regex:   regexp.MustCompile(`\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`),
			Comment: "Date in Month DD, YYYY format",
		},
		{
			Type:    VehicleIdentifier,
			Regex:   regexp.MustCompile(`(?i)\b(?:vin|vehicle)[:\s]*[A-HJ-NPR-Z0-9]{17}\b`),
			Comment: "Vehicle Identification Number (17 chars)",
		},
		{
			Type:    WebURL,
			Regex:   regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`),
			Comment: "Web URL (http or https)",
		},
	}
}

// InputPatterns returns patterns for input sanitization — targeted at
// patient identifiers only. Operational data (dates of service, provider
// NPIs, procedure codes) is preserved so the agent can do its job.
func InputPatterns() []Pattern {
	return []Pattern{
		{
			Type:    SSN,
			Regex:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Comment: "Social Security Number (XXX-XX-XXXX)",
		},
		{
			Type:    SSN,
			Regex:   regexp.MustCompile(`\b\d{9}\b`),
			Comment: "SSN without dashes (9 consecutive digits)",
		},
		{
			Type:    MedicalRecordNumber,
			Regex:   regexp.MustCompile(`(?i)\b(?:mrn|medical\s*record)[:\s#\-]*\d{4,12}\b`),
			Comment: "Medical Record Number",
		},
		{
			Type:    HealthPlanBenefID,
			Regex:   regexp.MustCompile(`(?i)\b(?:member|beneficiary|plan)\s*(?:id|#|number)[:\s]*[A-Z0-9]{6,15}\b`),
			Comment: "Health plan beneficiary ID",
		},
		{
			Type:    EmailAddress,
			Regex:   regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`),
			Comment: "Email address",
		},
		{
			Type:    Date,
			Regex:   regexp.MustCompile(`(?i)(?:dob|date\s*of\s*birth|born|birthday)[:\s]*(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}`),
			Comment: "Date of birth only (context-anchored, not all dates)",
		},
		{
			Type:    Date,
			Regex:   regexp.MustCompile(`(?i)(?:dob|date\s*of\s*birth|born|birthday)[:\s]*(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}`),
			Comment: "Date of birth in Month DD, YYYY format (context-anchored)",
		},
		{
			Type:    Name,
			Regex:   regexp.MustCompile(`(?i)(?:patient|patient\s*name|member\s*name|insured|subscriber)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})`),
			Comment: "Patient name following structured field labels (e.g. 'Patient: Jane Doe')",
		},
		{
			Type:    PhoneNumber,
			Regex:   regexp.MustCompile(`(?i)(?:phone|cell|mobile|tel|contact)[:\s]*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
			Comment: "Phone number (context-anchored, won't match NPIs)",
		},
	}
}

// NERRequiredTypes returns identifier types that require NER (not regex).
func NERRequiredTypes() []IdentifierType {
	return []IdentifierType{
		Name,
		GeographicData,
		BiometricID,
		FullFacePhoto,
		CertificateLicense,
		DeviceIdentifier,
		UniqueIdentifier,
	}
}
