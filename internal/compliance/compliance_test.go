package compliance

import (
	"strings"
	"testing"
)

func TestCheck_FullCompliance(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{
		PIIDetection:       true,
		PIIAnonymization:   true,
		EncryptionAtRest:   true,
		AuditLogging:       true,
		ConsentManagement:  true,
		DataRetention:      true,
		AccessControl:      true,
		PromptGuard:        true,
		OutputGuardrails:   true,
		SkillAuditing:      true,
		RateLimiting:       true,
		TLSEncryption:      true,
		DataLocalization:   true,
		RightToErasure:     true,
		DataPortability:    true,
		HumanOversight:     true,
		TransparencyReport: true,
	}

	report := checker.Check(caps)

	if report.OverallScore != 100 {
		t.Errorf("expected 100%% compliance, got %.1f%%", report.OverallScore)
	}

	for _, r := range report.Results {
		if r.Status != StatusCompliant {
			t.Errorf("requirement %s should be compliant, got %s", r.Requirement.ID, r.Status)
		}
	}

	if len(report.Recommendations) != 0 {
		t.Errorf("expected 0 recommendations, got %d", len(report.Recommendations))
	}
}

func TestCheck_NoCompliance(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{} // All false

	report := checker.Check(caps)

	if report.OverallScore != 0 {
		t.Errorf("expected 0%% compliance, got %.1f%%", report.OverallScore)
	}

	for _, r := range report.Results {
		if r.Status != StatusNonCompliant && r.Status != StatusNotApplicable {
			t.Errorf("requirement %s should be non-compliant, got %s", r.Requirement.ID, r.Status)
		}
	}

	if len(report.Recommendations) == 0 {
		t.Error("expected recommendations for non-compliant system")
	}
}

func TestCheck_PartialCompliance(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
		EncryptionAtRest: true,
		AuditLogging:     true,
		TLSEncryption:    true,
		AccessControl:    true,
	}

	report := checker.Check(caps)

	if report.OverallScore <= 0 || report.OverallScore >= 100 {
		t.Errorf("expected partial score, got %.1f%%", report.OverallScore)
	}

	compliant := 0
	nonCompliant := 0
	for _, r := range report.Results {
		switch r.Status {
		case StatusCompliant:
			compliant++
		case StatusNonCompliant:
			nonCompliant++
		}
	}

	if compliant == 0 {
		t.Error("expected some compliant requirements")
	}
	if nonCompliant == 0 {
		t.Error("expected some non-compliant requirements")
	}
}

func TestCheck_VietnamOnly(t *testing.T) {
	checker := NewCheckerForFrameworks(FrameworkVietnamAI)
	caps := SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
	}

	report := checker.Check(caps)

	for _, r := range report.Results {
		if r.Requirement.Framework != FrameworkVietnamAI {
			t.Errorf("expected only Vietnam framework, got %s", r.Requirement.Framework)
		}
	}

	if len(report.Frameworks) != 1 || report.Frameworks[0] != FrameworkVietnamAI {
		t.Errorf("expected 1 framework (Vietnam), got %v", report.Frameworks)
	}
}

func TestCheck_GDPROnly(t *testing.T) {
	checker := NewCheckerForFrameworks(FrameworkGDPR)
	caps := SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
		RightToErasure:   true,
		DataPortability:  true,
		EncryptionAtRest: true,
		TLSEncryption:    true,
		AuditLogging:     true,
		ConsentManagement: true,
	}

	report := checker.Check(caps)

	if report.OverallScore != 100 {
		t.Errorf("expected 100%% GDPR compliance, got %.1f%%", report.OverallScore)
	}

	for _, r := range report.Results {
		if r.Requirement.Framework != FrameworkGDPR {
			t.Errorf("expected only GDPR framework, got %s", r.Requirement.Framework)
		}
	}
}

func TestCheck_EUAIAct(t *testing.T) {
	checker := NewCheckerForFrameworks(FrameworkEUAI)
	caps := SystemCapabilities{
		SkillAuditing:      true,
		HumanOversight:     true,
		TransparencyReport: true,
		AuditLogging:       true,
		PromptGuard:        true,
		OutputGuardrails:   true,
	}

	report := checker.Check(caps)

	if report.OverallScore != 100 {
		t.Errorf("expected 100%% EU AI Act compliance, got %.1f%%", report.OverallScore)
	}
}

func TestCheck_Evidence(t *testing.T) {
	checker := NewCheckerForFrameworks(FrameworkVietnamAI)
	caps := SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
		EncryptionAtRest: true,
		TLSEncryption:    true,
		AccessControl:    true,
		SkillAuditing:    true,
		AuditLogging:     true,
	}

	report := checker.Check(caps)

	foundEvidence := false
	for _, r := range report.Results {
		if len(r.Evidence) > 0 {
			foundEvidence = true
			break
		}
	}
	if !foundEvidence {
		t.Error("expected evidence in compliant results")
	}
}

func TestCheck_Recommendations(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
	}

	report := checker.Check(caps)

	if len(report.Recommendations) == 0 {
		t.Error("expected recommendations for partially compliant system")
	}

	// Recommendations should reference mandatory non-compliant items
	for _, rec := range report.Recommendations {
		if !strings.Contains(rec, "[") {
			t.Errorf("recommendation should include requirement ID: %s", rec)
		}
	}
}

func TestReportJSON(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{PIIDetection: true}
	report := checker.Check(caps)

	jsonBytes, err := report.ReportJSON()
	if err != nil {
		t.Fatalf("ReportJSON: %v", err)
	}

	json := string(jsonBytes)
	if !strings.Contains(json, "overall_score") {
		t.Error("JSON missing overall_score")
	}
	if !strings.Contains(json, "frameworks") {
		t.Error("JSON missing frameworks")
	}
	if !strings.Contains(json, "results") {
		t.Error("JSON missing results")
	}
}

func TestReportHTML(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{PIIDetection: true, AuditLogging: true}
	report := checker.Check(caps)

	html := report.ReportHTML()

	if !strings.Contains(html, "<html>") {
		t.Error("expected HTML output")
	}
	if !strings.Contains(html, "Vura Compliance Report") {
		t.Error("expected report title")
	}
	if !strings.Contains(html, "Luật AI Việt Nam 2026") {
		t.Error("expected Vietnam framework name")
	}
	if !strings.Contains(html, "GDPR") {
		t.Error("expected GDPR framework name")
	}
}

func TestFrameworkName(t *testing.T) {
	tests := []struct {
		fw       Framework
		expected string
	}{
		{FrameworkVietnamAI, "Luật AI Việt Nam 2026"},
		{FrameworkEUAI, "EU AI Act"},
		{FrameworkGDPR, "GDPR"},
		{Framework("unknown"), "unknown"},
	}
	for _, tt := range tests {
		got := frameworkName(tt.fw)
		if got != tt.expected {
			t.Errorf("frameworkName(%s) = %s, want %s", tt.fw, got, tt.expected)
		}
	}
}

func TestStatusDisplayName(t *testing.T) {
	tests := []struct {
		status   ComplianceStatus
		expected string
	}{
		{StatusCompliant, "Đạt"},
		{StatusNonCompliant, "Không đạt"},
		{StatusPartial, "Một phần"},
		{StatusNotApplicable, "N/A"},
		{ComplianceStatus("other"), "other"},
	}
	for _, tt := range tests {
		got := statusDisplayName(tt.status)
		if got != tt.expected {
			t.Errorf("statusDisplayName(%s) = %s, want %s", tt.status, got, tt.expected)
		}
	}
}

func TestBoolStatus(t *testing.T) {
	if boolStatus(true) != StatusCompliant {
		t.Error("expected compliant for true")
	}
	if boolStatus(false) != StatusNonCompliant {
		t.Error("expected non-compliant for false")
	}
}

func TestComplianceSummary(t *testing.T) {
	checker := NewChecker()
	caps := SystemCapabilities{PIIDetection: true}
	report := checker.Check(caps)

	if report.Summary == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(report.Summary, "Đánh giá tuân thủ") {
		t.Error("summary should contain assessment text")
	}
}

func TestRequirementWeight(t *testing.T) {
	if requirementWeight("mandatory") != 3.0 {
		t.Error("mandatory should have weight 3.0")
	}
	if requirementWeight("recommended") != 2.0 {
		t.Error("recommended should have weight 2.0")
	}
	if requirementWeight("optional") != 1.0 {
		t.Error("optional should have weight 1.0")
	}
	if requirementWeight("") != 1.0 {
		t.Error("unknown should have weight 1.0")
	}
}
