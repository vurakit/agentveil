package compliance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Framework identifies a regulatory framework
type Framework string

const (
	FrameworkVietnamAI Framework = "vietnam_ai_2026"
	FrameworkEUAI      Framework = "eu_ai_act"
	FrameworkGDPR      Framework = "gdpr"
)

// Requirement represents a single regulatory requirement
type Requirement struct {
	ID          string    `json:"id"`
	Framework   Framework `json:"framework"`
	Article     string    `json:"article"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"` // "mandatory", "recommended", "optional"
}

// ComplianceStatus represents whether a requirement is met
type ComplianceStatus string

const (
	StatusCompliant    ComplianceStatus = "compliant"
	StatusNonCompliant ComplianceStatus = "non_compliant"
	StatusPartial      ComplianceStatus = "partial"
	StatusNotApplicable ComplianceStatus = "not_applicable"
)

// CheckResult represents the result of checking one requirement
type CheckResult struct {
	Requirement Requirement      `json:"requirement"`
	Status      ComplianceStatus `json:"status"`
	Details     string           `json:"details"`
	Evidence    []string         `json:"evidence,omitempty"`
}

// ComplianceReport is the full compliance assessment
type ComplianceReport struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	Frameworks     []Framework    `json:"frameworks"`
	Results        []CheckResult  `json:"results"`
	OverallScore   float64        `json:"overall_score"` // 0-100
	Summary        string         `json:"summary"`
	Recommendations []string      `json:"recommendations,omitempty"`
}

// SystemCapabilities describes what the system currently supports
type SystemCapabilities struct {
	PIIDetection       bool `json:"pii_detection"`
	PIIAnonymization   bool `json:"pii_anonymization"`
	EncryptionAtRest   bool `json:"encryption_at_rest"`
	AuditLogging       bool `json:"audit_logging"`
	ConsentManagement  bool `json:"consent_management"`
	DataRetention      bool `json:"data_retention"`
	AccessControl      bool `json:"access_control"`
	PromptGuard        bool `json:"prompt_guard"`
	OutputGuardrails   bool `json:"output_guardrails"`
	SkillAuditing      bool `json:"skill_auditing"`
	RateLimiting       bool `json:"rate_limiting"`
	TLSEncryption      bool `json:"tls_encryption"`
	DataLocalization   bool `json:"data_localization"`   // Data stays in-country
	RightToErasure     bool `json:"right_to_erasure"`    // GDPR Art.17
	DataPortability    bool `json:"data_portability"`     // GDPR Art.20
	HumanOversight     bool `json:"human_oversight"`      // EU AI Act
	TransparencyReport bool `json:"transparency_report"`  // EU AI Act
}

// Checker validates system compliance against regulatory frameworks
type Checker struct {
	requirements []Requirement
}

// NewChecker creates a compliance checker with all known requirements
func NewChecker() *Checker {
	var reqs []Requirement
	reqs = append(reqs, vietnamAIRequirements()...)
	reqs = append(reqs, euAIRequirements()...)
	reqs = append(reqs, gdprRequirements()...)
	return &Checker{requirements: reqs}
}

// NewCheckerForFrameworks creates a checker for specific frameworks only
func NewCheckerForFrameworks(frameworks ...Framework) *Checker {
	var reqs []Requirement
	fwSet := make(map[Framework]bool)
	for _, fw := range frameworks {
		fwSet[fw] = true
	}

	all := append(vietnamAIRequirements(), euAIRequirements()...)
	all = append(all, gdprRequirements()...)

	for _, r := range all {
		if fwSet[r.Framework] {
			reqs = append(reqs, r)
		}
	}
	return &Checker{requirements: reqs}
}

// Check evaluates system capabilities against all requirements
func (c *Checker) Check(caps SystemCapabilities) ComplianceReport {
	var results []CheckResult
	var frameworks []Framework
	fwSeen := make(map[Framework]bool)

	for _, req := range c.requirements {
		result := evaluateRequirement(req, caps)
		results = append(results, result)
		if !fwSeen[req.Framework] {
			fwSeen[req.Framework] = true
			frameworks = append(frameworks, req.Framework)
		}
	}

	score := calculateComplianceScore(results)
	recommendations := generateRecommendations(results)

	return ComplianceReport{
		GeneratedAt:     time.Now(),
		Frameworks:      frameworks,
		Results:         results,
		OverallScore:    score,
		Summary:         buildComplianceSummary(results, score),
		Recommendations: recommendations,
	}
}

func evaluateRequirement(req Requirement, caps SystemCapabilities) CheckResult {
	result := CheckResult{
		Requirement: req,
	}

	switch req.ID {
	// Vietnam AI Law
	case "VN-AI-01":
		result.Status = boolStatus(caps.PIIDetection && caps.PIIAnonymization)
		result.Details = "Phát hiện & ẩn danh hóa dữ liệu cá nhân"
		if caps.PIIDetection {
			result.Evidence = append(result.Evidence, "PII detection enabled")
		}
		if caps.PIIAnonymization {
			result.Evidence = append(result.Evidence, "PII anonymization enabled")
		}
	case "VN-AI-02":
		result.Status = boolStatus(caps.ConsentManagement)
		result.Details = "Cơ chế đồng ý người dùng"
	case "VN-AI-03":
		result.Status = boolStatus(caps.AuditLogging)
		result.Details = "Nhật ký kiểm toán có cấu trúc"
		if caps.AuditLogging {
			result.Evidence = append(result.Evidence, "Structured audit logging enabled")
		}
	case "VN-AI-04":
		result.Status = boolStatus(caps.DataLocalization)
		result.Details = "Dữ liệu lưu trữ trong lãnh thổ Việt Nam"
	case "VN-AI-05":
		result.Status = boolStatus(caps.SkillAuditing)
		result.Details = "Kiểm toán skill.md cho AI agents"
		if caps.SkillAuditing {
			result.Evidence = append(result.Evidence, "Skill auditing V2 enabled")
		}
	case "VN-AI-06":
		result.Status = boolStatus(caps.EncryptionAtRest && caps.TLSEncryption)
		result.Details = "Mã hóa dữ liệu tại chỗ và truyền tải"
		if caps.EncryptionAtRest {
			result.Evidence = append(result.Evidence, "AES-256-GCM encryption at rest")
		}
		if caps.TLSEncryption {
			result.Evidence = append(result.Evidence, "TLS encryption in transit")
		}
	case "VN-AI-07":
		result.Status = boolStatus(caps.AccessControl)
		result.Details = "Kiểm soát truy cập theo vai trò"
		if caps.AccessControl {
			result.Evidence = append(result.Evidence, "Role-based access control enabled")
		}

	// EU AI Act
	case "EU-AI-01":
		result.Status = boolStatus(caps.SkillAuditing)
		result.Details = "Risk assessment for AI systems"
	case "EU-AI-02":
		result.Status = boolStatus(caps.HumanOversight)
		result.Details = "Human oversight capabilities"
	case "EU-AI-03":
		result.Status = boolStatus(caps.TransparencyReport)
		result.Details = "Transparency and documentation"
	case "EU-AI-04":
		result.Status = boolStatus(caps.AuditLogging)
		result.Details = "Record-keeping of AI operations"
	case "EU-AI-05":
		result.Status = boolStatus(caps.PromptGuard && caps.OutputGuardrails)
		result.Details = "Accuracy, robustness and cybersecurity"
		if caps.PromptGuard {
			result.Evidence = append(result.Evidence, "Prompt injection protection")
		}
		if caps.OutputGuardrails {
			result.Evidence = append(result.Evidence, "Output guardrails")
		}

	// GDPR
	case "GDPR-01":
		result.Status = boolStatus(caps.PIIDetection && caps.PIIAnonymization)
		result.Details = "Data minimization (Art. 5(1)(c))"
	case "GDPR-02":
		result.Status = boolStatus(caps.ConsentManagement)
		result.Details = "Lawful basis for processing (Art. 6)"
	case "GDPR-03":
		result.Status = boolStatus(caps.RightToErasure)
		result.Details = "Right to erasure (Art. 17)"
	case "GDPR-04":
		result.Status = boolStatus(caps.DataPortability)
		result.Details = "Data portability (Art. 20)"
	case "GDPR-05":
		result.Status = boolStatus(caps.EncryptionAtRest && caps.TLSEncryption)
		result.Details = "Security of processing (Art. 32)"
	case "GDPR-06":
		result.Status = boolStatus(caps.AuditLogging)
		result.Details = "Records of processing activities (Art. 30)"

	default:
		result.Status = StatusNotApplicable
		result.Details = "Unknown requirement"
	}

	return result
}

func boolStatus(met bool) ComplianceStatus {
	if met {
		return StatusCompliant
	}
	return StatusNonCompliant
}

func calculateComplianceScore(results []CheckResult) float64 {
	if len(results) == 0 {
		return 100
	}

	total := 0.0
	weight := 0.0

	for _, r := range results {
		w := requirementWeight(r.Requirement.Severity)
		weight += w
		switch r.Status {
		case StatusCompliant:
			total += w
		case StatusPartial:
			total += w * 0.5
		}
	}

	if weight == 0 {
		return 100
	}
	return (total / weight) * 100
}

func requirementWeight(severity string) float64 {
	switch severity {
	case "mandatory":
		return 3.0
	case "recommended":
		return 2.0
	case "optional":
		return 1.0
	default:
		return 1.0
	}
}

func buildComplianceSummary(results []CheckResult, score float64) string {
	compliant, nonCompliant, partial := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case StatusCompliant:
			compliant++
		case StatusNonCompliant:
			nonCompliant++
		case StatusPartial:
			partial++
		}
	}

	return fmt.Sprintf(
		"Đánh giá tuân thủ: %.0f/100. Đạt: %d, Không đạt: %d, Một phần: %d trên tổng %d yêu cầu.",
		score, compliant, nonCompliant, partial, len(results),
	)
}

func generateRecommendations(results []CheckResult) []string {
	var recs []string
	for _, r := range results {
		if r.Status == StatusNonCompliant && r.Requirement.Severity == "mandatory" {
			recs = append(recs, fmt.Sprintf("[%s] %s: %s",
				r.Requirement.ID, r.Requirement.Title, r.Requirement.Description))
		}
	}
	return recs
}

// ReportJSON returns the report as formatted JSON
func (r ComplianceReport) ReportJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ReportHTML returns a formatted HTML compliance report
func (r ComplianceReport) ReportHTML() string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Agent Veil Compliance Report</title>")
	sb.WriteString("<style>body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}")
	sb.WriteString(".compliant{color:#16a34a}.non_compliant{color:#dc2626}.partial{color:#ca8a04}")
	sb.WriteString("table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}")
	sb.WriteString(".score{font-size:2em;font-weight:bold}")
	sb.WriteString("</style></head><body>")

	sb.WriteString("<h1>Agent Veil Compliance Report</h1>")
	sb.WriteString(fmt.Sprintf("<p class='score'>%.0f/100</p>", r.OverallScore))
	sb.WriteString(fmt.Sprintf("<p>%s</p>", r.Summary))
	sb.WriteString(fmt.Sprintf("<p><em>Generated: %s</em></p>", r.GeneratedAt.Format("2006-01-02 15:04:05")))

	// Group by framework
	grouped := make(map[Framework][]CheckResult)
	for _, result := range r.Results {
		fw := result.Requirement.Framework
		grouped[fw] = append(grouped[fw], result)
	}

	for _, fw := range r.Frameworks {
		results := grouped[fw]
		sb.WriteString(fmt.Sprintf("<h2>%s</h2>", frameworkName(fw)))
		sb.WriteString("<table><tr><th>ID</th><th>Article</th><th>Requirement</th><th>Status</th><th>Details</th></tr>")
		for _, cr := range results {
			statusClass := string(cr.Status)
			statusLabel := statusDisplayName(cr.Status)
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td></tr>",
				cr.Requirement.ID, cr.Requirement.Article, cr.Requirement.Title,
				statusClass, statusLabel, cr.Details))
		}
		sb.WriteString("</table>")
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString("<h2>Khuyến nghị</h2><ul>")
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("<li>%s</li>", rec))
		}
		sb.WriteString("</ul>")
	}

	sb.WriteString("</body></html>")
	return sb.String()
}

func frameworkName(fw Framework) string {
	switch fw {
	case FrameworkVietnamAI:
		return "Luật AI Việt Nam 2026"
	case FrameworkEUAI:
		return "EU AI Act"
	case FrameworkGDPR:
		return "GDPR"
	default:
		return string(fw)
	}
}

func statusDisplayName(s ComplianceStatus) string {
	switch s {
	case StatusCompliant:
		return "Đạt"
	case StatusNonCompliant:
		return "Không đạt"
	case StatusPartial:
		return "Một phần"
	case StatusNotApplicable:
		return "N/A"
	default:
		return string(s)
	}
}

// === Regulatory Requirements Definitions ===

func vietnamAIRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "VN-AI-01",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 12",
			Title:       "Bảo vệ dữ liệu cá nhân",
			Description: "Hệ thống AI phải phát hiện và ẩn danh hóa dữ liệu cá nhân trước khi xử lý",
			Category:    "data_protection",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-02",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 15",
			Title:       "Đồng ý của chủ thể dữ liệu",
			Description: "Thu thập và xử lý dữ liệu cá nhân phải có sự đồng ý của chủ thể",
			Category:    "consent",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-03",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 20",
			Title:       "Nhật ký hoạt động AI",
			Description: "Ghi nhận đầy đủ nhật ký hoạt động của hệ thống AI để kiểm toán",
			Category:    "audit",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-04",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 26",
			Title:       "Lưu trữ dữ liệu trong nước",
			Description: "Dữ liệu cá nhân công dân Việt Nam phải được lưu trữ trong lãnh thổ Việt Nam",
			Category:    "data_localization",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-05",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 30",
			Title:       "Đánh giá rủi ro AI",
			Description: "Hệ thống AI phải được đánh giá và phân loại mức độ rủi ro",
			Category:    "risk_assessment",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-06",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 35",
			Title:       "An ninh dữ liệu",
			Description: "Mã hóa dữ liệu tại chỗ và trong quá trình truyền tải",
			Category:    "security",
			Severity:    "mandatory",
		},
		{
			ID:          "VN-AI-07",
			Framework:   FrameworkVietnamAI,
			Article:     "Điều 38",
			Title:       "Kiểm soát truy cập",
			Description: "Phân quyền truy cập dựa trên vai trò và nguyên tắc tối thiểu quyền",
			Category:    "access_control",
			Severity:    "mandatory",
		},
	}
}

func euAIRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "EU-AI-01",
			Framework:   FrameworkEUAI,
			Article:     "Art. 9",
			Title:       "Risk Management System",
			Description: "Establish and maintain a risk management system for high-risk AI",
			Category:    "risk_management",
			Severity:    "mandatory",
		},
		{
			ID:          "EU-AI-02",
			Framework:   FrameworkEUAI,
			Article:     "Art. 14",
			Title:       "Human Oversight",
			Description: "Ensure appropriate human oversight measures for AI systems",
			Category:    "oversight",
			Severity:    "mandatory",
		},
		{
			ID:          "EU-AI-03",
			Framework:   FrameworkEUAI,
			Article:     "Art. 13",
			Title:       "Transparency",
			Description: "AI systems must be designed to enable transparency and explainability",
			Category:    "transparency",
			Severity:    "mandatory",
		},
		{
			ID:          "EU-AI-04",
			Framework:   FrameworkEUAI,
			Article:     "Art. 12",
			Title:       "Record-keeping",
			Description: "Maintain logs of AI system operations for traceability",
			Category:    "audit",
			Severity:    "mandatory",
		},
		{
			ID:          "EU-AI-05",
			Framework:   FrameworkEUAI,
			Article:     "Art. 15",
			Title:       "Accuracy and Robustness",
			Description: "Ensure AI systems achieve appropriate levels of accuracy, robustness and cybersecurity",
			Category:    "security",
			Severity:    "mandatory",
		},
	}
}

func gdprRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "GDPR-01",
			Framework:   FrameworkGDPR,
			Article:     "Art. 5(1)(c)",
			Title:       "Data Minimization",
			Description: "Process only data that is necessary for the purpose",
			Category:    "data_protection",
			Severity:    "mandatory",
		},
		{
			ID:          "GDPR-02",
			Framework:   FrameworkGDPR,
			Article:     "Art. 6",
			Title:       "Lawful Basis for Processing",
			Description: "Ensure lawful basis for data processing, including consent",
			Category:    "consent",
			Severity:    "mandatory",
		},
		{
			ID:          "GDPR-03",
			Framework:   FrameworkGDPR,
			Article:     "Art. 17",
			Title:       "Right to Erasure",
			Description: "Data subjects have the right to have their data erased",
			Category:    "data_rights",
			Severity:    "mandatory",
		},
		{
			ID:          "GDPR-04",
			Framework:   FrameworkGDPR,
			Article:     "Art. 20",
			Title:       "Data Portability",
			Description: "Data subjects have the right to receive their data in portable format",
			Category:    "data_rights",
			Severity:    "recommended",
		},
		{
			ID:          "GDPR-05",
			Framework:   FrameworkGDPR,
			Article:     "Art. 32",
			Title:       "Security of Processing",
			Description: "Implement appropriate technical and organizational security measures",
			Category:    "security",
			Severity:    "mandatory",
		},
		{
			ID:          "GDPR-06",
			Framework:   FrameworkGDPR,
			Article:     "Art. 30",
			Title:       "Records of Processing",
			Description: "Maintain records of processing activities",
			Category:    "audit",
			Severity:    "mandatory",
		},
	}
}
