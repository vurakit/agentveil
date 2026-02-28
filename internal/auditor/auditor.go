package auditor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Risk levels per Vietnam AI Law 2026 (4 levels)
const (
	RiskMinimal      = 1 // Rủi ro tối thiểu
	RiskLimited      = 2 // Rủi ro hạn chế
	RiskHigh         = 3 // Rủi ro cao
	RiskUnacceptable = 4 // Rủi ro không chấp nhận được
)

// RiskLevelName maps numeric level to Vietnamese label
var RiskLevelName = map[int]string{
	RiskMinimal:      "Tối thiểu",
	RiskLimited:      "Hạn chế",
	RiskHigh:         "Cao",
	RiskUnacceptable: "Không chấp nhận được",
}

// Finding represents a single security issue found in a skill.md
type Finding struct {
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Snippet     string `json:"snippet"`
}

// Report is the complete audit result
type Report struct {
	Findings       []Finding      `json:"findings"`
	BehaviorChains []ChainFinding `json:"behavior_chains,omitempty"`
	RiskLevel      int            `json:"risk_level"`
	RiskLevelLabel string         `json:"risk_level_label"`
	Score          float64        `json:"compliance_score"`
	Summary        string         `json:"summary"`
	Sections       []string       `json:"sections,omitempty"`
}

// ReportJSON returns the report as formatted JSON bytes
func (r Report) ReportJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ReportHTML returns a simple HTML report
func (r Report) ReportHTML() string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Agent Veil Audit Report</title>")
	sb.WriteString("<style>body{font-family:sans-serif;max-width:800px;margin:0 auto;padding:20px}")
	sb.WriteString(".critical{color:#dc2626}.high{color:#ea580c}.medium{color:#ca8a04}.low{color:#16a34a}")
	sb.WriteString("table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}")
	sb.WriteString("</style></head><body>")

	sb.WriteString(fmt.Sprintf("<h1>Agent Veil Audit Report</h1>"))
	sb.WriteString(fmt.Sprintf("<p><strong>Risk Level:</strong> <span class='%s'>%s</span></p>",
		strings.ToLower(r.RiskLevelLabel), r.RiskLevelLabel))
	sb.WriteString(fmt.Sprintf("<p><strong>Compliance Score:</strong> %.1f/100</p>", r.Score))
	sb.WriteString(fmt.Sprintf("<p>%s</p>", r.Summary))

	if len(r.Findings) > 0 {
		sb.WriteString("<h2>Findings</h2><table><tr><th>Line</th><th>Severity</th><th>Category</th><th>Description</th></tr>")
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td class='%s'>%s</td><td>%s</td><td>%s</td></tr>",
				f.Line, f.Severity, f.Severity, f.Category, f.Description))
		}
		sb.WriteString("</table>")
	}

	if len(r.BehaviorChains) > 0 {
		sb.WriteString("<h2>Behavior Chains</h2><ul>")
		for _, bc := range r.BehaviorChains {
			sb.WriteString(fmt.Sprintf("<li class='%s'><strong>%s</strong>: %s (weight: %d)</li>",
				bc.Chain.Severity, bc.Chain.Name, bc.Chain.Description, bc.Chain.Weight))
		}
		sb.WriteString("</ul>")
	}

	sb.WriteString("</body></html>")
	return sb.String()
}

// dangerousPattern defines a regex and its associated risk
type dangerousPattern struct {
	Pattern     *regexp.Regexp
	Severity    string
	Category    string
	Description string
	Weight      int
}

// Auditor analyzes skill.md files for security compliance
type Auditor struct {
	patterns       []dangerousPattern
	enableEvasion  bool
	enableBehavior bool
}

// New creates an Auditor with built-in security rules and V2 features
func New() *Auditor {
	return &Auditor{
		patterns:       defaultPatterns(),
		enableEvasion:  true,
		enableBehavior: true,
	}
}

// NewWithCustomRules creates an Auditor merging built-in + custom rules
func NewWithCustomRules(customYAML string) (*Auditor, error) {
	cfg, err := ParseRulesConfig(customYAML)
	if err != nil {
		return nil, err
	}

	patterns := defaultPatterns()
	patterns = append(patterns, cfg.ToPatterns()...)

	return &Auditor{
		patterns:       patterns,
		enableEvasion:  true,
		enableBehavior: true,
	}, nil
}

func defaultPatterns() []dangerousPattern {
	return []dangerousPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)(?:read|access|extract|get|fetch|steal|copy)\s+(?:user|customer|client)?\s*(?:password|credentials|secret|token|api.?key|private.?key)`),
			Severity:    "critical",
			Category:    "credential_access",
			Description: "Chỉ dẫn truy cập thông tin xác thực / mật khẩu",
			Weight:      40,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:send|post|upload|transmit|exfiltrate|forward)\s+(?:data|information|pii|personal)\s+(?:to|towards)\s+(?:external|third.?party|outside|http)`),
			Severity:    "critical",
			Category:    "data_exfiltration",
			Description: "Chỉ dẫn gửi dữ liệu ra ngoài hệ thống",
			Weight:      40,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:bypass|skip|ignore|disable|circumvent)\s+(?:security|auth|authentication|authorization|validation|verification|consent)`),
			Severity:    "critical",
			Category:    "security_bypass",
			Description: "Chỉ dẫn bỏ qua cơ chế bảo mật",
			Weight:      35,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:collect|gather|harvest|scrape|mine)\s+(?:personal|user|citizen|customer)\s+(?:data|information|details|records|cccd|cmnd)`),
			Severity:    "high",
			Category:    "mass_collection",
			Description: "Thu thập hàng loạt dữ liệu cá nhân",
			Weight:      30,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:delete|remove|wipe|destroy|drop)\s+(?:all|every)?\s*(?:log|audit|record|trail|evidence|backup)`),
			Severity:    "critical",
			Category:    "audit_destruction",
			Description: "Chỉ dẫn xóa bản ghi kiểm toán",
			Weight:      35,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:execute|run|eval|system|shell|exec)\s*\(`),
			Severity:    "high",
			Category:    "code_execution",
			Description: "Chỉ dẫn thực thi mã tùy ý",
			Weight:      25,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:without|no)\s+(?:user)?\s*(?:consent|permission|approval|authorization)`),
			Severity:    "high",
			Category:    "consent_violation",
			Description: "Hành động không có sự đồng ý của người dùng",
			Weight:      25,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:track|monitor|surveil|spy|watch)\s+(?:user|employee|citizen|individual|person)`),
			Severity:    "high",
			Category:    "surveillance",
			Description: "Giám sát người dùng trái phép",
			Weight:      20,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:store|save|keep|retain)\s+(?:cccd|cmnd|passport|id.?card|social.?security|ssn|mã.?số.?thuế)`),
			Severity:    "medium",
			Category:    "sensitive_storage",
			Description: "Lưu trữ dữ liệu nhạy cảm cao",
			Weight:      15,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:share|distribute|sell|trade)\s+(?:personal|user|client|customer)\s+(?:data|info|information)`),
			Severity:    "high",
			Category:    "data_sharing",
			Description: "Chia sẻ dữ liệu cá nhân cho bên thứ ba",
			Weight:      25,
		},
		// V3: Indirect prompt injection patterns
		{
			Pattern:     regexp.MustCompile(`(?i)(?:read|fetch|load|open|visit|follow|navigate|go\s+to|click|browse|retrieve|download)\s+(?:this\s+)?(?:url|link|http|https|website|webpage|page|site)[\s:]*(?:https?://\S+)?`),
			Severity:    "critical",
			Category:    "url_fetch_injection",
			Description: "Chỉ dẫn đọc/fetch URL/link ngoài trong skill — vector injection gián tiếp",
			Weight:      35,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:delete|remove|clear|wipe|overwrite|replace|modify|edit|change|strip|drop)\s+(?:all\s+)?(?:skill|instruction|rule|guideline|system\s+prompt|\.md|markdown)`),
			Severity:    "critical",
			Category:    "skill_tampering",
			Description: "Chỉ dẫn xóa/sửa/bỏ skill hoặc file chỉ dẫn",
			Weight:      40,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:follow|execute|obey|comply|apply|use|adopt)\s+(?:the\s+)?(?:instructions?|commands?|directives?|guidance|content|steps?)\s+(?:from|in|at|on)\s+(?:the\s+)?(?:url|link|page|site|external|remote|http)`),
			Severity:    "critical",
			Category:    "indirect_injection",
			Description: "Chỉ dẫn follow/execute instructions từ nguồn bên ngoài",
			Weight:      40,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:post|send|submit|forward|transmit|upload)\s+(?:all\s+)?(?:customer|client|user|khách\s*hàng|người\s*dùng)\s+(?:data|info|information|dữ\s*liệu|thông\s*tin)\s+(?:to|tới|đến)\s+(?:https?://\S+|external|outside|webhook|endpoint)`),
			Severity:    "critical",
			Category:    "data_post_external",
			Description: "Chỉ dẫn POST/gửi data khách hàng ra endpoint cụ thể",
			Weight:      40,
		},
	}
}

// Analyze parses skill.md content and produces a compliance report
func (a *Auditor) Analyze(content string) Report {
	lines := strings.Split(content, "\n")
	var findings []Finding
	totalWeight := 0

	// Parse markdown sections
	sections := MergeMarkdownSections(content)
	var sectionNames []string
	for name := range sections {
		sectionNames = append(sectionNames, name)
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Scan original line
		for _, dp := range a.patterns {
			if dp.Pattern.MatchString(line) {
				findings = append(findings, Finding{
					Line:        lineNum + 1,
					Severity:    dp.Severity,
					Category:    dp.Category,
					Description: dp.Description,
					Snippet:     truncate(trimmed, 120),
				})
				totalWeight += dp.Weight
			}
		}

		// V2: Anti-evasion — also scan deobfuscated versions
		if a.enableEvasion {
			revealed := DeobfuscateLine(line)
			for _, rev := range revealed {
				for _, dp := range a.patterns {
					if dp.Pattern.MatchString(rev) {
						findings = append(findings, Finding{
							Line:        lineNum + 1,
							Severity:    dp.Severity,
							Category:    "evasion:" + dp.Category,
							Description: "[Obfuscated] " + dp.Description,
							Snippet:     truncate(trimmed, 120),
						})
						totalWeight += dp.Weight
					}
				}
			}
		}
	}

	// V2: Behavior chain analysis
	var chainFindings []ChainFinding
	if a.enableBehavior {
		chainFindings = AnalyzeBehaviorChains(content)
		for _, cf := range chainFindings {
			totalWeight += cf.Chain.Weight
			findings = append(findings, Finding{
				Line:        cf.Actions[0].Line,
				Severity:    cf.Chain.Severity,
				Category:    "behavior:" + cf.Chain.Name,
				Description: cf.Chain.Description,
				Snippet:     fmt.Sprintf("Chain: %v", cf.Actions),
			})
		}
	}

	// Calculate compliance score
	score := 100.0 - float64(totalWeight)
	if score < 0 {
		score = 0
	}

	riskLevel := calculateRiskLevel(score, findings)

	return Report{
		Findings:       findings,
		BehaviorChains: chainFindings,
		RiskLevel:      riskLevel,
		RiskLevelLabel: RiskLevelName[riskLevel],
		Score:          score,
		Summary:        buildSummary(findings, riskLevel),
		Sections:       sectionNames,
	}
}

func calculateRiskLevel(score float64, findings []Finding) int {
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
			break
		}
	}

	if hasCritical && score < 30 {
		return RiskUnacceptable
	}
	if hasCritical || score < 40 {
		return RiskHigh
	}
	if score < 70 {
		return RiskLimited
	}
	return RiskMinimal
}

func buildSummary(findings []Finding, riskLevel int) string {
	if len(findings) == 0 {
		return "Skill.md tuân thủ tốt. Không phát hiện chỉ dẫn nguy hiểm."
	}

	var sb strings.Builder
	sb.WriteString("Phát hiện ")

	critical, high, medium := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}

	var parts []string
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d vấn đề nghiêm trọng", critical))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("%d vấn đề cao", high))
	}
	if medium > 0 {
		parts = append(parts, fmt.Sprintf("%d vấn đề trung bình", medium))
	}

	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(". Mức rủi ro: ")
	sb.WriteString(RiskLevelName[riskLevel])
	sb.WriteString(".")

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
