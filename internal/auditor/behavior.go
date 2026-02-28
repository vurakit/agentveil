package auditor

import (
	"regexp"
	"strings"
)

// BehaviorChain detects dangerous sequences of actions in skill.md.
// For example: "read file" + "send HTTP" = data exfiltration pattern.

// ActionType represents a single agent action
type ActionType string

const (
	ActionReadFile    ActionType = "read_file"
	ActionReadDB      ActionType = "read_database"
	ActionHTTPSend    ActionType = "http_send"
	ActionWriteFile   ActionType = "write_file"
	ActionDeleteFile  ActionType = "delete_file"
	ActionExecCode    ActionType = "exec_code"
	ActionAccessCreds ActionType = "access_creds"
	ActionFetchURL    ActionType = "fetch_url"
	ActionModifySkill ActionType = "modify_skill"
)

type actionPattern struct {
	Action  ActionType
	Pattern *regexp.Regexp
}

var actionPatterns = []actionPattern{
	{ActionReadFile, regexp.MustCompile(`(?i)(?:read|open|load|access|scan)\s+(?:file|document|config|env|\.env)`)},
	{ActionReadDB, regexp.MustCompile(`(?i)(?:query|select|read|access|dump)\s+(?:database|db|table|record|sql)`)},
	{ActionHTTPSend, regexp.MustCompile(`(?i)(?:send|post|put|upload|fetch|curl|wget|http|request)\s+(?:to|http|https|api|endpoint|url|webhook)`)},
	{ActionWriteFile, regexp.MustCompile(`(?i)(?:write|create|save|dump|export)\s+(?:file|log|output|csv|json)`)},
	{ActionDeleteFile, regexp.MustCompile(`(?i)(?:delete|remove|rm|unlink|wipe)\s+(?:file|log|record|data)`)},
	{ActionExecCode, regexp.MustCompile(`(?i)(?:execute|run|eval|spawn|shell|subprocess|os\.system|child_process)`)},
	{ActionAccessCreds, regexp.MustCompile(`(?i)(?:password|secret|token|api.?key|credential|private.?key|ssh.?key)`)},
	{ActionFetchURL, regexp.MustCompile(`(?i)(?:fetch|read|load|open|visit|follow|navigate|browse|retrieve|download)\s+(?:this\s+)?(?:url|link|https?://|website|page|site)`)},
	{ActionModifySkill, regexp.MustCompile(`(?i)(?:delete|remove|modify|clear|overwrite|replace|strip|drop|edit|change)\s+(?:all\s+)?(?:skill|instruction|rule|guideline|system.?prompt|\.md|markdown)`)},
}

// DangerousChain defines a sequence of actions that indicates a threat
type DangerousChain struct {
	Name        string
	Sequence    []ActionType
	Severity    string
	Description string
	Weight      int
}

var dangerousChains = []DangerousChain{
	{
		Name:        "data_exfiltration",
		Sequence:    []ActionType{ActionReadFile, ActionHTTPSend},
		Severity:    "critical",
		Description: "Đọc file rồi gửi HTTP = nghi ngờ rò rỉ dữ liệu",
		Weight:      35,
	},
	{
		Name:        "db_exfiltration",
		Sequence:    []ActionType{ActionReadDB, ActionHTTPSend},
		Severity:    "critical",
		Description: "Truy vấn DB rồi gửi HTTP = nghi ngờ rò rỉ CSDL",
		Weight:      40,
	},
	{
		Name:        "credential_theft",
		Sequence:    []ActionType{ActionAccessCreds, ActionHTTPSend},
		Severity:    "critical",
		Description: "Truy cập credentials rồi gửi ra ngoài",
		Weight:      45,
	},
	{
		Name:        "cover_tracks",
		Sequence:    []ActionType{ActionExecCode, ActionDeleteFile},
		Severity:    "critical",
		Description: "Thực thi mã rồi xóa file = xóa dấu vết",
		Weight:      35,
	},
	{
		Name:        "reverse_shell",
		Sequence:    []ActionType{ActionExecCode, ActionHTTPSend},
		Severity:    "critical",
		Description: "Thực thi mã + kết nối mạng = nghi ngờ reverse shell",
		Weight:      40,
	},
	// V3: Indirect prompt injection chains
	{
		Name:        "indirect_injection",
		Sequence:    []ActionType{ActionFetchURL, ActionModifySkill},
		Severity:    "critical",
		Description: "Đọc URL rồi sửa skill = injection gián tiếp",
		Weight:      45,
	},
	{
		Name:        "url_data_exfil",
		Sequence:    []ActionType{ActionFetchURL, ActionHTTPSend},
		Severity:    "critical",
		Description: "Đọc URL rồi gửi dữ liệu ra ngoài",
		Weight:      40,
	},
	{
		Name:        "skill_sabotage",
		Sequence:    []ActionType{ActionModifySkill, ActionHTTPSend},
		Severity:    "critical",
		Description: "Xóa skill rồi gửi dữ liệu = phá hoại + rò rỉ",
		Weight:      45,
	},
}

// DetectedAction records where an action was found
type DetectedAction struct {
	Action ActionType
	Line   int
}

// ChainFinding represents a detected dangerous behavior chain
type ChainFinding struct {
	Chain   DangerousChain
	Actions []DetectedAction
}

// AnalyzeBehaviorChains scans content for dangerous action sequences
func AnalyzeBehaviorChains(content string) []ChainFinding {
	lines := strings.Split(content, "\n")

	// Step 1: Find all actions in the document
	var detected []DetectedAction
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, ap := range actionPatterns {
			if ap.Pattern.MatchString(line) {
				detected = append(detected, DetectedAction{
					Action: ap.Action,
					Line:   lineNum + 1,
				})
			}
		}
	}

	if len(detected) < 2 {
		return nil
	}

	// Step 2: Check if any dangerous chain is present
	actionSet := make(map[ActionType][]int) // action -> lines
	for _, d := range detected {
		actionSet[d.Action] = append(actionSet[d.Action], d.Line)
	}

	var findings []ChainFinding
	for _, chain := range dangerousChains {
		matched := true
		var actions []DetectedAction
		for _, required := range chain.Sequence {
			if lines, ok := actionSet[required]; ok {
				actions = append(actions, DetectedAction{Action: required, Line: lines[0]})
			} else {
				matched = false
				break
			}
		}
		if matched {
			findings = append(findings, ChainFinding{
				Chain:   chain,
				Actions: actions,
			})
		}
	}

	return findings
}
