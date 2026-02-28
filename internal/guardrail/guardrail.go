package guardrail

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Policy defines runtime safety constraints for AI agent requests
type Policy struct {
	MaxOutputTokens     int            `json:"max_output_tokens"`      // 0 = unlimited
	MaxRequestsPerMin   int            `json:"max_requests_per_min"`   // per-session rate limit
	BlockHarmfulContent bool           `json:"block_harmful_content"`  // scan output for harmful patterns
	BlockPIIInOutput    bool           `json:"block_pii_in_output"`    // block PII leaking in LLM responses
	AllowedTopics       []string       `json:"allowed_topics"`         // empty = all allowed
	BlockedTopics       []string       `json:"blocked_topics"`         // topics to block
	MaxSessionDuration  time.Duration  `json:"max_session_duration"`   // 0 = unlimited
	CustomRules         []ContentRule  `json:"custom_rules,omitempty"` // user-defined rules
}

// DefaultPolicy returns a sensible default policy
func DefaultPolicy() Policy {
	return Policy{
		MaxOutputTokens:     4096,
		MaxRequestsPerMin:   60,
		BlockHarmfulContent: true,
		BlockPIIInOutput:    true,
	}
}

// ContentRule defines a custom content filtering rule
type ContentRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`      // "block", "warn", "redact"
	Description string `json:"description"`
	Severity    string `json:"severity"`     // "low", "medium", "high", "critical"
}

// Violation represents a guardrail violation
type Violation struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Action      string `json:"action"` // "blocked", "warned", "redacted"
	Snippet     string `json:"snippet,omitempty"`
}

// CheckResult is the result of a guardrail check
type CheckResult struct {
	Allowed    bool        `json:"allowed"`
	Violations []Violation `json:"violations,omitempty"`
}

// Guardrail enforces runtime safety policies
type Guardrail struct {
	policy          Policy
	harmfulPatterns []harmfulPattern
	customCompiled  []compiledRule
	sessionTracker  *SessionTracker
}

type harmfulPattern struct {
	Pattern     *regexp.Regexp
	Category    string
	Description string
	Severity    string
}

type compiledRule struct {
	Rule    ContentRule
	Pattern *regexp.Regexp
}

// New creates a Guardrail with the given policy
func New(policy Policy) *Guardrail {
	g := &Guardrail{
		policy:          policy,
		harmfulPatterns: defaultHarmfulPatterns(),
		sessionTracker:  NewSessionTracker(),
	}

	// Compile custom rules
	for _, rule := range policy.CustomRules {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		g.customCompiled = append(g.customCompiled, compiledRule{
			Rule:    rule,
			Pattern: compiled,
		})
	}

	return g
}

// CheckOutput validates LLM output against the policy
func (g *Guardrail) CheckOutput(output string) CheckResult {
	var violations []Violation

	// 1. Token limit check (approximate: 1 token ≈ 4 chars)
	if g.policy.MaxOutputTokens > 0 {
		approxTokens := len(output) / 4
		if approxTokens > g.policy.MaxOutputTokens {
			violations = append(violations, Violation{
				Rule:        "max_output_tokens",
				Severity:    "high",
				Description: fmt.Sprintf("Output exceeds token limit: ~%d tokens (max: %d)", approxTokens, g.policy.MaxOutputTokens),
				Action:      "blocked",
			})
		}
	}

	// 2. Harmful content check
	if g.policy.BlockHarmfulContent {
		for _, hp := range g.harmfulPatterns {
			if hp.Pattern.MatchString(strings.ToLower(output)) {
				snippet := extractMatch(output, hp.Pattern, 80)
				violations = append(violations, Violation{
					Rule:        "harmful_content:" + hp.Category,
					Severity:    hp.Severity,
					Description: hp.Description,
					Action:      "blocked",
					Snippet:     snippet,
				})
			}
		}
	}

	// 3. Blocked topics
	lower := strings.ToLower(output)
	for _, topic := range g.policy.BlockedTopics {
		if strings.Contains(lower, strings.ToLower(topic)) {
			violations = append(violations, Violation{
				Rule:        "blocked_topic",
				Severity:    "medium",
				Description: fmt.Sprintf("Output contains blocked topic: %s", topic),
				Action:      "blocked",
			})
		}
	}

	// 4. Custom rules
	for _, cr := range g.customCompiled {
		if cr.Pattern.MatchString(output) {
			snippet := extractMatch(output, cr.Pattern, 80)
			violations = append(violations, Violation{
				Rule:        "custom:" + cr.Rule.ID,
				Severity:    cr.Rule.Severity,
				Description: cr.Rule.Description,
				Action:      cr.Rule.Action,
				Snippet:     snippet,
			})
		}
	}

	// Determine if blocked
	blocked := false
	for _, v := range violations {
		if v.Action == "blocked" {
			blocked = true
			break
		}
	}

	return CheckResult{
		Allowed:    !blocked,
		Violations: violations,
	}
}

// CheckRateLimit checks if a session has exceeded its rate limit
func (g *Guardrail) CheckRateLimit(sessionID string) CheckResult {
	if g.policy.MaxRequestsPerMin <= 0 {
		return CheckResult{Allowed: true}
	}

	allowed := g.sessionTracker.RecordRequest(sessionID, g.policy.MaxRequestsPerMin)
	if !allowed {
		return CheckResult{
			Allowed: false,
			Violations: []Violation{{
				Rule:        "session_rate_limit",
				Severity:    "high",
				Description: fmt.Sprintf("Session %s exceeded %d requests/min", sessionID, g.policy.MaxRequestsPerMin),
				Action:      "blocked",
			}},
		}
	}
	return CheckResult{Allowed: true}
}

// TruncateOutput truncates output to the token limit if set
func (g *Guardrail) TruncateOutput(output string) string {
	if g.policy.MaxOutputTokens <= 0 {
		return output
	}
	maxChars := g.policy.MaxOutputTokens * 4
	if len(output) <= maxChars {
		return output
	}
	return output[:maxChars] + "\n\n[Output truncated by Vura guardrail]"
}

func extractMatch(text string, pattern *regexp.Regexp, maxLen int) string {
	loc := pattern.FindStringIndex(strings.ToLower(text))
	if loc == nil {
		return ""
	}
	start := loc[0]
	end := loc[1]
	if start > 10 {
		start -= 10
	} else {
		start = 0
	}
	if end+10 < len(text) {
		end += 10
	} else {
		end = len(text)
	}
	s := text[start:end]
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func defaultHarmfulPatterns() []harmfulPattern {
	return []harmfulPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)(?:how\s+to\s+(?:make|build|create|synthesize)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison|drug|meth))`),
			Category:    "dangerous_instructions",
			Description: "Hướng dẫn tạo vật phẩm nguy hiểm",
			Severity:    "critical",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:(?:kill|harm|attack|assault|murder)\s+(?:yourself|himself|herself|themselves|someone|people|a\s+person))`),
			Category:    "violence",
			Description: "Nội dung bạo lực / gây hại",
			Severity:    "critical",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:(?:hack|exploit|attack|breach|compromise)\s+(?:the|a|this)?\s*(?:server|system|network|database|website|account))`),
			Category:    "cyber_attack",
			Description: "Hướng dẫn tấn công mạng",
			Severity:    "high",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:(?:steal|phish|harvest)\s+(?:password|credential|credit\s*card|identity|personal\s+data))`),
			Category:    "theft_instructions",
			Description: "Hướng dẫn đánh cắp thông tin",
			Severity:    "critical",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(?:self[- ]?harm|su[i!]c[i!]de\s+(?:method|way|how))`),
			Category:    "self_harm",
			Description: "Nội dung tự gây hại",
			Severity:    "critical",
		},
	}
}

// === Session Rate Tracking ===

// SessionTracker tracks per-session request rates
type SessionTracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionWindow
}

type sessionWindow struct {
	timestamps []time.Time
}

// NewSessionTracker creates a new tracker
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions: make(map[string]*sessionWindow),
	}
}

// RecordRequest records a request and returns true if within limit
func (st *SessionTracker) RecordRequest(sessionID string, maxPerMin int) bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	window, ok := st.sessions[sessionID]
	if !ok {
		window = &sessionWindow{}
		st.sessions[sessionID] = window
	}

	// Remove timestamps older than 1 minute
	cutoff := now.Add(-time.Minute)
	valid := window.timestamps[:0]
	for _, ts := range window.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	window.timestamps = valid

	if len(window.timestamps) >= maxPerMin {
		return false
	}

	window.timestamps = append(window.timestamps, now)
	return true
}

// Cleanup removes expired sessions
func (st *SessionTracker) Cleanup() {
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for id, w := range st.sessions {
		if len(w.timestamps) == 0 {
			delete(st.sessions, id)
			continue
		}
		// If the newest timestamp is old, remove the session
		if w.timestamps[len(w.timestamps)-1].Before(cutoff) {
			delete(st.sessions, id)
		}
	}
}
