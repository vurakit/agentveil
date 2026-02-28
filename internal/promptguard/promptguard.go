package promptguard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ThreatLevel represents the severity of a prompt injection attempt
type ThreatLevel int

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

var threatLevelName = map[ThreatLevel]string{
	ThreatNone:     "none",
	ThreatLow:      "low",
	ThreatMedium:   "medium",
	ThreatHigh:     "high",
	ThreatCritical: "critical",
}

func (t ThreatLevel) String() string {
	if name, ok := threatLevelName[t]; ok {
		return name
	}
	return "unknown"
}

// Detection represents a single prompt injection detection
type Detection struct {
	Type        string      `json:"type"`
	Category    string      `json:"category"`
	Description string      `json:"description"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Snippet     string      `json:"snippet"`
	Score       float64     `json:"score"`
}

// ScanResult is the result of scanning input/output for prompt injection
type ScanResult struct {
	Safe        bool        `json:"safe"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Detections  []Detection `json:"detections,omitempty"`
	Score       float64     `json:"score"` // 0-100, higher = more dangerous
}

// injectionPattern defines a regex-based injection detection rule
type injectionPattern struct {
	Pattern     *regexp.Regexp
	Category    string
	Description string
	ThreatLevel ThreatLevel
	Weight      float64
}

// Guard is the main prompt injection protection engine
type Guard struct {
	inputPatterns  []injectionPattern
	outputPatterns []injectionPattern
	canaryStore    *CanaryStore
	blockThreshold ThreatLevel // block if threat >= this level
}

// Option configures Guard behavior
type Option func(*Guard)

// WithBlockThreshold sets the minimum threat level to block a request
func WithBlockThreshold(level ThreatLevel) Option {
	return func(g *Guard) {
		g.blockThreshold = level
	}
}

// New creates a Guard with default patterns
func New(opts ...Option) *Guard {
	g := &Guard{
		inputPatterns:  defaultInputPatterns(),
		outputPatterns: defaultOutputPatterns(),
		canaryStore:    NewCanaryStore(),
		blockThreshold: ThreatHigh,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// ScanInput analyzes user/agent input for prompt injection attempts
func (g *Guard) ScanInput(text string) ScanResult {
	return g.scan(text, g.inputPatterns)
}

// ScanOutput analyzes LLM output for leaked data or harmful content
func (g *Guard) ScanOutput(text string) ScanResult {
	return g.scan(text, g.outputPatterns)
}

// ShouldBlock returns true if the scan result warrants blocking
func (g *Guard) ShouldBlock(result ScanResult) bool {
	return result.ThreatLevel >= g.blockThreshold
}

func (g *Guard) scan(text string, patterns []injectionPattern) ScanResult {
	if text == "" {
		return ScanResult{Safe: true, ThreatLevel: ThreatNone, Score: 0}
	}

	lower := strings.ToLower(text)
	var detections []Detection
	totalWeight := 0.0
	maxThreat := ThreatNone

	for _, p := range patterns {
		if p.Pattern.MatchString(lower) {
			snippet := extractSnippet(text, p.Pattern, 80)
			detections = append(detections, Detection{
				Type:        "pattern",
				Category:    p.Category,
				Description: p.Description,
				ThreatLevel: p.ThreatLevel,
				Snippet:     snippet,
				Score:       p.Weight,
			})
			totalWeight += p.Weight
			if p.ThreatLevel > maxThreat {
				maxThreat = p.ThreatLevel
			}
		}
	}

	// Heuristic: multiple low-level detections escalate threat
	if len(detections) >= 3 && maxThreat < ThreatMedium {
		maxThreat = ThreatMedium
	}
	if len(detections) >= 5 && maxThreat < ThreatHigh {
		maxThreat = ThreatHigh
	}

	// Canary leak check
	if g.canaryStore != nil {
		if leaked := g.canaryStore.CheckLeaked(text); len(leaked) > 0 {
			for _, canary := range leaked {
				detections = append(detections, Detection{
					Type:        "canary_leak",
					Category:    "data_leak",
					Description: fmt.Sprintf("Canary token leaked: session %s", canary.SessionID),
					ThreatLevel: ThreatCritical,
					Snippet:     canary.Token,
					Score:       50,
				})
				totalWeight += 50
				maxThreat = ThreatCritical
			}
		}
	}

	score := totalWeight
	if score > 100 {
		score = 100
	}

	return ScanResult{
		Safe:        maxThreat == ThreatNone,
		ThreatLevel: maxThreat,
		Detections:  detections,
		Score:       score,
	}
}

func extractSnippet(text string, pattern *regexp.Regexp, maxLen int) string {
	loc := pattern.FindStringIndex(strings.ToLower(text))
	if loc == nil {
		return truncateStr(text, maxLen)
	}
	start := loc[0]
	end := loc[1]
	// Expand to include context
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
	return truncateStr(text[start:end], maxLen)
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// === Input Injection Patterns ===

func defaultInputPatterns() []injectionPattern {
	return []injectionPattern{
		// Direct instruction override
		{
			Pattern:     regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:your\s+|the\s+|my\s+)?(?:previous|prior|above|earlier|original|system)\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?)`),
			Category:    "instruction_override",
			Description: "Cố gắng ghi đè chỉ dẫn hệ thống",
			ThreatLevel: ThreatCritical,
			Weight:      40,
		},
		// System prompt extraction
		{
			Pattern:     regexp.MustCompile(`(?i)(?:show|display|reveal|print|output|repeat|tell)\s+(?:me\s+)?(?:your|the)?\s*(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?))|(?i)what\s+(?:are|is)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)`),
			Category:    "prompt_extraction",
			Description: "Cố gắng trích xuất system prompt",
			ThreatLevel: ThreatHigh,
			Weight:      30,
		},
		// Role-play jailbreak
		{
			Pattern:     regexp.MustCompile(`(?i)(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|from\s+now\s+on\s+you\s+are|imagine\s+you\s+are)\s+(?:(?:a|an)\s+)?(?:different|new|unrestricted|unfiltered|evil|malicious|DAN|jailbroken)`),
			Category:    "jailbreak_roleplay",
			Description: "Tấn công jailbreak qua role-play",
			ThreatLevel: ThreatCritical,
			Weight:      40,
		},
		// DAN / Do Anything Now
		{
			Pattern:     regexp.MustCompile(`(?i)\b(?:DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|sudo\s+mode|admin\s+mode|unrestricted\s+mode)\b`),
			Category:    "jailbreak_dan",
			Description: "Tấn công jailbreak kiểu DAN",
			ThreatLevel: ThreatHigh,
			Weight:      35,
		},
		// Delimiter injection
		{
			Pattern:     regexp.MustCompile(`(?i)(?:\[/?SYSTEM\]|\[/?INST\]|<\|(?:im_start|im_end|system|user|assistant)\|>|<<SYS>>|<\/s>)`),
			Category:    "delimiter_injection",
			Description: "Tiêm dấu phân cách để giả mạo vai trò",
			ThreatLevel: ThreatCritical,
			Weight:      45,
		},
		// Encoded payload (base64 instruction)
		{
			Pattern:     regexp.MustCompile(`(?i)(?:decode|base64|eval|execute)\s*(?:\(|:)\s*[A-Za-z0-9+/]{20,}={0,2}`),
			Category:    "encoded_payload",
			Description: "Payload mã hóa để lẩn tránh kiểm tra",
			ThreatLevel: ThreatHigh,
			Weight:      30,
		},
		// Instruction injection via markdown/formatting (HTML comments)
		{
			Pattern:     regexp.MustCompile("(?i)<!--\\s*(?:system|instruction|override)[\\s\\S]*?-->"),
			Category:    "format_injection",
			Description: "Chèn chỉ dẫn ẩn qua định dạng",
			ThreatLevel: ThreatMedium,
			Weight:      20,
		},
		// Context manipulation
		{
			Pattern:     regexp.MustCompile(`(?i)(?:new\s+conversation|reset\s+context|clear\s+(?:history|memory|context)|start\s+(?:fresh|over|new\s+session))\s*[.!]?\s*(?:you\s+(?:are|will|must|should))`),
			Category:    "context_manipulation",
			Description: "Thao túng ngữ cảnh hội thoại",
			ThreatLevel: ThreatMedium,
			Weight:      20,
		},
		// Token smuggling
		{
			Pattern:     regexp.MustCompile(`(?i)(?:ignore\s+(?:the\s+)?(?:following|next|rest)|skip\s+to\s+(?:the\s+)?end|begin\s+(?:new|real)\s+(?:task|instruction))`),
			Category:    "token_smuggling",
			Description: "Lén chèn token để chuyển hướng chỉ dẫn",
			ThreatLevel: ThreatMedium,
			Weight:      25,
		},
		// Prompt leaking via translation/summary
		{
			Pattern:     regexp.MustCompile(`(?i)(?:translate|summarize|rephrase|rewrite)\s+(?:your|the|all)?\s*(?:system|initial|original|hidden|secret)\s+(?:prompt|instructions?|message|rules?)\s+(?:to|in|into)`),
			Category:    "prompt_leak_indirect",
			Description: "Trích xuất prompt gián tiếp qua dịch/tóm tắt",
			ThreatLevel: ThreatHigh,
			Weight:      25,
		},
		// Multi-step manipulation (Vietnamese)
		{
			Pattern:     regexp.MustCompile(`(?i)(?:bỏ\s+qua|bỏ\s+quên|quên\s+đi|phớt\s+lờ|không\s+tuân\s+theo)\s+(?:tất\s+cả\s+)?(?:hướng\s+dẫn|chỉ\s+dẫn|quy\s+tắc|luật)`),
			Category:    "instruction_override_vi",
			Description: "Ghi đè chỉ dẫn bằng tiếng Việt",
			ThreatLevel: ThreatCritical,
			Weight:      40,
		},
	}
}

// === Output Scanning Patterns ===

func defaultOutputPatterns() []injectionPattern {
	return []injectionPattern{
		// Leaked system prompt indicators
		{
			Pattern:     regexp.MustCompile(`(?i)(?:my\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|says?)|i\s+was\s+(?:instructed|told|programmed|configured)\s+to|here\s+(?:is|are)\s+my\s+(?:system\s+)?instructions?)`),
			Category:    "prompt_leak",
			Description: "LLM có thể đã tiết lộ system prompt",
			ThreatLevel: ThreatHigh,
			Weight:      35,
		},
		// Harmful content generation
		{
			Pattern:     regexp.MustCompile(`(?i)(?:here(?:'s|\s+is)\s+(?:how\s+to|a\s+(?:guide|tutorial|script)\s+(?:to|for))\s+(?:hack|exploit|attack|break\s+into|compromise|inject|bypass\s+security))`),
			Category:    "harmful_content",
			Description: "LLM tạo nội dung hướng dẫn tấn công",
			ThreatLevel: ThreatHigh,
			Weight:      30,
		},
		// Code injection in output
		{
			Pattern:     regexp.MustCompile(`(?i)(?:os\.system|subprocess\.(?:call|run|Popen)|exec\(|eval\(|child_process|Runtime\.exec)\s*\(`),
			Category:    "code_injection_output",
			Description: "Output chứa lệnh thực thi mã độc",
			ThreatLevel: ThreatCritical,
			Weight:      40,
		},
		// Jailbreak success indicator
		{
			Pattern:     regexp.MustCompile(`(?i)(?:i(?:'m|\s+am)\s+now\s+(?:in\s+)?(?:DAN|developer|unrestricted|jailbroken|unfiltered)\s+mode|sure[,!]?\s+(?:i'll|i\s+will|let\s+me)\s+(?:ignore|bypass|override)\s+(?:my|the)\s+(?:rules|guidelines|restrictions))`),
			Category:    "jailbreak_success",
			Description: "LLM có vẻ đã bị jailbreak thành công",
			ThreatLevel: ThreatCritical,
			Weight:      45,
		},
	}
}

// === Canary Token System ===

// CanaryToken is an invisible marker injected into prompts to detect data leaks
type CanaryToken struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
}

// CanaryStore manages canary tokens
type CanaryStore struct {
	mu     sync.RWMutex
	tokens map[string]CanaryToken // token -> canary info
}

// NewCanaryStore creates a new canary token store
func NewCanaryStore() *CanaryStore {
	return &CanaryStore{
		tokens: make(map[string]CanaryToken),
	}
}

// Generate creates a new canary token for a session
func (cs *CanaryStore) Generate(sessionID string) CanaryToken {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := "vura_canary_" + hex.EncodeToString(b)

	canary := CanaryToken{
		Token:     token,
		SessionID: sessionID,
	}

	cs.mu.Lock()
	cs.tokens[token] = canary
	cs.mu.Unlock()

	return canary
}

// InjectCanary adds a canary token to text as an invisible marker
func (cs *CanaryStore) InjectCanary(text, sessionID string) (string, CanaryToken) {
	canary := cs.Generate(sessionID)
	// Inject as zero-width-encoded or comment marker
	marker := fmt.Sprintf("\u200B%s\u200B", canary.Token)
	return text + marker, canary
}

// CheckLeaked checks if any canary tokens appear in the text
func (cs *CanaryStore) CheckLeaked(text string) []CanaryToken {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var leaked []CanaryToken
	for token, canary := range cs.tokens {
		if strings.Contains(text, token) {
			leaked = append(leaked, canary)
		}
	}
	return leaked
}

// Remove deletes a canary token
func (cs *CanaryStore) Remove(token string) {
	cs.mu.Lock()
	delete(cs.tokens, token)
	cs.mu.Unlock()
}

// CanaryStore returns the guard's canary store for external use
func (g *Guard) CanaryStore() *CanaryStore {
	return g.canaryStore
}
