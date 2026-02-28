package detector

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/vurakit/agentveil/pkg/pii"
)

// Sensitivity controls detection aggressiveness
type Sensitivity int

const (
	SensitivityLow      Sensitivity = iota // only high-confidence matches
	SensitivityMedium                      // balanced
	SensitivityHigh                        // aggressive, more false positives
)

// Match represents a single PII detection result
type Match struct {
	Original   string
	Token      string
	Category   pii.Category
	Start      int
	End        int
	Confidence int // 0-100 confidence score
}

// Config configures the detector behavior
type Config struct {
	Sensitivity    Sensitivity
	EnableVietnam  bool
	EnableIntl     bool
	EnableSecrets  bool
	AllowList      map[string]bool // values to never flag
	BlockList      map[string]bool // values to always flag
}

// DefaultConfig returns balanced detection settings
func DefaultConfig() Config {
	return Config{
		Sensitivity:   SensitivityMedium,
		EnableVietnam: true,
		EnableIntl:    true,
		EnableSecrets: true,
	}
}

// Detector scans text for PII and produces pseudonymized tokens
type Detector struct {
	patterns    []pii.Pattern
	mu          sync.Mutex
	counters    map[pii.Category]*atomic.Int64
	config      Config
}

// New creates a Detector loaded with all PII patterns
func New() *Detector {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a Detector with custom configuration
func NewWithConfig(cfg Config) *Detector {
	counters := make(map[pii.Category]*atomic.Int64)
	for cat := range pii.TokenPrefix {
		counters[cat] = &atomic.Int64{}
	}

	var patterns []pii.Pattern
	if cfg.EnableVietnam {
		patterns = append(patterns, pii.VietnamPatterns()...)
	}
	if cfg.EnableIntl {
		patterns = append(patterns, pii.InternationalPatterns()...)
	}
	if cfg.EnableSecrets {
		patterns = append(patterns, pii.SecretPatterns()...)
	}

	return &Detector{
		patterns: patterns,
		counters: counters,
		config:   cfg,
	}
}

// confidenceFor assigns a confidence score based on category and context
func confidenceFor(cat pii.Category, original string) int {
	switch cat {
	case pii.CatEmail:
		return 95
	case pii.CatCCCD:
		// CCCD with valid province prefix (0-96) gets higher confidence
		if len(original) == 12 && original[0] == '0' {
			return 90
		}
		return 70
	case pii.CatPhone:
		return 90
	case pii.CatCreditCard:
		if pii.LuhnCheck(original) {
			return 95
		}
		return 40
	case pii.CatSSN:
		return 85
	case pii.CatIBAN:
		return 85
	case pii.CatIPAddr:
		return 75
	case pii.CatPassport:
		return 85
	case pii.CatLicPlate:
		return 80
	case pii.CatTIN:
		return 70
	case pii.CatBankAcct:
		return 80 // context-hinted
	case pii.CatBHXH:
		return 80 // context-hinted
	case pii.CatDOB:
		return 75
	case pii.CatAddress:
		return 85
	case pii.CatCMND:
		return 50 // 9 digits is ambiguous without context
	// Secret & credential categories
	case pii.CatAPIKeyOpenAI:
		return 98
	case pii.CatAPIKeyAnthropic:
		return 98
	case pii.CatAPIKeyGoogle:
		return 97
	case pii.CatAWSAccessKey:
		return 97
	case pii.CatAWSSecretKey:
		return 90
	case pii.CatGitHubToken:
		return 98
	case pii.CatGitLabToken:
		return 97
	case pii.CatSlackToken:
		return 95
	case pii.CatStripeKey:
		return 97
	case pii.CatSendGridKey:
		return 96
	case pii.CatTwilioKey:
		return 95
	case pii.CatNPMToken:
		return 96
	case pii.CatPyPIToken:
		return 96
	case pii.CatDockerToken:
		return 96
	case pii.CatHuggingFace:
		return 95
	case pii.CatReplicateToken:
		return 95
	case pii.CatPEMPrivateKey:
		return 99
	case pii.CatJWT:
		return 92
	case pii.CatConnectionStr:
		return 92
	case pii.CatGenericSecret:
		return 80
	case pii.CatHexSecret:
		return 75
	default:
		return 60
	}
}

// minConfidence returns the threshold for the given sensitivity
func minConfidence(s Sensitivity) int {
	switch s {
	case SensitivityLow:
		return 80
	case SensitivityHigh:
		return 30
	default:
		return 50
	}
}

// Scan detects all PII in text and returns matches with pseudonym tokens
func (d *Detector) Scan(text string) []Match {
	var matches []Match
	seen := make(map[string]string) // original -> token (dedup within same scan)
	threshold := minConfidence(d.config.Sensitivity)

	for _, p := range d.patterns {
		locs := p.Regex.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			original := text[loc[0]:loc[1]]

			// Allow list check
			if d.config.AllowList != nil && d.config.AllowList[original] {
				continue
			}

			confidence := confidenceFor(p.Category, original)

			// Block list always matches regardless of confidence
			isBlocked := d.config.BlockList != nil && d.config.BlockList[original]

			if confidence < threshold && !isBlocked {
				continue
			}

			// Credit card Luhn post-check
			if p.Category == pii.CatCreditCard && !pii.LuhnCheck(original) && !isBlocked {
				continue
			}

			// Skip if already matched by higher-priority pattern
			token, exists := seen[original]
			if !exists {
				if pii.IsSecretCategory(p.Category) {
					// Secrets: partial mask (show ~40%, hide rest with *)
					token = pii.PartialMask(original)
				} else {
					counter := d.counters[p.Category]
					if counter == nil {
						counter = &atomic.Int64{}
						d.mu.Lock()
						d.counters[p.Category] = counter
						d.mu.Unlock()
					}
					idx := counter.Add(1)
					prefix := pii.TokenPrefix[p.Category]
					token = fmt.Sprintf("[%s_%d]", prefix, idx)
				}
				seen[original] = token
			}

			matches = append(matches, Match{
				Original:   original,
				Token:      token,
				Category:   p.Category,
				Start:      loc[0],
				End:        loc[1],
				Confidence: confidence,
			})
		}
	}

	return matches
}

// Anonymize replaces all PII in text with pseudonym tokens and returns
// the anonymized text along with the mapping (token -> original)
func (d *Detector) Anonymize(text string) (string, map[string]string) {
	matches := d.Scan(text)
	if len(matches) == 0 {
		return text, nil
	}

	// Sort matches by position descending to replace from end to start
	sortByPosDesc(matches)

	// Deduplicate overlapping matches (keep the first = higher priority)
	matches = removeOverlaps(matches)

	mapping := make(map[string]string)
	result := text
	for _, m := range matches {
		if m.Start >= 0 && m.End <= len(result) {
			result = result[:m.Start] + m.Token + result[m.End:]
			mapping[m.Token] = m.Original
		}
	}

	return result, mapping
}

// ResetCounters resets the per-category token counters
func (d *Detector) ResetCounters() {
	for _, c := range d.counters {
		c.Store(0)
	}
}

func sortByPosDesc(matches []Match) {
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].Start > matches[j-1].Start; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
}

// removeOverlaps removes matches that overlap with earlier (higher-priority) ones.
// Assumes matches are sorted by Start descending.
func removeOverlaps(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	var result []Match
	result = append(result, matches[0])

	for i := 1; i < len(matches); i++ {
		prev := result[len(result)-1]
		curr := matches[i]
		// Since sorted desc by Start, check if curr overlaps with prev
		if curr.End <= prev.Start {
			result = append(result, curr)
		}
	}

	return result
}
