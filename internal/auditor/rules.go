package auditor

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CustomRule defines a user-configurable audit rule
type CustomRule struct {
	ID          string `yaml:"id"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`    // critical, high, medium, low
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Weight      int    `yaml:"weight"`
	Enabled     bool   `yaml:"enabled"`
}

// RulesConfig is the YAML config structure for custom audit rules
type RulesConfig struct {
	Rules     []CustomRule      `yaml:"rules"`
	Overrides map[string]string `yaml:"severity_overrides"` // rule_id -> new severity
}

// ParseRulesConfig parses a YAML string into RulesConfig
func ParseRulesConfig(data string) (*RulesConfig, error) {
	var cfg RulesConfig
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse rules YAML: %w", err)
	}

	// Validate
	for i, r := range cfg.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule %d: missing id", i)
		}
		if r.Pattern == "" {
			return nil, fmt.Errorf("rule %s: missing pattern", r.ID)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return nil, fmt.Errorf("rule %s: invalid regex: %w", r.ID, err)
		}
		if r.Severity == "" {
			cfg.Rules[i].Severity = "medium"
		}
		if r.Weight == 0 {
			cfg.Rules[i].Weight = 15
		}
		if !cfg.Rules[i].Enabled {
			cfg.Rules[i].Enabled = true // default to enabled
		}
	}

	return &cfg, nil
}

// ToPatterns converts custom rules to dangerousPattern slice
func (rc *RulesConfig) ToPatterns() []dangerousPattern {
	var patterns []dangerousPattern
	for _, r := range rc.Rules {
		if !r.Enabled {
			continue
		}

		severity := r.Severity
		// Apply overrides
		if override, ok := rc.Overrides[r.ID]; ok {
			severity = override
		}

		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}

		patterns = append(patterns, dangerousPattern{
			Pattern:     compiled,
			Severity:    severity,
			Category:    r.Category,
			Description: r.Description,
			Weight:      r.Weight,
		})
	}
	return patterns
}

// MergeMarkdownSections parses markdown and returns a map of section -> content
func MergeMarkdownSections(content string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(content, "\n")

	currentSection := "_root"
	var sectionLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			// Save previous section
			if len(sectionLines) > 0 {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			// Start new section
			currentSection = strings.TrimLeft(trimmed, "# ")
			sectionLines = nil
		} else {
			sectionLines = append(sectionLines, line)
		}
	}

	// Save last section
	if len(sectionLines) > 0 {
		sections[currentSection] = strings.Join(sectionLines, "\n")
	}

	return sections
}
