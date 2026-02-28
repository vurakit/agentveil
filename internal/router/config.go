package router

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProviderConfig represents one upstream LLM provider
type ProviderConfig struct {
	Name       string `yaml:"name"`        // e.g. "openai", "anthropic", "gemini", "ollama"
	BaseURL    string `yaml:"base_url"`    // e.g. "https://api.openai.com"
	APIKey     string `yaml:"api_key"`     // provider API key (or env var reference $ENV_VAR)
	AuthMethod string `yaml:"auth_method"` // "header" (Bearer), "x-api-key", or "query"
	AuthParam  string `yaml:"auth_param"`  // query param name for auth_method=query (default "key")
	Model      string `yaml:"model"`       // default model for this provider
	Priority   int    `yaml:"priority"`    // lower = higher priority for fallback (1 = primary)
	Weight     int    `yaml:"weight"`      // weight for weighted round-robin (higher = more traffic)
	MaxRetries int    `yaml:"max_retries"` // max retries before fallback
	TimeoutSec int    `yaml:"timeout_sec"` // request timeout in seconds
	Enabled    bool   `yaml:"enabled"`
}

// RouteConfig maps a path prefix to a provider
type RouteConfig struct {
	PathPrefix string `yaml:"path_prefix"` // e.g. "/v1/openai"
	Provider   string `yaml:"provider"`    // provider name
}

// FallbackConfig configures fallback behavior
type FallbackConfig struct {
	Enabled        bool `yaml:"enabled"`
	MaxAttempts    int  `yaml:"max_attempts"`
	RetryDelaySec  int  `yaml:"retry_delay_sec"`
}

// LoadBalanceStrategy defines how to distribute traffic
type LoadBalanceStrategy string

const (
	StrategyRoundRobin LoadBalanceStrategy = "round_robin"
	StrategyWeighted   LoadBalanceStrategy = "weighted"
	StrategyPriority   LoadBalanceStrategy = "priority"
)

// RouterConfig is the top-level YAML configuration
type RouterConfig struct {
	Providers    []ProviderConfig    `yaml:"providers"`
	Routes       []RouteConfig       `yaml:"routes"`
	Fallback     FallbackConfig      `yaml:"fallback"`
	LoadBalance  LoadBalanceStrategy `yaml:"load_balance"`
	DefaultRoute string              `yaml:"default_route"` // default provider name
}

// LoadConfig reads router configuration from a YAML file
func LoadConfig(path string) (*RouterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(string(data))
}

// ParseConfig parses router configuration from YAML string
func ParseConfig(data string) (*RouterConfig, error) {
	var cfg RouterConfig
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Defaults
	if cfg.LoadBalance == "" {
		cfg.LoadBalance = StrategyPriority
	}
	if cfg.Fallback.MaxAttempts == 0 {
		cfg.Fallback.MaxAttempts = 3
	}

	// Validate and resolve env vars
	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		if p.Name == "" {
			return nil, fmt.Errorf("provider %d: missing name", i)
		}
		if p.BaseURL == "" {
			return nil, fmt.Errorf("provider %s: missing base_url", p.Name)
		}
		// Resolve $ENV_VAR references in api_key
		if len(p.APIKey) > 0 && p.APIKey[0] == '$' {
			p.APIKey = os.Getenv(p.APIKey[1:])
		}
		if p.Weight == 0 {
			p.Weight = 1
		}
		if p.MaxRetries == 0 {
			p.MaxRetries = 2
		}
		if p.TimeoutSec == 0 {
			p.TimeoutSec = 30
		}
		if p.AuthMethod == "" {
			p.AuthMethod = "header"
		}
		if p.AuthMethod == "query" && p.AuthParam == "" {
			p.AuthParam = "key"
		}
	}

	// Validate routes reference existing providers
	providerSet := make(map[string]bool)
	for _, p := range cfg.Providers {
		providerSet[p.Name] = true
	}
	for _, r := range cfg.Routes {
		if !providerSet[r.Provider] {
			return nil, fmt.Errorf("route %s: unknown provider %s", r.PathPrefix, r.Provider)
		}
	}
	if cfg.DefaultRoute != "" && !providerSet[cfg.DefaultRoute] {
		return nil, fmt.Errorf("default_route: unknown provider %s", cfg.DefaultRoute)
	}

	return &cfg, nil
}
