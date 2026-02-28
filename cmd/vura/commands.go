package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/vura/privacyguard/internal/auditor"
	"github.com/vura/privacyguard/internal/compliance"
	"github.com/vura/privacyguard/internal/detector"
)

// handleWrap wraps an AI tool command, setting env vars to route through Vura proxy
func handleWrap(args []string) {
	// Find "--" separator
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}

	var cmdArgs []string
	if dashIdx >= 0 && dashIdx+1 < len(args) {
		cmdArgs = args[dashIdx+1:]
	} else if len(args) > 0 && args[0] != "--" {
		cmdArgs = args
	} else {
		fmt.Println("Usage: vura wrap -- <command> [args...]")
		fmt.Println("\nExamples:")
		fmt.Println("  vura wrap -- claude-code")
		fmt.Println("  vura wrap -- cursor")
		fmt.Println("  vura wrap -- aider --model gpt-4")
		fmt.Println("  vura wrap -- python my_agent.py")
		return
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "No command specified after --")
		os.Exit(1)
	}

	proxyURL := envOr("VURA_PROXY_URL", "http://localhost:8080")
	baseURL := proxyURL + "/v1"

	// Detect the tool and set appropriate env vars
	toolName := strings.ToLower(cmdArgs[0])
	env := os.Environ()

	switch {
	case strings.Contains(toolName, "claude"):
		env = setEnv(env, "ANTHROPIC_BASE_URL", baseURL)
		fmt.Fprintf(os.Stderr, "🛡️  Vura: wrapping Claude via %s\n", baseURL)
	case strings.Contains(toolName, "cursor"):
		env = setEnv(env, "OPENAI_BASE_URL", baseURL)
		env = setEnv(env, "ANTHROPIC_BASE_URL", baseURL)
		fmt.Fprintf(os.Stderr, "🛡️  Vura: wrapping Cursor via %s\n", baseURL)
	case strings.Contains(toolName, "aider"):
		env = setEnv(env, "OPENAI_API_BASE", baseURL)
		fmt.Fprintf(os.Stderr, "🛡️  Vura: wrapping Aider via %s\n", baseURL)
	default:
		// Generic: set all common env vars
		env = setEnv(env, "OPENAI_BASE_URL", baseURL)
		env = setEnv(env, "OPENAI_API_BASE", baseURL)
		env = setEnv(env, "ANTHROPIC_BASE_URL", baseURL)
		fmt.Fprintf(os.Stderr, "🛡️  Vura: wrapping %s via %s\n", cmdArgs[0], baseURL)
	}

	// Pass through Vura API key if set
	if apiKey := os.Getenv("VURA_API_KEY"); apiKey != "" {
		env = setEnv(env, "VURA_API_KEY", apiKey)
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// handleAudit audits a skill.md file
func handleAudit(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vura audit <file|->")
		fmt.Println("\nExamples:")
		fmt.Println("  vura audit skill.md")
		fmt.Println("  cat skill.md | vura audit -")
		return
	}

	var content string
	if args[0] == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		content = string(data)
	} else {
		data, err := os.ReadFile(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		content = string(data)
	}

	// Check for --custom-rules flag
	var a *auditor.Auditor
	customRulesIdx := -1
	for i, arg := range args {
		if arg == "--rules" && i+1 < len(args) {
			customRulesIdx = i + 1
			break
		}
	}

	if customRulesIdx >= 0 {
		rulesData, err := os.ReadFile(args[customRulesIdx])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading rules file: %v\n", err)
			os.Exit(1)
		}
		var createErr error
		a, createErr = auditor.NewWithCustomRules(string(rulesData))
		if createErr != nil {
			fmt.Fprintf(os.Stderr, "Error parsing rules: %v\n", createErr)
			os.Exit(1)
		}
	} else {
		a = auditor.New()
	}

	report := a.Analyze(content)

	// Output format
	outputFormat := "text"
	for i, arg := range args {
		if arg == "--format" && i+1 < len(args) {
			outputFormat = args[i+1]
		}
	}

	switch outputFormat {
	case "json":
		data, _ := report.ReportJSON()
		fmt.Println(string(data))
	case "html":
		fmt.Println(report.ReportHTML())
	default:
		printAuditReport(report)
	}

	// Exit with non-zero code if high risk
	if report.RiskLevel >= auditor.RiskHigh {
		os.Exit(2)
	}
}

func printAuditReport(report auditor.Report) {
	fmt.Printf("\n=== Vura Audit Report ===\n\n")
	fmt.Printf("Risk Level:  %s (%d/4)\n", report.RiskLevelLabel, report.RiskLevel)
	fmt.Printf("Score:       %.0f/100\n", report.Score)
	fmt.Printf("Findings:    %d\n", len(report.Findings))
	fmt.Printf("Summary:     %s\n\n", report.Summary)

	if len(report.Findings) > 0 {
		fmt.Println("Findings:")
		for i, f := range report.Findings {
			fmt.Printf("  %d. [%s] Line %d: %s\n", i+1, f.Severity, f.Line, f.Description)
			if f.Snippet != "" {
				fmt.Printf("     > %s\n", f.Snippet)
			}
		}
	}

	if len(report.BehaviorChains) > 0 {
		fmt.Println("\nBehavior Chains:")
		for _, bc := range report.BehaviorChains {
			fmt.Printf("  - [%s] %s: %s\n", bc.Chain.Severity, bc.Chain.Name, bc.Chain.Description)
		}
	}
	fmt.Println()
}

// handleScan scans text for PII
func handleScan(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vura scan <text|->")
		fmt.Println("\nExamples:")
		fmt.Println("  vura scan \"CCCD: 012345678901, phone: 0912345678\"")
		fmt.Println("  echo \"text\" | vura scan -")
		return
	}

	var text string
	if args[0] == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		text = string(data)
	} else {
		text = strings.Join(args, " ")
	}

	det := detector.New()
	entities := det.Scan(text)

	// Output format
	outputJSON := false
	for _, arg := range args {
		if arg == "--json" {
			outputJSON = true
		}
	}

	if outputJSON || len(args) > 1 && args[len(args)-1] == "--json" {
		result := map[string]any{
			"found":    len(entities) > 0,
			"count":    len(entities),
			"entities": entities,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(entities) == 0 {
		fmt.Println("No PII detected.")
		return
	}

	fmt.Printf("Found %d PII entities:\n\n", len(entities))
	for i, e := range entities {
		fmt.Printf("  %d. [%s] \"%s\" (pos: %d-%d, confidence: %d)\n",
			i+1, e.Category, e.Original, e.Start, e.End, e.Confidence)
	}

	// Show anonymized version
	anonymized, _ := det.Anonymize(text)
	fmt.Printf("\nAnonymized:\n  %s\n", anonymized)
}

// handleConfig shows current configuration
func handleConfig(args []string) {
	if len(args) == 0 || args[0] == "show" {
		config := map[string]string{
			"VURA_PROXY_URL":      envOr("VURA_PROXY_URL", "http://localhost:8080"),
			"TARGET_URL":          envOr("TARGET_URL", "https://api.openai.com"),
			"REDIS_ADDR":          envOr("REDIS_ADDR", "localhost:6379"),
			"LISTEN_ADDR":         envOr("LISTEN_ADDR", ":8080"),
			"LOG_LEVEL":           envOr("LOG_LEVEL", "info"),
			"VURA_ENCRYPTION_KEY": maskIfSet("VURA_ENCRYPTION_KEY"),
			"VURA_API_KEY":        maskIfSet("VURA_API_KEY"),
		}

		fmt.Println("Vura Configuration:")
		fmt.Println()
		for k, v := range config {
			fmt.Printf("  %-25s %s\n", k+":", v)
		}
		fmt.Printf("\n  %-25s %s\n", "Go version:", runtime.Version())
		fmt.Printf("  %-25s %s/%s\n", "Platform:", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  %-25s %s\n", "Vura version:", version)
	} else {
		fmt.Println("Usage: vura config show")
	}
}

// handleCompliance checks regulatory compliance
func handleCompliance(args []string) {
	if len(args) == 0 || args[0] != "check" {
		fmt.Println("Usage: vura compliance check [--framework <name>]")
		fmt.Println("\nFrameworks: vietnam, eu, gdpr, all (default)")
		return
	}

	// Determine framework
	framework := "all"
	for i, arg := range args {
		if arg == "--framework" && i+1 < len(args) {
			framework = args[i+1]
		}
	}

	var checker *compliance.Checker
	switch framework {
	case "vietnam":
		checker = compliance.NewCheckerForFrameworks(compliance.FrameworkVietnamAI)
	case "eu":
		checker = compliance.NewCheckerForFrameworks(compliance.FrameworkEUAI)
	case "gdpr":
		checker = compliance.NewCheckerForFrameworks(compliance.FrameworkGDPR)
	default:
		checker = compliance.NewChecker()
	}

	// Detect current capabilities from running system
	caps := compliance.SystemCapabilities{
		PIIDetection:     true,
		PIIAnonymization: true,
		EncryptionAtRest: os.Getenv("VURA_ENCRYPTION_KEY") != "",
		AuditLogging:     true,
		AccessControl:    true,
		PromptGuard:      true,
		OutputGuardrails: true,
		SkillAuditing:    true,
		RateLimiting:     true,
		TLSEncryption:    os.Getenv("TLS_CERT") != "",
	}

	report := checker.Check(caps)

	// Output format
	outputFormat := "text"
	for i, arg := range args {
		if arg == "--format" && i+1 < len(args) {
			outputFormat = args[i+1]
		}
	}

	switch outputFormat {
	case "json":
		data, _ := report.ReportJSON()
		fmt.Println(string(data))
	case "html":
		fmt.Println(report.ReportHTML())
	default:
		printComplianceReport(report)
	}
}

func printComplianceReport(report compliance.ComplianceReport) {
	fmt.Printf("\n=== Vura Compliance Report ===\n\n")
	fmt.Printf("Score: %.0f/100\n", report.OverallScore)
	fmt.Printf("%s\n\n", report.Summary)

	for _, r := range report.Results {
		status := "✓"
		if r.Status == compliance.StatusNonCompliant {
			status = "✗"
		} else if r.Status == compliance.StatusPartial {
			status = "~"
		}
		fmt.Printf("  %s [%s] %s — %s\n", status, r.Requirement.ID, r.Requirement.Title, r.Details)
	}

	if len(report.Recommendations) > 0 {
		fmt.Println("\nRecommendations:")
		for _, rec := range report.Recommendations {
			fmt.Printf("  → %s\n", rec)
		}
	}
	fmt.Println()
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func maskIfSet(key string) string {
	v := os.Getenv(key)
	if v == "" {
		return "(not set)"
	}
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "..." + v[len(v)-4:]
}
