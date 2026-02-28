package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vurakit/agentveil/internal/auditor"
	"github.com/vurakit/agentveil/internal/compliance"
	"github.com/vurakit/agentveil/internal/detector"
)

// handleWrap wraps an AI tool command, setting env vars to route through Agent Veil proxy
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
		fmt.Println("Usage: agentveil wrap -- <command> [args...]")
		fmt.Println("\nExamples:")
		fmt.Println("  agentveil wrap -- claude-code")
		fmt.Println("  agentveil wrap -- cursor")
		fmt.Println("  agentveil wrap -- aider --model gpt-4")
		fmt.Println("  agentveil wrap -- python my_agent.py")
		return
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "No command specified after --")
		os.Exit(1)
	}

	proxyURL := envOr("VEIL_PROXY_URL", "http://localhost:8080")
	openaiBase := proxyURL + "/v1"    // OpenAI SDK expects base URL with /v1
	anthropicBase := proxyURL         // Anthropic SDK appends /v1/messages itself
	geminiBase := proxyURL + "/gemini" // Gemini route prefix

	// Detect the tool and set appropriate env vars
	toolName := strings.ToLower(cmdArgs[0])
	env := os.Environ()

	switch {
	case strings.Contains(toolName, "claude"):
		env = setEnv(env, "ANTHROPIC_BASE_URL", anthropicBase)
		fmt.Fprintf(os.Stderr, "🛡️  Agent Veil: wrapping Claude via %s\n", anthropicBase)
	case strings.Contains(toolName, "cursor"):
		env = setEnv(env, "OPENAI_BASE_URL", openaiBase)
		env = setEnv(env, "ANTHROPIC_BASE_URL", anthropicBase)
		fmt.Fprintf(os.Stderr, "🛡️  Agent Veil: wrapping Cursor via %s\n", proxyURL)
	case strings.Contains(toolName, "aider"):
		env = setEnv(env, "OPENAI_API_BASE", openaiBase)
		fmt.Fprintf(os.Stderr, "🛡️  Agent Veil: wrapping Aider via %s\n", openaiBase)
	case strings.Contains(toolName, "gemini"):
		env = setEnv(env, "GEMINI_API_BASE", geminiBase)
		fmt.Fprintf(os.Stderr, "🛡️  Agent Veil: wrapping Gemini via %s\n", geminiBase)
	default:
		// Generic: set all common env vars
		env = setEnv(env, "OPENAI_BASE_URL", openaiBase)
		env = setEnv(env, "OPENAI_API_BASE", openaiBase)
		env = setEnv(env, "ANTHROPIC_BASE_URL", anthropicBase)
		env = setEnv(env, "GEMINI_API_BASE", geminiBase)
		fmt.Fprintf(os.Stderr, "🛡️  Agent Veil: wrapping %s via %s\n", cmdArgs[0], proxyURL)
	}

	// Pass through Agent Veil API key if set
	if apiKey := os.Getenv("VEIL_API_KEY"); apiKey != "" {
		env = setEnv(env, "VEIL_API_KEY", apiKey)
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
		fmt.Println("Usage: agentveil audit <file|->")
		fmt.Println("\nExamples:")
		fmt.Println("  agentveil audit skill.md")
		fmt.Println("  cat skill.md | agentveil audit -")
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
	fmt.Printf("\n=== Agent Veil Audit Report ===\n\n")
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
		fmt.Println("Usage: agentveil scan <text|->")
		fmt.Println("\nExamples:")
		fmt.Println("  agentveil scan \"CCCD: 012345678901, phone: 0912345678\"")
		fmt.Println("  echo \"text\" | agentveil scan -")
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
			"VEIL_PROXY_URL":      envOr("VEIL_PROXY_URL", "http://localhost:8080"),
			"TARGET_URL":          envOr("TARGET_URL", "https://api.openai.com"),
			"REDIS_ADDR":          envOr("REDIS_ADDR", "localhost:6379"),
			"LISTEN_ADDR":         envOr("LISTEN_ADDR", ":8080"),
			"LOG_LEVEL":           envOr("LOG_LEVEL", "info"),
			"VEIL_ENCRYPTION_KEY": maskIfSet("VEIL_ENCRYPTION_KEY"),
			"VEIL_API_KEY":        maskIfSet("VEIL_API_KEY"),
		}

		fmt.Println("Agent Veil Configuration:")
		fmt.Println()
		for k, v := range config {
			fmt.Printf("  %-25s %s\n", k+":", v)
		}
		fmt.Printf("\n  %-25s %s\n", "Go version:", runtime.Version())
		fmt.Printf("  %-25s %s/%s\n", "Platform:", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  %-25s %s\n", "Agent Veil version:", version)
	} else {
		fmt.Println("Usage: agentveil config show")
	}
}

// handleCompliance checks regulatory compliance
func handleCompliance(args []string) {
	if len(args) == 0 || args[0] != "check" {
		fmt.Println("Usage: agentveil compliance check [--framework <name>]")
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
		EncryptionAtRest: os.Getenv("VEIL_ENCRYPTION_KEY") != "",
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
	fmt.Printf("\n=== Agent Veil Compliance Report ===\n\n")
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

// ─── Setup command ────────────────────────────────────────────────

const (
	markerStart = "# >>> Agent Veil >>>"
	markerEnd   = "# <<< Agent Veil <<<"
	defaultProxy = "http://localhost:8080"
)

// handleSetup orchestrates one-command setup/teardown of Agent Veil.
func handleSetup(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "--undo", "undo":
			setupUninstall()
			return
		case "--status", "status":
			setupStatus()
			return
		}
	}
	setupInstall()
}

func setupInstall() {
	proxyURL := envOr("VEIL_PROXY_URL", defaultProxy)

	// 1. Pre-flight
	fmt.Print("\n=== Agent Veil Setup ===\n\n")
	if err := checkCommand("docker"); err != nil {
		fmt.Fprintf(os.Stderr, "[fail] docker not found. Install: https://docs.docker.com/get-docker/\n")
		os.Exit(1)
	}
	if err := checkDockerCompose(); err != nil {
		fmt.Fprintf(os.Stderr, "[fail] docker compose not found. Install Docker Desktop or the compose plugin.\n")
		os.Exit(1)
	}
	fmt.Println("[ok]  docker and docker compose found")

	// 2. Generate .env
	if err := setupGenerateEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "[fail] %v\n", err)
		os.Exit(1)
	}

	// 3. docker compose up
	fmt.Println("[info] Building and starting containers...")
	cmd := exec.Command("docker", "compose", "up", "-d", "--build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[fail] docker compose up failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[ok]  Containers started")

	// 4. Health check
	if err := waitForProxy(proxyURL, 60*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "[fail] %v\n", err)
		fmt.Fprintln(os.Stderr, "  Check logs: docker compose logs proxy")
		os.Exit(1)
	}

	// 5. Inject shell env vars
	profile := detectShellProfile()
	if err := injectShellEnv(profile, proxyURL); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] Could not update shell profile: %v\n", err)
	}

	// 6. Print success
	fmt.Printf("\n=== Agent Veil is ready! ===\n\n")
	fmt.Println("  All AI tools will now route through the security proxy.")
	fmt.Printf("\n  To apply in your current terminal:\n    source %s\n\n", profile)
	fmt.Println("  Test commands:")
	fmt.Printf("    curl -s %s/health\n", proxyURL)
	fmt.Println("    agentveil setup --status")
	fmt.Println("\n  Uninstall:")
	fmt.Println("    agentveil setup --undo")
	fmt.Println()
}

func setupUninstall() {
	fmt.Println("[info] Uninstalling Agent Veil...")

	// Remove env block from shell profile
	profile := detectShellProfile()
	if removed, err := removeShellEnv(profile); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] %v\n", err)
	} else if removed {
		fmt.Printf("[ok]  Removed env vars from %s\n", profile)
	} else {
		fmt.Printf("[info] No env vars found in %s\n", profile)
	}

	// docker compose down
	cmd := exec.Command("docker", "compose", "down", "-v")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	fmt.Println("[ok]  Containers stopped and volumes removed")

	// Remove .env
	if err := os.Remove(".env"); err == nil {
		fmt.Println("[ok]  Removed .env")
	}

	fmt.Printf("\nAgent Veil uninstalled.\n  Restart your shell or run: source %s\n", profile)
}

func setupStatus() {
	proxyURL := envOr("VEIL_PROXY_URL", defaultProxy)
	fmt.Print("=== Agent Veil Status ===\n\n")

	// Proxy health
	resp, err := http.Get(proxyURL + "/health")
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		fmt.Printf("[ok]  Proxy:           healthy (%s)\n", proxyURL)
	} else {
		fmt.Printf("[fail] Proxy:          unreachable (%s)\n", proxyURL)
	}

	// Docker containers
	out, err := exec.Command("docker", "compose", "ps", "--status", "running", "--format", "{{.Name}}").Output()
	if err == nil {
		lines := strings.TrimSpace(string(out))
		if strings.Contains(lines, "proxy") {
			fmt.Println("[ok]  Container proxy: running")
		} else {
			fmt.Println("[fail] Container proxy: not running")
		}
		if strings.Contains(lines, "redis") {
			fmt.Println("[ok]  Container redis: running")
		} else {
			fmt.Println("[fail] Container redis: not running")
		}
	}

	// Shell profile
	profile := detectShellProfile()
	if profileHasMarker(profile) {
		fmt.Printf("[ok]  Shell profile:   configured (%s)\n", profile)
	} else {
		fmt.Printf("[warn] Shell profile:  not configured (%s)\n", profile)
	}

	// Current env
	fmt.Println("\n  Current session env:")
	fmt.Printf("    ANTHROPIC_BASE_URL=%s\n", envOr("ANTHROPIC_BASE_URL", "<not set>"))
	fmt.Printf("    OPENAI_API_BASE=%s\n", envOr("OPENAI_API_BASE", "<not set>"))
	fmt.Printf("    OPENAI_BASE_URL=%s\n", envOr("OPENAI_BASE_URL", "<not set>"))
	fmt.Printf("    GEMINI_API_BASE=%s\n", envOr("GEMINI_API_BASE", "<not set>"))

	// .env
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println("\n[ok]  .env file:       present")
	} else {
		fmt.Println("\n[warn] .env file:      missing")
	}
	fmt.Println()
}

// ─── Setup helpers ────────────────────────────────────────────────

func checkCommand(name string) error {
	_, err := exec.LookPath(name)
	return err
}

func checkDockerCompose() error {
	return exec.Command("docker", "compose", "version").Run()
}

func setupGenerateEnv() error {
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println("[info] .env already exists, keeping it")
		return nil
	}

	example, err := os.ReadFile(".env.example")
	if err != nil {
		return fmt.Errorf(".env.example not found — are you in the agentveil repo root?")
	}

	content := string(example)

	// Generate encryption key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}
	key := hex.EncodeToString(keyBytes)

	content = replaceEnvLine(content, "VEIL_ENCRYPTION_KEY", key)
	content = replaceEnvLine(content, "TARGET_URL", "https://api.anthropic.com")

	if err := os.WriteFile(".env", []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write .env: %w", err)
	}
	fmt.Println("[ok]  Generated .env with encryption key")
	return nil
}

func replaceEnvLine(content, key, value string) string {
	lines := strings.Split(content, "\n")
	prefix := key + "="
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = prefix + value
		}
	}
	return strings.Join(lines, "\n")
}

func waitForProxy(proxyURL string, timeout time.Duration) error {
	fmt.Printf("[info] Waiting for proxy to be healthy (max %ds)...\n", int(timeout.Seconds()))
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(proxyURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			fmt.Println("[ok]  Proxy is healthy")
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("proxy did not become healthy within %ds", int(timeout.Seconds()))
}

func detectShellProfile() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	name := filepath.Base(shell)
	home, _ := os.UserHomeDir()

	switch name {
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "bash":
		bp := filepath.Join(home, ".bash_profile")
		if _, err := os.Stat(bp); err == nil {
			return bp
		}
		return filepath.Join(home, ".bashrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	default:
		return filepath.Join(home, ".profile")
	}
}

func profileHasMarker(profile string) bool {
	data, err := os.ReadFile(profile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), markerStart)
}

func injectShellEnv(profile, proxyURL string) error {
	if profileHasMarker(profile) {
		fmt.Printf("[info] Shell env vars already in %s, skipping\n", profile)
		return nil
	}

	shell := filepath.Base(os.Getenv("SHELL"))
	var block string
	if shell == "fish" {
		block = fmt.Sprintf("\n%s\nset -gx ANTHROPIC_BASE_URL %s\nset -gx OPENAI_API_BASE %s/v1\nset -gx OPENAI_BASE_URL %s/v1\nset -gx GEMINI_API_BASE %s/gemini\n%s\n",
			markerStart, proxyURL, proxyURL, proxyURL, proxyURL, markerEnd)
	} else {
		block = fmt.Sprintf("\n%s\nexport ANTHROPIC_BASE_URL=%s\nexport OPENAI_API_BASE=%s/v1\nexport OPENAI_BASE_URL=%s/v1\nexport GEMINI_API_BASE=%s/gemini\n%s\n",
			markerStart, proxyURL, proxyURL, proxyURL, proxyURL, markerEnd)
	}

	f, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(block); err != nil {
		return err
	}
	fmt.Printf("[ok]  Added env vars to %s\n", profile)
	return nil
}

func removeShellEnv(profile string) (bool, error) {
	data, err := os.ReadFile(profile)
	if err != nil {
		return false, nil // file doesn't exist, nothing to remove
	}

	content := string(data)
	if !strings.Contains(content, markerStart) {
		return false, nil
	}

	// Remove the marker block line by line
	var result []string
	inBlock := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == markerStart {
			inBlock = true
			continue
		}
		if strings.TrimSpace(line) == markerEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			result = append(result, line)
		}
	}

	// Trim trailing empty lines
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}

	output := strings.Join(result, "\n") + "\n"
	if err := os.WriteFile(profile, []byte(output), 0644); err != nil {
		return false, err
	}
	return true, nil
}
