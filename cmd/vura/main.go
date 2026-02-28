// agentveil CLI — Security proxy for AI agents
//
// Commands:
//
//	agentveil proxy start       Start the Agent Veil proxy server
//	agentveil wrap -- <cmd>     Wrap any AI tool to route through Agent Veil
//	agentveil audit <file>      Audit a skill.md file for security issues
//	agentveil scan <text>       Scan text for PII
//	agentveil config show       Show current configuration
//	agentveil compliance check  Check compliance status
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "proxy":
		handleProxy(args)
	case "wrap":
		handleWrap(args)
	case "audit":
		handleAudit(args)
	case "scan":
		handleScan(args)
	case "config":
		handleConfig(args)
	case "compliance":
		handleCompliance(args)
	case "setup":
		handleSetup(args)
	case "version", "--version", "-v":
		fmt.Printf("agentveil version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`agentveil — Security Proxy for AI Agents

Usage:
  agentveil <command> [arguments]

Commands:
  proxy start            Start the Agent Veil proxy server
  wrap -- <cmd>          Wrap any AI tool to route through Agent Veil proxy
  audit <file|->         Audit a skill.md file for security compliance
  scan <text>            Scan text for PII (Personally Identifiable Information)
  config show            Show current configuration
  compliance check       Check compliance against regulatory frameworks
  setup                  One-command setup (build, start, configure shell)
  setup --undo           Uninstall Agent Veil
  setup --status         Check setup status
  version                Show version
  help                   Show this help

Examples:
  agentveil proxy start                           Start proxy on :8080
  agentveil wrap -- claude-code                   Wrap Claude Code through Agent Veil
  agentveil wrap -- cursor                        Wrap Cursor through Agent Veil
  agentveil audit skill.md                        Audit a skill file
  agentveil scan "CCCD: 012345678901"             Scan text for PII
  echo "text" | agentveil scan -                  Scan from stdin
  agentveil compliance check --framework vietnam  Check Vietnam AI Law compliance

Environment:
  VEIL_PROXY_URL         Proxy URL (default: http://localhost:8080)
  VEIL_API_KEY           API key for authentication
  VEIL_ENCRYPTION_KEY    32-byte hex key for vault encryption
  TARGET_URL             Upstream LLM API (default: https://api.openai.com)
  REDIS_ADDR             Redis address (default: localhost:6379)`)
}
