// vura CLI — Security proxy for AI agents
//
// Commands:
//
//	vura proxy start       Start the Vura proxy server
//	vura wrap -- <cmd>     Wrap any AI tool to route through Vura
//	vura audit <file>      Audit a skill.md file for security issues
//	vura scan <text>       Scan text for PII
//	vura config show       Show current configuration
//	vura compliance check  Check compliance status
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
	case "version", "--version", "-v":
		fmt.Printf("vura version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`vura — Security Proxy for AI Agents

Usage:
  vura <command> [arguments]

Commands:
  proxy start            Start the Vura proxy server
  wrap -- <cmd>          Wrap any AI tool to route through Vura proxy
  audit <file|->         Audit a skill.md file for security compliance
  scan <text>            Scan text for PII (Personally Identifiable Information)
  config show            Show current configuration
  compliance check       Check compliance against regulatory frameworks
  version                Show version
  help                   Show this help

Examples:
  vura proxy start                           Start proxy on :8080
  vura wrap -- claude-code                   Wrap Claude Code through Vura
  vura wrap -- cursor                        Wrap Cursor through Vura
  vura audit skill.md                        Audit a skill file
  vura scan "CCCD: 012345678901"             Scan text for PII
  echo "text" | vura scan -                  Scan from stdin
  vura compliance check --framework vietnam  Check Vietnam AI Law compliance

Environment:
  VURA_PROXY_URL         Proxy URL (default: http://localhost:8080)
  VURA_API_KEY           API key for authentication
  VURA_ENCRYPTION_KEY    32-byte hex key for vault encryption
  TARGET_URL             Upstream LLM API (default: https://api.openai.com)
  REDIS_ADDR             Redis address (default: localhost:6379)`)
}
