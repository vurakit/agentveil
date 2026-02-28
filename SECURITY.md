# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < 1.0   | Best effort        |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@vura.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix & Disclosure**: Within 30 days (coordinated disclosure)

### What to Expect

1. We will acknowledge your report promptly
2. We will investigate and validate the issue
3. We will develop and test a fix
4. We will release a security advisory and patch
5. We will credit you (unless you prefer anonymity)

## Scope

The following are in scope:
- PII detection bypass (data leaking through to LLM)
- Vault data exposure (accessing other sessions' PII)
- Authentication/authorization bypass
- Injection attacks through proxy headers/body
- SSE streaming rehydration errors exposing PII

## Out of Scope

- Vulnerabilities in upstream LLM providers
- Social engineering attacks
- Denial of service (unless caused by a specific code bug)
