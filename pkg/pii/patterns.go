package pii

import (
	"regexp"
	"strings"
)

// PII category types
type Category string

const (
	CatCCCD       Category = "CCCD"
	CatCMND       Category = "CMND"
	CatTIN        Category = "TIN"
	CatPhone      Category = "PHONE"
	CatAddress    Category = "ADDRESS"
	CatEmail      Category = "EMAIL"
	CatName       Category = "NAME"
	CatBankAcct   Category = "BANK_ACCOUNT"
	CatLicPlate   Category = "LICENSE_PLATE"
	CatBHXH       Category = "BHXH"
	CatPassport   Category = "PASSPORT"
	CatDOB        Category = "DOB"
	CatCreditCard Category = "CREDIT_CARD"
	CatSSN        Category = "SSN"
	CatIBAN       Category = "IBAN"
	CatIPAddr     Category = "IP_ADDRESS"

	// Secret & credential categories
	CatAPIKeyOpenAI    Category = "SECRET_OPENAI_KEY"
	CatAPIKeyAnthropic Category = "SECRET_ANTHROPIC_KEY"
	CatAPIKeyGoogle    Category = "SECRET_GOOGLE_KEY"
	CatAWSAccessKey    Category = "SECRET_AWS_ACCESS_KEY"
	CatAWSSecretKey    Category = "SECRET_AWS_SECRET_KEY"
	CatGitHubToken     Category = "SECRET_GITHUB_TOKEN"
	CatGitLabToken     Category = "SECRET_GITLAB_TOKEN"
	CatSlackToken      Category = "SECRET_SLACK_TOKEN"
	CatStripeKey       Category = "SECRET_STRIPE_KEY"
	CatSendGridKey     Category = "SECRET_SENDGRID_KEY"
	CatTwilioKey       Category = "SECRET_TWILIO_KEY"
	CatNPMToken        Category = "SECRET_NPM_TOKEN"
	CatPyPIToken       Category = "SECRET_PYPI_TOKEN"
	CatDockerToken     Category = "SECRET_DOCKER_TOKEN"
	CatHuggingFace     Category = "SECRET_HF_TOKEN"
	CatReplicateToken  Category = "SECRET_REPLICATE_TOKEN"
	CatPEMPrivateKey   Category = "SECRET_PEM_KEY"
	CatJWT             Category = "SECRET_JWT"
	CatConnectionStr   Category = "SECRET_CONN_STR"
	CatGenericSecret   Category = "SECRET_GENERIC"
	CatHexSecret       Category = "SECRET_HEX_KEY"
)

// TokenPrefix maps category to pseudonymization prefix
var TokenPrefix = map[Category]string{
	CatCCCD:       "CCCD",
	CatCMND:       "CMND",
	CatTIN:        "TIN",
	CatPhone:      "PHONE",
	CatAddress:    "ADDR",
	CatEmail:      "EMAIL",
	CatName:       "NAME",
	CatBankAcct:   "BANK",
	CatLicPlate:   "PLATE",
	CatBHXH:       "BHXH",
	CatPassport:   "PASSPORT",
	CatDOB:        "DOB",
	CatCreditCard: "CARD",
	CatSSN:        "SSN",
	CatIBAN:       "IBAN",
	CatIPAddr:     "IP",

	// Secret & credential prefixes
	CatAPIKeyOpenAI:    "OPENAI_KEY",
	CatAPIKeyAnthropic: "ANTHROPIC_KEY",
	CatAPIKeyGoogle:    "GOOGLE_KEY",
	CatAWSAccessKey:    "AWS_AKEY",
	CatAWSSecretKey:    "AWS_SKEY",
	CatGitHubToken:     "GH_TOKEN",
	CatGitLabToken:     "GL_TOKEN",
	CatSlackToken:      "SLACK_TOKEN",
	CatStripeKey:       "STRIPE_KEY",
	CatSendGridKey:     "SG_KEY",
	CatTwilioKey:       "TWILIO_KEY",
	CatNPMToken:        "NPM_TOKEN",
	CatPyPIToken:       "PYPI_TOKEN",
	CatDockerToken:     "DOCKER_TOKEN",
	CatHuggingFace:     "HF_TOKEN",
	CatReplicateToken:  "REPLICATE_TOKEN",
	CatPEMPrivateKey:   "PEM_KEY",
	CatJWT:             "JWT",
	CatConnectionStr:   "CONN_STR",
	CatGenericSecret:   "SECRET",
	CatHexSecret:       "HEX_KEY",
}

// Pattern holds a compiled regex and its PII category
type Pattern struct {
	Regex    *regexp.Regexp
	Category Category
	Label    string
}

// VietnamPatterns returns all Vietnam-specific PII regex patterns.
// Order matters: more specific patterns come before broader ones to
// avoid false positives via the dedup map in detector.
func VietnamPatterns() []Pattern {
	return []Pattern{
		// === HIGH SPECIFICITY (match first) ===
		{
			// Vietnamese Passport: B or C prefix + 7 digits
			Regex:    regexp.MustCompile(`\b[BC]\d{7}\b`),
			Category: CatPassport,
			Label:    "Hộ chiếu Việt Nam",
		},
		{
			// License plate: XX-YZ NNNNN or XXYZ-NNNNN
			Regex:    regexp.MustCompile(`\b\d{2}[A-Z]{1,2}[\s\-]?\d{4,5}\b`),
			Category: CatLicPlate,
			Label:    "Biển số xe",
		},
		{
			// CCCD (new): exactly 12 digits starting with 0
			Regex:    regexp.MustCompile(`\b0\d{11}\b`),
			Category: CatCCCD,
			Label:    "Căn cước công dân",
		},
		{
			// CMND (old): 9 digits
			Regex:    regexp.MustCompile(`\b\d{9}\b`),
			Category: CatCMND,
			Label:    "Chứng minh nhân dân (cũ)",
		},
		{
			// BHXH: 10 digits (social insurance number)
			Regex:    regexp.MustCompile(`\b(?i:bhxh|bảo hiểm)\s*:?\s*(\d{10})\b`),
			Category: CatBHXH,
			Label:    "Số bảo hiểm xã hội",
		},
		{
			// Phone: Vietnamese mobile 0xx or +84/84 format
			Regex:    regexp.MustCompile(`\b(?:(?:\+?84)|0)(?:3[2-9]|5[2689]|7[0-9]|8[1-9]|9[0-9])\d{7}\b`),
			Category: CatPhone,
			Label:    "Số điện thoại",
		},
		{
			// Email
			Regex:    regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			Category: CatEmail,
			Label:    "Email",
		},
		{
			// Date of birth: dd/mm/yyyy or dd-mm-yyyy
			Regex:    regexp.MustCompile(`\b(?:0[1-9]|[12]\d|3[01])[/\-](?:0[1-9]|1[0-2])[/\-](?:19|20)\d{2}\b`),
			Category: CatDOB,
			Label:    "Ngày sinh",
		},
		{
			// Tax ID (MST): 10 or 13 digits, NOT starting with 0
			Regex:    regexp.MustCompile(`\b[1-9]\d{9}(?:\d{3})?\b`),
			Category: CatTIN,
			Label:    "Mã số thuế",
		},
		{
			// Vietnamese bank account: major banks have 9-19 digit accounts
			// Context hint required to reduce false positives
			Regex:    regexp.MustCompile(`(?i:(?:stk|tài khoản|tk|account)\s*:?\s*)(\d{9,19})\b`),
			Category: CatBankAcct,
			Label:    "Số tài khoản ngân hàng",
		},
		{
			// Vietnamese address with Phường/Xã, Quận/Huyện
			Regex:    regexp.MustCompile(`(?i)(?:số\s+\d+[a-zA-Z]?\s*,?\s*)?(?:đường|phố)\s+[\p{L}\s]+,\s*(?:phường|xã|thị trấn)\s+[\p{L}\s]+,\s*(?:quận|huyện|thành phố|thị xã)\s+[\p{L}\s]+`),
			Category: CatAddress,
			Label:    "Địa chỉ Việt Nam",
		},
	}
}

// InternationalPatterns returns PII patterns for international data.
func InternationalPatterns() []Pattern {
	return []Pattern{
		{
			// Credit card: 13-19 digits (Visa, MC, Amex, etc.)
			// Basic pattern — Luhn check done in post-processing
			Regex:    regexp.MustCompile(`\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`),
			Category: CatCreditCard,
			Label:    "Credit Card",
		},
		{
			// US SSN: XXX-XX-XXXX
			Regex:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Category: CatSSN,
			Label:    "US Social Security Number",
		},
		{
			// IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric
			Regex:    regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
			Category: CatIBAN,
			Label:    "IBAN",
		},
		{
			// IPv4 address
			Regex:    regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
			Category: CatIPAddr,
			Label:    "IPv4 Address",
		},
		{
			// Date of birth (international): yyyy-mm-dd, mm/dd/yyyy
			Regex:    regexp.MustCompile(`\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b`),
			Category: CatDOB,
			Label:    "Date of Birth",
		},
	}
}

// SecretPatterns returns patterns for detecting secrets and credentials.
// Order: provider-specific (highest specificity) → structural → context-hinted generics.
func SecretPatterns() []Pattern {
	return []Pattern{
		// === PROVIDER-SPECIFIC (highest specificity) ===
		{
			// OpenAI: sk-proj-... (new project keys) or sk- followed by 20+ alphanum
			Regex:    regexp.MustCompile(`sk-proj-[a-zA-Z0-9_-]{40,}`),
			Category: CatAPIKeyOpenAI,
			Label:    "OpenAI API Key (project)",
		},
		{
			// Anthropic: sk-ant-... (must come before generic sk- pattern)
			Regex:    regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`),
			Category: CatAPIKeyAnthropic,
			Label:    "Anthropic API Key",
		},
		{
			// OpenAI: legacy sk- keys (no dashes after sk-, so won't match sk-ant-...)
			Regex:    regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
			Category: CatAPIKeyOpenAI,
			Label:    "OpenAI API Key",
		},
		{
			// Google: AIza followed by 35 chars
			Regex:    regexp.MustCompile(`AIza[a-zA-Z0-9_-]{35}`),
			Category: CatAPIKeyGoogle,
			Label:    "Google API Key",
		},
		{
			// AWS Access Key: AKIA followed by 16 uppercase alphanum
			Regex:    regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			Category: CatAWSAccessKey,
			Label:    "AWS Access Key ID",
		},
		{
			// AWS Secret Key: context-hinted, 40 base64 chars
			Regex:    regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*([a-zA-Z0-9/+=]{40})`),
			Category: CatAWSSecretKey,
			Label:    "AWS Secret Access Key",
		},
		{
			// GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_
			Regex:    regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36,}`),
			Category: CatGitHubToken,
			Label:    "GitHub Token",
		},
		{
			// GitLab Personal Access Token
			Regex:    regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`),
			Category: CatGitLabToken,
			Label:    "GitLab Personal Access Token",
		},
		{
			// Slack: xoxb-, xoxp-, xoxa- bot/user/app tokens
			Regex:    regexp.MustCompile(`xox[bpa]-[a-zA-Z0-9-]{10,}`),
			Category: CatSlackToken,
			Label:    "Slack Token",
		},
		{
			// Slack: xapp- app-level tokens
			Regex:    regexp.MustCompile(`xapp-[a-zA-Z0-9-]{10,}`),
			Category: CatSlackToken,
			Label:    "Slack App Token",
		},
		{
			// Stripe: sk_live_, sk_test_, pk_live_, pk_test_, rk_live_, rk_test_
			Regex:    regexp.MustCompile(`[spr]k_(?:live|test)_[a-zA-Z0-9]{20,}`),
			Category: CatStripeKey,
			Label:    "Stripe API Key",
		},
		{
			// SendGrid: SG.xxxx.yyyy
			Regex:    regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
			Category: CatSendGridKey,
			Label:    "SendGrid API Key",
		},
		{
			// Twilio: SK followed by 32 hex chars
			Regex:    regexp.MustCompile(`SK[a-f0-9]{32}`),
			Category: CatTwilioKey,
			Label:    "Twilio API Key",
		},
		{
			// NPM token
			Regex:    regexp.MustCompile(`npm_[a-zA-Z0-9]{20,}`),
			Category: CatNPMToken,
			Label:    "NPM Access Token",
		},
		{
			// PyPI token
			Regex:    regexp.MustCompile(`pypi-[a-zA-Z0-9_-]{20,}`),
			Category: CatPyPIToken,
			Label:    "PyPI API Token",
		},
		{
			// Docker PAT
			Regex:    regexp.MustCompile(`dckr_pat_[a-zA-Z0-9_-]{20,}`),
			Category: CatDockerToken,
			Label:    "Docker Personal Access Token",
		},
		{
			// Hugging Face
			Regex:    regexp.MustCompile(`hf_[a-zA-Z0-9]{20,}`),
			Category: CatHuggingFace,
			Label:    "Hugging Face Token",
		},
		{
			// Replicate
			Regex:    regexp.MustCompile(`r8_[a-zA-Z0-9]{20,}`),
			Category: CatReplicateToken,
			Label:    "Replicate API Token",
		},

		// === STRUCTURAL PATTERNS ===
		{
			// PEM private key block
			Regex:    regexp.MustCompile(`-----BEGIN\s[A-Z\s]*PRIVATE\sKEY-----`),
			Category: CatPEMPrivateKey,
			Label:    "PEM Private Key",
		},
		{
			// JWT: three base64url segments separated by dots
			Regex:    regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
			Category: CatJWT,
			Label:    "JSON Web Token",
		},
		{
			// Connection strings: protocol://user:pass@host
			Regex:    regexp.MustCompile(`(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s"'` + "`" + `]+:[^\s"'` + "`" + `]+@[^\s"'` + "`" + `]+`),
			Category: CatConnectionStr,
			Label:    "Database Connection String",
		},

		// === CONTEXT-HINTED GENERICS (lowest specificity) ===
		{
			// Generic secret: KEY_NAME=value (with context hints)
			Regex:    regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|ENCRYPTION_KEY|PRIVATE_KEY|AUTH_TOKEN)\s*[=:]\s*['"]?([^\s'"` + "`" + `]{8,})['"]?`),
			Category: CatGenericSecret,
			Label:    "Generic Secret/Password",
		},
		{
			// Hex secret: KEY/SECRET= followed by 64+ hex chars (e.g. encryption keys)
			Regex:    regexp.MustCompile(`(?i)(?:KEY|SECRET|ENCRYPTION_KEY|SIGNING_KEY|HMAC_KEY)\s*[=:]\s*['"]?([0-9a-f]{64,})['"]?`),
			Category: CatHexSecret,
			Label:    "Hex-encoded Secret Key",
		},
	}
}

// AllPatterns returns both Vietnam and international patterns combined.
func AllPatterns() []Pattern {
	vn := VietnamPatterns()
	intl := InternationalPatterns()
	all := make([]Pattern, 0, len(vn)+len(intl))
	all = append(all, vn...)
	all = append(all, intl...)
	return all
}

// LuhnCheck validates a credit card number using the Luhn algorithm.
func LuhnCheck(number string) bool {
	n := len(number)
	if n < 13 || n > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(number[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// IsSecretCategory returns true if the category is a secret/credential type.
func IsSecretCategory(cat Category) bool {
	s := string(cat)
	return len(s) > 7 && s[:7] == "SECRET_"
}

// PartialMask masks the latter portion of a secret, showing ~40% of visible chars.
// Example: "3783d5176a38886071bf04296c81065248..." → "3783d5176a38886071bf04296*************..."
func PartialMask(s string) string {
	n := len(s)
	if n <= 8 {
		if n <= 2 {
			return strings.Repeat("*", n)
		}
		return s[:2] + strings.Repeat("*", n-2)
	}
	visible := n * 2 / 5
	if visible < 4 {
		visible = 4
	}
	return s[:visible] + strings.Repeat("*", n-visible)
}
