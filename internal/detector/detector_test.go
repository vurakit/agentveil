package detector

import (
	"testing"

	"github.com/vurakit/agentveil/pkg/pii"
)

func TestScan_CCCD(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		expect int
		cat    pii.Category
	}{
		{"valid CCCD", "CCCD: 012345678901", 1, pii.CatCCCD},
		{"CCCD in sentence", "Số CCCD của tôi là 001234567890 nhé", 1, pii.CatCCCD},
		{"multiple CCCD", "012345678901 và 098765432101", 2, pii.CatCCCD},
		{"not CCCD - 11 digits", "01234567890", 0, ""},
		{"not CCCD - 13 digits", "0123456789012", 0, ""},
		{"not CCCD - starts with non-0", "112345678901", 0, pii.CatCCCD},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := d.Scan(tt.input)

			catMatches := filterByCategory(matches, tt.cat)
			if tt.expect == 0 {
				// For "not CCCD" cases, just check no CCCD detected
				cccdMatches := filterByCategory(matches, pii.CatCCCD)
				if len(cccdMatches) != 0 {
					t.Errorf("expected 0 CCCD matches, got %d", len(cccdMatches))
				}
				return
			}
			if len(catMatches) != tt.expect {
				t.Errorf("expected %d matches for %s, got %d (all matches: %v)",
					tt.expect, tt.cat, len(catMatches), matches)
			}
		})
	}
}

func TestScan_Phone(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"0xx format", "SĐT: 0901234567", 1},
		{"84 prefix", "Gọi: 84901234567", 1},
		{"+84 prefix", "SĐT: +84901234567", 1},
		{"multiple phones", "0901234567 hoặc 0352345678", 2},
		{"not phone - too short", "09012345", 0},
		{"not phone - invalid prefix", "0101234567", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatPhone)
			if len(matches) != tt.expect {
				t.Errorf("expected %d phone matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_Email(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"standard email", "email: test@example.com", 1},
		{"vn email", "liên hệ nguyenvana@congty.vn để biết thêm", 1},
		{"multiple emails", "a@b.com và c@d.org", 2},
		{"not email", "không phải email@", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatEmail)
			if len(matches) != tt.expect {
				t.Errorf("expected %d email matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_TIN(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"10-digit TIN", "MST: 1234567890", 1},
		{"13-digit TIN", "MST: 1234567890123", 1},
		// CCCD starts with 0, should NOT match TIN
		{"CCCD not TIN", "012345678901", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatTIN)
			if len(matches) != tt.expect {
				t.Errorf("expected %d TIN matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_Address(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{
			"full address",
			"đường Nguyễn Huệ, phường Bến Nghé, quận Một",
			1,
		},
		{
			"no address",
			"Tôi sống ở Việt Nam",
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatAddress)
			if len(matches) != tt.expect {
				t.Errorf("expected %d address matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestAnonymize(t *testing.T) {
	d := New()

	input := "CCCD: 012345678901, email: test@example.com, SĐT: 0901234567"
	anonymized, mapping := d.Anonymize(input)

	// Should not contain original PII
	if containsAny(anonymized, "012345678901", "test@example.com", "0901234567") {
		t.Errorf("anonymized text still contains PII: %s", anonymized)
	}

	// Should contain tokens
	if len(mapping) == 0 {
		t.Fatal("mapping is empty")
	}

	// Mapping should have correct originals
	for token, original := range mapping {
		if original == "" {
			t.Errorf("empty original for token %s", token)
		}
		if token == "" {
			t.Error("empty token in mapping")
		}
	}
}

func TestAnonymize_NoPII(t *testing.T) {
	d := New()

	input := "Xin chào, tôi muốn hỏi về sản phẩm"
	anonymized, mapping := d.Anonymize(input)

	if anonymized != input {
		t.Errorf("expected unchanged text, got: %s", anonymized)
	}
	if mapping != nil {
		t.Errorf("expected nil mapping, got: %v", mapping)
	}
}

func TestAnonymize_Dedup(t *testing.T) {
	d := New()

	// Same CCCD appearing twice should get same token
	input := "CCCD 012345678901 lặp lại 012345678901"
	_, mapping := d.Anonymize(input)

	// Mapping should have exactly 1 entry for the CCCD
	cccdCount := 0
	for _, original := range mapping {
		if original == "012345678901" {
			cccdCount++
		}
	}
	if cccdCount != 1 {
		t.Errorf("expected 1 unique CCCD mapping, got %d", cccdCount)
	}
}

// === GĐ2: Expanded pattern tests ===

func TestScan_Passport(t *testing.T) {
	d := New()
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"valid B prefix", "Hộ chiếu B1234567", 1},
		{"valid C prefix", "Passport: C9876543", 1},
		{"invalid prefix", "A1234567", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatPassport)
			if len(matches) != tt.expect {
				t.Errorf("expected %d passport matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_LicensePlate(t *testing.T) {
	d := New()
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"standard plate", "Biển số: 30A12345", 1},
		{"with dash", "51F-12345", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatLicPlate)
			if len(matches) != tt.expect {
				t.Errorf("expected %d plate matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_DOB(t *testing.T) {
	d := New()
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"dd/mm/yyyy", "Sinh ngày 15/03/1990", 1},
		{"dd-mm-yyyy", "DOB: 01-12-2000", 1},
		{"invalid date", "99/99/9999", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatDOB)
			if len(matches) != tt.expect {
				t.Errorf("expected %d DOB matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_CreditCard(t *testing.T) {
	d := New()
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"valid Visa", "Card: 4111111111111111", 1},   // passes Luhn
		{"invalid Luhn", "Card: 4111111111111112", 0}, // fails Luhn
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatCreditCard)
			if len(matches) != tt.expect {
				t.Errorf("expected %d card matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_SSN(t *testing.T) {
	d := New()
	matches := filterByCategory(d.Scan("SSN: 123-45-6789"), pii.CatSSN)
	if len(matches) != 1 {
		t.Errorf("expected 1 SSN match, got %d", len(matches))
	}
}

func TestScan_IPv4(t *testing.T) {
	d := New()
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"valid IP", "Server: 192.168.1.100", 1},
		{"invalid IP", "999.999.999.999", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), pii.CatIPAddr)
			if len(matches) != tt.expect {
				t.Errorf("expected %d IP matches, got %d", tt.expect, len(matches))
			}
		})
	}
}

func TestScan_BankAccount(t *testing.T) {
	d := New()
	input := "STK: 0123456789012"
	matches := filterByCategory(d.Scan(input), pii.CatBankAcct)
	if len(matches) != 1 {
		t.Errorf("expected 1 bank account match, got %d", len(matches))
	}
}

func TestScan_Confidence(t *testing.T) {
	d := New()
	matches := d.Scan("email: test@example.com")
	if len(matches) == 0 {
		t.Fatal("expected matches")
	}
	if matches[0].Confidence < 90 {
		t.Errorf("expected high confidence for email, got %d", matches[0].Confidence)
	}
}

func TestSensitivity_Low(t *testing.T) {
	d := NewWithConfig(Config{
		Sensitivity:   SensitivityLow,
		EnableVietnam: true,
		EnableIntl:    true,
	})
	// Low sensitivity should skip low-confidence matches (like CMND 9 digits)
	matches := filterByCategory(d.Scan("Số 123456789 không rõ"), pii.CatCMND)
	if len(matches) != 0 {
		t.Errorf("low sensitivity should skip ambiguous 9-digit CMND, got %d matches", len(matches))
	}
}

func TestAllowList(t *testing.T) {
	d := NewWithConfig(Config{
		Sensitivity:   SensitivityMedium,
		EnableVietnam: true,
		AllowList:     map[string]bool{"0901234567": true},
	})
	matches := filterByCategory(d.Scan("SĐT: 0901234567"), pii.CatPhone)
	if len(matches) != 0 {
		t.Error("allowlisted phone should not be detected")
	}
}

func TestBlockList(t *testing.T) {
	d := NewWithConfig(Config{
		Sensitivity:   SensitivityLow,
		EnableVietnam: true,
		EnableIntl:    true,
		BlockList:     map[string]bool{"test@example.com": true},
	})
	matches := filterByCategory(d.Scan("email: test@example.com"), pii.CatEmail)
	if len(matches) != 1 {
		t.Error("blocklisted value should always be detected")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true}, // Visa test
		{"5500000000000004", true}, // MC test
		{"4111111111111112", false},
		{"0000000000000000", true}, // edge case
		{"123", false},             // too short
	}
	for _, tt := range tests {
		got := pii.LuhnCheck(tt.number)
		if got != tt.valid {
			t.Errorf("LuhnCheck(%s) = %v, want %v", tt.number, got, tt.valid)
		}
	}
}

// === Secret & Credential Detection Tests ===

func TestScan_SecretKeys(t *testing.T) {
	d := New()

	tests := []struct {
		name   string
		input  string
		cat    pii.Category
		expect int
	}{
		{
			"OpenAI project key",
			"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF",
			pii.CatAPIKeyOpenAI, 1,
		},
		{
			"OpenAI legacy key",
			"key: sk-abcdefghijklmnopqrstuvwxyz1234",
			pii.CatAPIKeyOpenAI, 1,
		},
		{
			"Anthropic key",
			"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
			pii.CatAPIKeyAnthropic, 1,
		},
		{
			"Google API key",
			"GOOGLE_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv",
			pii.CatAPIKeyGoogle, 1,
		},
		{
			"AWS access key",
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			pii.CatAWSAccessKey, 1,
		},
		{
			"AWS secret key",
			"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			pii.CatAWSSecretKey, 1,
		},
		{
			"GitHub PAT",
			"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			pii.CatGitHubToken, 1,
		},
		{
			"GitLab PAT",
			"GITLAB_TOKEN=glpat-abcdefghijklmnopqrstuv",
			pii.CatGitLabToken, 1,
		},
		{
			"Slack bot token",
			"SLACK_TOKEN=xoxb-123456789-abcdefghij",
			pii.CatSlackToken, 1,
		},
		{
			"Stripe secret key",
			"STRIPE_KEY=sk_test_00000000000000000000",
			pii.CatStripeKey, 1,
		},
		{
			"Stripe publishable key",
			"pk_test_00000000000000000000",
			pii.CatStripeKey, 1,
		},
		{
			"SendGrid key",
			"SG.0000000000000000000000.0000000000000000000000000000000000000000000",
			pii.CatSendGridKey, 1,
		},
		{
			"Twilio key",
			"TWILIO=SK00000000000000000000000000000000",
			pii.CatTwilioKey, 1,
		},
		{
			"NPM token",
			"NPM_TOKEN=npm_abcdefghijklmnopqrstuv",
			pii.CatNPMToken, 1,
		},
		{
			"PyPI token",
			"PYPI_TOKEN=pypi-abcdefghijklmnopqrstuv",
			pii.CatPyPIToken, 1,
		},
		{
			"Docker PAT",
			"DOCKER=dckr_pat_abcdefghijklmnopqrstuv",
			pii.CatDockerToken, 1,
		},
		{
			"Hugging Face token",
			"HF_TOKEN=hf_abcdefghijklmnopqrstuv",
			pii.CatHuggingFace, 1,
		},
		{
			"Replicate token",
			"REPLICATE=r8_abcdefghijklmnopqrstuv",
			pii.CatReplicateToken, 1,
		},
		{
			"PEM private key",
			"-----BEGIN RSA PRIVATE KEY-----",
			pii.CatPEMPrivateKey, 1,
		},
		{
			"PEM EC private key",
			"-----BEGIN EC PRIVATE KEY-----",
			pii.CatPEMPrivateKey, 1,
		},
		{
			"JWT token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A",
			pii.CatJWT, 1,
		},
		{
			"MongoDB connection string",
			"mongodb://admin:secretpass@db.example.com:27017/mydb",
			pii.CatConnectionStr, 1,
		},
		{
			"PostgreSQL connection string",
			"postgres://user:password123@localhost:5432/mydb",
			pii.CatConnectionStr, 1,
		},
		{
			"Redis connection string",
			"redis://default:mypassword@redis.example.com:6379",
			pii.CatConnectionStr, 1,
		},
		{
			"Generic password",
			"PASSWORD=mysupersecretpassword123",
			pii.CatGenericSecret, 1,
		},
		{
			"Generic secret with quotes",
			`SECRET="my-secret-value-here"`,
			pii.CatGenericSecret, 1,
		},
		{
			"Encryption key env var",
			"ENCRYPTION_KEY=3783d5176a38886071bf04296c8106524899db278bcfed69352393c7d64f32c9",
			pii.CatHexSecret, 1,
		},
		{
			"not a secret - short value",
			"PASSWORD=short",
			pii.CatGenericSecret, 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.ResetCounters()
			matches := filterByCategory(d.Scan(tt.input), tt.cat)
			if len(matches) != tt.expect {
				all := d.Scan(tt.input)
				t.Errorf("expected %d %s matches, got %d (all matches: %v)",
					tt.expect, tt.cat, len(matches), all)
			}
		})
	}
}

func TestScan_SecretsDisabled(t *testing.T) {
	d := NewWithConfig(Config{
		Sensitivity:   SensitivityMedium,
		EnableVietnam: true,
		EnableIntl:    true,
		EnableSecrets: false,
	})

	secrets := []string{
		"sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"-----BEGIN RSA PRIVATE KEY-----",
		"PASSWORD=mysupersecretpassword123",
	}

	for _, s := range secrets {
		matches := d.Scan(s)
		for _, m := range matches {
			cat := string(m.Category)
			if len(cat) > 7 && cat[:7] == "SECRET_" {
				t.Errorf("with EnableSecrets=false, should not detect %s in %q", m.Category, s)
			}
		}
	}
}

func TestAnonymize_WithSecrets(t *testing.T) {
	d := New()

	input := "Config: ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz and DB=postgres://admin:secret@db:5432/app"
	anonymized, mapping := d.Anonymize(input)

	// Original secrets must not appear in full
	if containsAny(anonymized, "sk-ant-api03-abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("anonymized text still contains full Anthropic key: %s", anonymized)
	}
	if containsAny(anonymized, "postgres://admin:secret@db:5432/app") {
		t.Errorf("anonymized text still contains full connection string: %s", anonymized)
	}

	// Mapping should exist
	if len(mapping) == 0 {
		t.Fatal("mapping is empty, expected secret entries")
	}

	// Secrets should be partially masked (contain * characters)
	for token, original := range mapping {
		if pii.IsSecretCategory(pii.CatAPIKeyAnthropic) && original == "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" {
			if !containsAny(token, "*") {
				t.Errorf("expected partial mask with * for Anthropic key, got: %s", token)
			}
			// Should still show prefix
			if !containsAny(token, "sk-ant") {
				t.Errorf("partial mask should show prefix, got: %s", token)
			}
		}
	}
}

func TestAnonymize_SecretPartialMask(t *testing.T) {
	d := New()

	input := "ENCRYPTION_KEY=3783d5176a38886071bf04296c8106524899db278bcfed69352393c7d64f32c9"
	anonymized, _ := d.Anonymize(input)

	// Full hex value must not appear
	if containsAny(anonymized, "3783d5176a38886071bf04296c8106524899db278bcfed69352393c7d64f32c9") {
		t.Errorf("anonymized text still contains full hex key: %s", anonymized)
	}

	// Partial prefix should be visible
	if !containsAny(anonymized, "3783d5") {
		t.Errorf("expected visible prefix in partial mask, got: %s", anonymized)
	}

	// Should contain mask characters
	if !containsAny(anonymized, "***") {
		t.Errorf("expected * mask characters, got: %s", anonymized)
	}

	t.Logf("masked output: %s", anonymized)
}

// BenchmarkScan benchmarks detector performance
func BenchmarkScan(b *testing.B) {
	d := New()
	input := "Xin chào, CCCD 012345678901, email test@example.com, SĐT 0901234567. MST: 1234567890. Tôi ở số 10, đường Nguyễn Huệ, phường Bến Nghé, quận 1."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Scan(input)
	}
}

func BenchmarkAnonymize(b *testing.B) {
	d := New()
	input := "CCCD: 012345678901, email: test@example.com, SĐT: 0901234567"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ResetCounters()
		d.Anonymize(input)
	}
}

// helpers

func filterByCategory(matches []Match, cat pii.Category) []Match {
	var filtered []Match
	for _, m := range matches {
		if m.Category == cat {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
