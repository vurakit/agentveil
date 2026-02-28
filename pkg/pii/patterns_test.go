package pii

import "testing"

func TestSecretPatterns_Compile(t *testing.T) {
	patterns := SecretPatterns()
	if len(patterns) == 0 {
		t.Fatal("SecretPatterns() returned empty slice")
	}

	for i, p := range patterns {
		if p.Regex == nil {
			t.Errorf("pattern[%d] (%s) has nil Regex", i, p.Label)
		}
		if p.Category == "" {
			t.Errorf("pattern[%d] has empty Category", i)
		}
		if p.Label == "" {
			t.Errorf("pattern[%d] (%s) has empty Label", i, p.Category)
		}
	}
}

func TestSecretPatterns_TokenPrefixCoverage(t *testing.T) {
	patterns := SecretPatterns()

	// Collect all unique categories from secret patterns
	categories := make(map[Category]bool)
	for _, p := range patterns {
		categories[p.Category] = true
	}

	// Every category must have a TokenPrefix entry
	for cat := range categories {
		if _, ok := TokenPrefix[cat]; !ok {
			t.Errorf("category %s has no TokenPrefix entry", cat)
		}
	}
}

func TestPartialMask(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPfx string // visible prefix
		wantStar bool  // should contain *
	}{
		{
			"hex key 64 chars",
			"3783d5176a38886071bf04296c8106524899db278bcfed69352393c7d64f32c9",
			"3783d5176a38886071bf04296", // ~40% of 64 = 25 chars visible
			true,
		},
		{
			"short secret",
			"mypasswd",
			"my",
			true,
		},
		{
			"api key",
			"sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
			"sk-ant-api03-ab",
			true,
		},
		{
			"very short",
			"ab",
			"",
			true, // all masked
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PartialMask(tt.input)

			// Must not equal original
			if got == tt.input {
				t.Errorf("PartialMask should change the value, got unchanged: %s", got)
			}

			// Must be same length as original
			if len(got) != len(tt.input) {
				t.Errorf("PartialMask length mismatch: input=%d, got=%d (%s)", len(tt.input), len(got), got)
			}

			// Should contain * characters
			if tt.wantStar {
				hasStar := false
				for _, c := range got {
					if c == '*' {
						hasStar = true
						break
					}
				}
				if !hasStar {
					t.Errorf("expected * in masked output, got: %s", got)
				}
			}

			// Visible prefix check
			if tt.wantPfx != "" && len(got) >= len(tt.wantPfx) {
				if got[:len(tt.wantPfx)] != tt.wantPfx {
					t.Errorf("expected prefix %q, got %q", tt.wantPfx, got[:len(tt.wantPfx)])
				}
			}

			t.Logf("%s → %s", tt.input, got)
		})
	}
}

func TestIsSecretCategory(t *testing.T) {
	if !IsSecretCategory(CatAPIKeyOpenAI) {
		t.Error("CatAPIKeyOpenAI should be a secret category")
	}
	if !IsSecretCategory(CatHexSecret) {
		t.Error("CatHexSecret should be a secret category")
	}
	if IsSecretCategory(CatEmail) {
		t.Error("CatEmail should not be a secret category")
	}
	if IsSecretCategory(CatCCCD) {
		t.Error("CatCCCD should not be a secret category")
	}
}

func TestVietnamPatterns_Compile(t *testing.T) {
	patterns := VietnamPatterns()
	if len(patterns) == 0 {
		t.Fatal("VietnamPatterns() returned empty slice")
	}
	for i, p := range patterns {
		if p.Regex == nil {
			t.Errorf("pattern[%d] (%s) has nil Regex", i, p.Label)
		}
	}
}

func TestInternationalPatterns_Compile(t *testing.T) {
	patterns := InternationalPatterns()
	if len(patterns) == 0 {
		t.Fatal("InternationalPatterns() returned empty slice")
	}
	for i, p := range patterns {
		if p.Regex == nil {
			t.Errorf("pattern[%d] (%s) has nil Regex", i, p.Label)
		}
	}
}
