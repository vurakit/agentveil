package auditor

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// Anti-evasion: detect obfuscation techniques used to bypass auditor

var (
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	hexPattern    = regexp.MustCompile(`(?i)(?:0x|\\x)[0-9a-f]{2}(?:[0-9a-f]{2}){3,}`)
)

// DeobfuscateLine attempts to reveal hidden instructions in a line
func DeobfuscateLine(line string) []string {
	var revealed []string

	// 1. Decode base64 segments
	for _, match := range base64Pattern.FindAllString(line, -1) {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil && isPrintable(string(decoded)) {
			revealed = append(revealed, string(decoded))
		}
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(match)
		if err == nil && isPrintable(string(decoded)) {
			revealed = append(revealed, string(decoded))
		}
	}

	// 2. Normalize Unicode tricks (homoglyphs, zero-width chars)
	normalized := normalizeUnicode(line)
	if normalized != line {
		revealed = append(revealed, normalized)
	}

	// 3. Detect split keywords: "by" + "pass" → "bypass"
	joined := removeSplitters(line)
	if joined != line {
		revealed = append(revealed, joined)
	}

	return revealed
}

// normalizeUnicode replaces homoglyphs and removes zero-width characters
func normalizeUnicode(s string) string {
	var b strings.Builder
	for _, r := range s {
		// Remove zero-width characters
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			continue
		}
		// Replace common homoglyphs
		if replacement, ok := homoglyphs[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// homoglyphs maps visually similar Unicode chars to ASCII equivalents
var homoglyphs = map[rune]rune{
	'а': 'a', // Cyrillic
	'е': 'e',
	'о': 'o',
	'р': 'p',
	'с': 'c',
	'у': 'y',
	'х': 'x',
	'Ⅰ': 'I', // Roman numerals
	'０': '0', // Fullwidth
	'１': '1',
	'ａ': 'a',
	'ｂ': 'b',
}

// removeSplitters joins words that were split with dots, dashes, spaces to evade detection
func removeSplitters(s string) string {
	// "b.y.p.a.s.s" → "bypass", "e x e c" → "exec"
	replacer := strings.NewReplacer(
		". ", "", " . ", "", ".", "",
	)
	candidate := replacer.Replace(s)

	// Also try removing excessive spaces between single chars: "b y p a s s"
	words := strings.Fields(s)
	allSingle := true
	for _, w := range words {
		if len([]rune(w)) > 2 {
			allSingle = false
			break
		}
	}
	if allSingle && len(words) > 3 {
		candidate = strings.Join(words, "")
	}

	return candidate
}

func isPrintable(s string) bool {
	if len(s) < 4 {
		return false
	}
	printable := 0
	for _, r := range s {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) > 0.8
}
