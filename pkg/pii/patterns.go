package pii

import "regexp"

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
