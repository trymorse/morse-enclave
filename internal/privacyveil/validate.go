package privacyveil

import (
	"regexp"
	"strings"
)

var (
	ssnShape    = regexp.MustCompile(`\d{3}[- ]\d{2}[- ]\d{4}`)
	bareSSN     = regexp.MustCompile(`\d{9}`)
	cardShape   = regexp.MustCompile(`\d(?:[ -]?\d){11,18}`)
	ssnContext  = []string{"ssn", "social security"}
	contextBack = 40
)

// Validated finds the Social Security and payment card numbers in text that pass their checks, which the filter may
// miss or label only as an account number.
func Validated(text string) []Span {
	var spans []Span
	for _, at := range ssnShape.FindAllStringIndex(text, -1) {
		s := text[at[0]:at[1]]
		if bounded(text, at[0], at[1]) && s[3] == s[6] && validSSN(onlyDigits(s)) {
			spans = append(spans, Span{Start: at[0], End: at[1], Type: SSN})
		}
	}
	for _, at := range bareSSN.FindAllStringIndex(text, -1) {
		if bounded(text, at[0], at[1]) && validSSN(text[at[0]:at[1]]) && namesSSN(text[max(0, at[0]-contextBack):at[0]]) {
			spans = append(spans, Span{Start: at[0], End: at[1], Type: SSN})
		}
	}
	for _, at := range cardShape.FindAllStringIndex(text, -1) {
		if end, ok := cardEnd(text, at[0], at[1]); ok {
			spans = append(spans, Span{Start: at[0], End: end, Type: Card})
		}
	}
	return spans
}

// cardEnd is where a valid card number that opens text[start:end] ends: the whole run, or a run cut back by whole
// groups, since a card is often followed by its expiry or another number.
func cardEnd(text string, start, end int) (int, bool) {
	if start > 0 && isDigit(rune(text[start-1])) {
		return 0, false
	}
	s := text[start:end]
	if !consistentGroups(s) {
		return 0, false
	}
	for cut := len(s); cut > 0; cut = strings.LastIndexAny(s[:cut], " -") {
		if (start+cut == len(text) || !isDigit(rune(text[start+cut]))) && validCard(onlyDigits(s[:cut])) {
			return start + cut, true
		}
	}
	return 0, false
}

// bounded is a number that no digit runs on into.
func bounded(text string, start, end int) bool {
	return (start == 0 || !isDigit(rune(text[start-1]))) && (end == len(text) || !isDigit(rune(text[end])))
}

func namesSSN(before string) bool {
	before = strings.ToLower(before)
	for _, name := range ssnContext {
		if strings.Contains(before, name) {
			return true
		}
	}
	return false
}

// validSSN follows the SSA's rules: no area 000, 666, or 900 to 999, no group 00, and no serial 0000.
func validSSN(d string) bool {
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[:3], d[3:5], d[5:]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

// consistentGroups is a card number written with one kind of separator, or none.
func consistentGroups(s string) bool { return !(strings.Contains(s, " ") && strings.Contains(s, "-")) }

func validCard(d string) bool {
	return luhn(d) && knownIIN(d)
}

func luhn(d string) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

type iinRange struct {
	low, high string
	lengths   []int
}

var iins = []iinRange{
	{"4", "4", []int{13, 16, 19}},
	{"51", "55", []int{16}},
	{"2221", "2720", []int{16}},
	{"34", "34", []int{15}},
	{"37", "37", []int{15}},
	{"6011", "6011", []int{16, 17, 18, 19}},
	{"644", "649", []int{16, 17, 18, 19}},
	{"65", "65", []int{16, 17, 18, 19}},
	{"3528", "3589", []int{16, 17, 18, 19}},
	{"300", "305", []int{14, 15, 16, 17, 18, 19}},
	{"36", "36", []int{14, 15, 16, 17, 18, 19}},
	{"38", "39", []int{16, 17, 18, 19}},
	{"62", "62", []int{16, 17, 18, 19}},
}

func knownIIN(d string) bool {
	for _, r := range iins {
		if len(d) < len(r.low) {
			continue
		}
		prefix := d[:len(r.low)]
		if prefix >= r.low && prefix <= r.high && containsInt(r.lengths, len(d)) {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
