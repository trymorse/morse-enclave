// Package privacyveil swaps the personal details in a chat's text for placeholders before a vendor reads it, and puts
// the values back into the reply. It makes no network call: the worker hands it the spans a filter found.
package privacyveil

import (
	"strconv"
	"strings"
	"unicode"

	"morse/backend/internal/enum"
)

// Type is a kind of personal detail. Its name opens its placeholders, as in [NAME_1].
type Type uint8

const (
	_ Type = iota
	Name
	Address
	Email
	Phone
	URL
	Date
	SSN
	Card
	Account
	Secret
	PII
)

var typeNames = enum.Names[Type]{Name: "NAME", Address: "ADDRESS", Email: "EMAIL", Phone: "PHONE", URL: "URL", Date: "DATE",
	SSN: "SSN", Card: "CARD", Account: "ACCOUNT", Secret: "SECRET", PII: "PII"}

func Types() []Type { return typeNames.Values() }

func ParseType(name string) (Type, bool) { return typeNames.Parse(name) }

func (t Type) String() string { return typeNames.String(t) }

func (t Type) MarshalText() ([]byte, error) { return typeNames.MarshalText(t) }

func (t *Type) UnmarshalText(text []byte) error { return typeNames.UnmarshalText(t, text) }

// Sensitive types are released only by a grant that names them, and win a merge of spans that overlap.
func (t Type) Sensitive() bool { return t.rank() > 0 }

func (t Type) rank() int {
	switch t {
	case Secret:
		return 4
	case SSN:
		return 3
	case Card:
		return 2
	case Account:
		return 1
	}
	return 0
}

var labels = map[string]Type{"private_person": Name, "private_address": Address, "private_email": Email, "private_phone": Phone,
	"private_url": URL, "private_date": Date, "account_number": Account, "secret": Secret}

// TypeOfLabel is the type of one of the filter's labels. A label it does not know is PII, and false.
func TypeOfLabel(label string) (Type, bool) {
	if t, ok := labels[label]; ok {
		return t, true
	}
	return PII, false
}

type keying uint8

const (
	byFold keying = iota
	byDigits
	byBytes
)

// keying is how two surfaces of one detail are told to be the same: a name or an address in any case, a number in any
// punctuation, and anything else byte for byte.
func (t Type) keying() keying {
	switch t {
	case Name, Email, Address, URL:
		return byFold
	case SSN, Card, Phone, Account:
		return byDigits
	}
	return byBytes
}

func (t Type) key(surface string) string {
	switch t.keying() {
	case byFold:
		return fold(surface)
	case byDigits:
		return onlyDigits(surface)
	}
	return surface
}

func fold(s string) string { return strings.Map(unicode.ToLower, s) }

func onlyDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if isDigit(r) {
			return r
		}
		return -1
	}, s)
}

func isDigit(r rune) bool { return '0' <= r && r <= '9' }

// isWord is a letter, a digit, an underscore, or any byte of a multi-byte rune, so a value matches only where it
// stands as its own word, and a user named Mark leaves mark_done alone.
func isWord(b byte) bool {
	return b == '_' || '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || b >= 0x80
}

func placeholder(t Type, n int) string { return "[" + bare(t, n) + "]" }

func bare(t Type, n int) string { return t.String() + "_" + strconv.Itoa(n) }

// literals are the numbers already taken in text by a placeholder of each type, bracketed or bare, which a numbering
// skips so a client's own [NAME_1] never stands for a value.
func literals(text string, taken map[Type]map[int]bool) {
	for i := 0; i < len(text); i++ {
		if !isUpper(text[i]) || i > 0 && isWord(text[i-1]) {
			continue
		}
		j := i
		for j < len(text) && isUpper(text[j]) {
			j++
		}
		t, ok := ParseType(text[i:j])
		if !ok || j >= len(text) || text[j] != '_' {
			i = j
			continue
		}
		k := j + 1
		for k < len(text) && isDigit(rune(text[k])) {
			k++
		}
		if k > j+1 && (k == len(text) || !isWord(text[k])) {
			if n, err := strconv.Atoi(text[j+1 : k]); err == nil && n > 0 {
				if taken[t] == nil {
					taken[t] = map[int]bool{}
				}
				taken[t][n] = true
			}
		}
		i = k
	}
}

func isUpper(b byte) bool { return 'A' <= b && b <= 'Z' }
