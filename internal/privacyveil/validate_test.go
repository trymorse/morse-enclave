package privacyveil

import (
	"slices"
	"testing"
)

func found(text string, t Type) []string {
	var got []string
	for _, s := range Validated(text) {
		if s.Type == t {
			got = append(got, text[s.Start:s.End])
		}
	}
	return got
}

func TestTheValidatorsFindSocialSecurityNumbersBySSARules(t *testing.T) {
	for text, want := range map[string][]string{
		"SSN 512-44-7810 on file":              {"512-44-7810"},
		"spaced 512 44 7810":                   {"512 44 7810"},
		"mixed 512-44 7810":                    nil,
		"area 000-12-3456, 666-12-3456":        nil,
		"area 912-34-5678":                     nil,
		"group 512-00-7810 serial 512-44-0000": nil,
		"part of 1512-44-78101":                nil,
		"my social security number: 512447810": {"512447810"},
		"order 512447810 shipped":              nil,
	} {
		if got := found(text, SSN); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

func TestTheValidatorsFindCardsThatPassLuhnWithAKnownIssuer(t *testing.T) {
	for text, want := range map[string][]string{
		"visa 4111 1111 1111 1111 thanks":     {"4111 1111 1111 1111"},
		"amex 3782-822463-10005":              {"3782-822463-10005"},
		"mc 5555555555554444.":                {"5555555555554444"},
		"luhn fails 4111 1111 1111 1112":      nil,
		"unknown issuer 9111111111111117":     nil,
		"mixed 4111 1111-1111 1111":           nil,
		"card 4111 1111 1111 1111 exp 1227":   {"4111 1111 1111 1111"},
		"card 4111 1111 1111 1111 1227 total": {"4111 1111 1111 1111"},
	} {
		if got := found(text, Card); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

func TestOverlappingSpansMergeAndAValidatedNumberKeepsItsType(t *testing.T) {
	filtered := []Span{{Start: 4, End: 15, Type: Phone}, {Start: 20, End: 30, Type: Name}, {Start: 25, End: 40, Type: Address}}
	validated := []Span{{Start: 4, End: 15, Type: SSN}}
	got := merge(filtered, validated)
	want := []Span{{Start: 4, End: 15, Type: SSN}, {Start: 20, End: 40, Type: Address}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := merge([]Span{{Start: 0, End: 10, Type: Date}, {Start: 5, End: 8, Type: Secret}}, nil); got[0].Type != Secret || got[0].End != 10 {
		t.Errorf("a secret inside a date should make the merged span a secret: %+v", got)
	}
}

func TestByteOffsetsCountCodePointsAsTheFilterDoes(t *testing.T) {
	text := "hi 👋 José 東京"
	for _, c := range []struct{ start, end, bs, be int }{{0, 2, 0, 2}, {3, 4, 3, 7}, {5, 9, 8, 13}, {10, 12, 14, 20}, {12, 12, 20, 20}} {
		bs, be, ok := ByteOffsets(text, c.start, c.end)
		if !ok || bs != c.bs || be != c.be {
			t.Errorf("(%d,%d) = (%d,%d,%v), want (%d,%d)", c.start, c.end, bs, be, ok, c.bs, c.be)
		}
	}
	for _, c := range [][2]int{{-1, 2}, {3, 2}, {0, 13}} {
		if _, _, ok := ByteOffsets(text, c[0], c[1]); ok {
			t.Errorf("(%d,%d) should be out of range", c[0], c[1])
		}
	}
}

func TestEveryFilterLabelHasATypeAndAnUnknownOneIsPII(t *testing.T) {
	for label, want := range map[string]Type{"private_person": Name, "private_address": Address, "private_email": Email,
		"private_phone": Phone, "private_url": URL, "private_date": Date, "account_number": Account, "secret": Secret} {
		if got, known := TypeOfLabel(label); !known || got != want {
			t.Errorf("%s: %v (%v), want %v", label, got, known, want)
		}
	}
	if got, known := TypeOfLabel("private_passport"); known || got != PII {
		t.Errorf("an unknown label is %v (%v), want PII", got, known)
	}
}
