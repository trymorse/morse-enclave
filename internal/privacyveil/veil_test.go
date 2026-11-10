package privacyveil

import (
	"slices"
	"strings"
	"testing"
)

// spansOf marks each of values where it first appears in text, as typ.
func spansOf(text string, typed map[string]Type) []Span {
	var spans []Span
	for value, t := range typed {
		if i := strings.Index(text, value); i >= 0 {
			spans = append(spans, Span{Start: i, End: i + len(value), Type: t})
		}
	}
	return spans
}

func veilOf(texts []string, typed map[string]Type) *Veil {
	segments := make([]Segment, len(texts))
	spans := make([][]Span, len(texts))
	for i, text := range texts {
		segments[i] = Segment{Text: text, Literal: true}
		spans[i] = spansOf(text, typed)
	}
	return New(segments, spans)
}

func TestTheHeroExamplesBecomeTheirPlaceholders(t *testing.T) {
	v := veilOf([]string{"Call Jane Doe at 415-555-0199", "Ship it to 12 Elm St, Austin", "My SSN is 512-44-7810, file it"},
		map[string]Type{"Jane Doe": Name, "415-555-0199": Phone, "12 Elm St, Austin": Address, "512-44-7810": SSN})
	for in, want := range map[string]string{
		"Call Jane Doe at 415-555-0199":   "Call [NAME_1] at [PHONE_1]",
		"Ship it to 12 Elm St, Austin":    "Ship it to [ADDRESS_1]",
		"My SSN is 512-44-7810, file it":  "My SSN is [SSN_1], file it",
		"jane doe called (415) 555-0199.": "[NAME_1] called [PHONE_1].",
	} {
		if got := v.Substitute(in); got != want {
			t.Errorf("Substitute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEachTypeNumbersFromOneInTheOrderItsDetailsFirstAppear(t *testing.T) {
	v := veilOf([]string{"Ann Lee wrote to Bo Park.", "Then Ann Lee met Cy Diaz at 9 Oak Ave."},
		map[string]Type{"Ann Lee": Name, "Bo Park": Name, "Cy Diaz": Name, "9 Oak Ave": Address})
	got := v.Substitute("Bo Park, Cy Diaz, Ann Lee, 9 Oak Ave")
	if want := "[NAME_2], [NAME_3], [NAME_1], [ADDRESS_1]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestANumberingIsTheSameEveryTimeTheSameTextIsVeiled(t *testing.T) {
	texts := []string{"Mia Chen and Leo Cruz live at 4 Pine Rd with Ava Shah."}
	typed := map[string]Type{"Mia Chen": Name, "Leo Cruz": Name, "4 Pine Rd": Address, "Ava Shah": Name}
	first := veilOf(texts, typed).Substitute(texts[0])
	for range 20 {
		if again := veilOf(texts, typed).Substitute(texts[0]); again != first {
			t.Fatalf("one run gave %q, another %q", first, again)
		}
	}
}

func TestAValueMatchesOnlyWhereItStandsAsItsOwnWord(t *testing.T) {
	v := veilOf([]string{"Mark Ann"}, map[string]Type{"Mark": Name, "Ann": Name})
	for in, want := range map[string]string{
		"call mark_done for Mark":    "call mark_done for [NAME_1]",
		"Annual report by Ann.":      "Annual report by [NAME_2].",
		"“Mark” said, «Ann»":         "“[NAME_1]” said, «[NAME_2]»",
		"Markus and Joann are not.":  "Markus and Joann are not.",
		"MARK wrote to ann directly": "[NAME_1] wrote to [NAME_2] directly",
	} {
		if got := v.Substitute(in); got != want {
			t.Errorf("Substitute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestANameStandsForItselfByItsPartsUnlessTwoNamesShareThePart(t *testing.T) {
	v := veilOf([]string{"Jane Doe met John Doe and Jane."}, map[string]Type{"Jane Doe": Name, "John Doe": Name})
	got := v.Substitute("Jane Doe met John Doe. Later Jane and John saw Doe.")
	if want := "[NAME_1] met [NAME_2]. Later [NAME_1] and [NAME_2] saw [NAME_3]."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if entities := v.Entities(); len(entities) != 3 || entities[2].Value != "Doe" {
		t.Errorf("the shared part should be a detail of its own: %+v", entities)
	}
}

func TestAOneWordNameThatIsAPartOfALongerNameJoinsIt(t *testing.T) {
	segments := []Segment{{Text: "Jane wrote. Jane Doe signed."}}
	spans := [][]Span{{{Start: 0, End: 4, Type: Name}, {Start: 12, End: 20, Type: Name}}}
	v := New(segments, spans)
	if got, want := v.Substitute(segments[0].Text), "[NAME_1] wrote. [NAME_1] signed."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if n := len(v.Entities()); n != 1 {
		t.Errorf("%d details, want 1: the one-word name is the longer one's part", n)
	}
}

func TestAPlaceholderTheClientWritesIsNeverAssignedToAValue(t *testing.T) {
	segments := []Segment{{Text: "Template: Dear [NAME_1], NAME_2 says hi.", Literal: true}, {Text: "From Ana Ruiz"}}
	spans := [][]Span{nil, {{Start: 5, End: 13, Type: Name}}}
	v := New(segments, spans)
	if got, want := v.Substitute("Ana Ruiz"), "[NAME_3]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	assistant := New([]Segment{{Text: "sent to [EMAIL_1]"}, {Text: "a@b.co", Literal: true}}, [][]Span{nil, {{Start: 0, End: 6, Type: Email}}})
	if got := assistant.Substitute("a@b.co"); got != "[EMAIL_1]" {
		t.Errorf("a placeholder echoed in assistant text is not the client's own, so numbering keeps it: %q", got)
	}
}

func TestHoldsCatchesAValueThatSurvivesAndIgnoresThePlaceholders(t *testing.T) {
	v := veilOf([]string{"Ivy Stone, 4111 1111 1111 1111"}, map[string]Type{"Ivy Stone": Name, "4111 1111 1111 1111": Card})
	if v.Holds("[NAME_1] paid with [CARD_1]") {
		t.Error("placeholders alone hold no value")
	}
	for _, leak := range []string{"ivy stone", "4111-1111-1111-1111", "card 4111111111111111.", "Ivy said hi"} {
		if !v.Holds(leak) {
			t.Errorf("Holds(%q) is false", leak)
		}
	}
}

func TestAnEmptyVeilChangesNothing(t *testing.T) {
	v := New([]Segment{{Text: "nothing here"}}, [][]Span{nil})
	if !v.Empty() || v.Substitute("nothing here") != "nothing here" || v.Holds("nothing here") {
		t.Error("a veil that found nothing changed or flagged text")
	}
}

func TestSpansOutsideTheirTextAreIgnored(t *testing.T) {
	v := New([]Segment{{Text: "héllo"}}, [][]Span{{{Start: 2, End: 4, Type: Name}, {Start: 3, End: 99, Type: Name}}})
	if !v.Empty() {
		t.Errorf("a span off a rune boundary or past the text made details: %+v", v.Entities())
	}
}

func TestTheValueIsTheFirstSurfaceSeenAndKeepsItsCase(t *testing.T) {
	v := veilOf([]string{"JANE DOE", "Jane Doe"}, map[string]Type{"JANE DOE": Name, "Jane Doe": Name})
	entities := v.Entities()
	if len(entities) != 1 || entities[0].Value != "JANE DOE" {
		t.Errorf("entities %+v", entities)
	}
	if got := v.Substitute("Jane Doe and JANE DOE"); got != "[NAME_1] and [NAME_1]" {
		t.Errorf("got %q", got)
	}
}

func TestTheVeilRedactsItselfInLogs(t *testing.T) {
	v := veilOf([]string{"Secret Person"}, map[string]Type{"Secret Person": Name})
	for _, s := range []string{v.String(), v.GoString()} {
		if strings.Contains(s, "Secret") {
			t.Errorf("%q names a value", s)
		}
	}
}

func TestEntitiesAreInPlaceholderOrder(t *testing.T) {
	v := veilOf([]string{"Eve Moss emailed eve@moss.io"}, map[string]Type{"Eve Moss": Name, "eve@moss.io": Email})
	var got []string
	for _, e := range v.Entities() {
		got = append(got, e.Placeholder+"="+e.Value)
	}
	if want := []string{"[NAME_1]=Eve Moss", "[EMAIL_1]=eve@moss.io"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestADetailInsideALinkIsVeiledAsALinkWritesIt(t *testing.T) {
	v := veilOf([]string{"Ship to 12 Elm St, Austin and mail jane@doe.io"}, map[string]Type{"12 Elm St, Austin": Address, "jane@doe.io": Email})
	for in, want := range map[string]string{
		"https://maps.test/?q=12+Elm+St%2C+Austin&z=3":      "https://maps.test/?q=[ADDRESS_1]&z=3",
		"https://maps.test/place/12%20Elm%20St%2C%20Austin": "https://maps.test/place/[ADDRESS_1]",
		"mailto:jane%40doe.io":                              "mailto:[EMAIL_1]",
		"https://x.test/?to=JANE%40DOE.IO":                  "https://x.test/?to=[EMAIL_1]",
	} {
		if got := v.Substitute(in); got != want {
			t.Errorf("Substitute(%q) = %q, want %q", in, got, want)
		}
		if !v.Holds(in) {
			t.Errorf("the self-check misses the detail in %q", in)
		}
	}
}

func TestAnInternationalPhonesPlusGoesIntoItsPlaceholder(t *testing.T) {
	v := veilOf([]string{"his phone is +44 20 7946 0958"}, map[string]Type{"+44 20 7946 0958": Phone})
	for in, want := range map[string]string{
		"his phone is +44 20 7946 0958": "his phone is [PHONE_1]",
		"or 44 20 7946 0958":            "or [PHONE_1]",
		"(+44 20 7946 0958)":            "([PHONE_1])",
	} {
		if got := v.Substitute(in); got != want {
			t.Errorf("Substitute(%q) = %q, want %q", in, got, want)
		}
	}
	bare := veilOf([]string{"call 415-555-0199"}, map[string]Type{"415-555-0199": Phone})
	if got := bare.Substitute("a+415-555-0199"); got != "a+[PHONE_1]" {
		t.Errorf("a + the detail was not written with stayed outside: %q", got)
	}
}
