package privacyveil

import (
	"encoding/json"
	"strings"
	"testing"
)

func heroVeil() *Veil {
	return veilOf([]string{"Call Jane Doe at 415-555-0199 or jane@doe.io, SSN 512-44-7810"},
		map[string]Type{"Jane Doe": Name, "415-555-0199": Phone, "jane@doe.io": Email, "512-44-7810": SSN})
}

func restoreAll(r *Restorer, fragments ...string) string {
	var out strings.Builder
	for _, f := range fragments {
		out.WriteString(r.Next(f))
	}
	out.WriteString(r.Flush())
	return out.String()
}

func TestTheRestorerPutsValuesBackAcrossFragments(t *testing.T) {
	v := heroVeil()
	got := restoreAll(v.Restorer(), "Call [NAM", "E_1] at [PH", "ONE_1].")
	if want := "Call Jane Doe at 415-555-0199."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTheRestorerHoldsBackOnlyWhatCouldStillBeAPlaceholder(t *testing.T) {
	r := heroVeil().Restorer()
	if got := r.Next("Call [NAM"); got != "Call " {
		t.Errorf("first fragment sent %q", got)
	}
	if got := r.Next("BER] and [1]"); got != "[NAMBER] and [1]" {
		t.Errorf("text that turned out not to be a placeholder came out as %q", got)
	}
}

func TestBarePlaceholdersAreRestoredOnlyAsWholeWords(t *testing.T) {
	v := heroVeil()
	for in, want := range map[string]string{
		"Hi NAME_1!":               "Hi Jane Doe!",
		"Hi NAME_1":                "Hi Jane Doe",
		"MYNAME_1 and NAME_12":     "MYNAME_1 and NAME_12",
		"[NAME_9] is not assigned": "[NAME_9] is not assigned",
		"email:EMAIL_1.":           "email:jane@doe.io.",
	} {
		if got := restoreAll(v.Restorer(), in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestABarePlaceholderAtAFragmentsEndWaitsForTheNextByte(t *testing.T) {
	r := heroVeil().Restorer()
	if got := r.Next("Hi NAME_1"); got != "Hi " {
		t.Errorf("sent %q before knowing whether NAME_1 ends there", got)
	}
	if got := r.Next("2 is next"); got != "NAME_12 is next" {
		t.Errorf("got %q", got)
	}
}

func TestToolArgumentsKeepTheirPlaceholdersUnlessAGrantReleasesThem(t *testing.T) {
	v := heroVeil()
	held := v.ArgumentRestorer(nil)
	if got := restoreAll(held, `{"to":"[EMAIL_1]","ssn":"[SSN_1]"}`); got != `{"to":"[EMAIL_1]","ssn":"[SSN_1]"}` {
		t.Errorf("without a grant: %s", got)
	}
	if got := held.Held(); len(got) != 2 || got[0] != "[EMAIL_1]" || got[1] != "[SSN_1]" {
		t.Errorf("held %v", got)
	}
	ask, err := ParseAsk(json.RawMessage(`{"release":[{"tool":"send_email","types":["*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	granted := v.ArgumentRestorer(ask.Releases("send_email"))
	got := restoreAll(granted, `{"to":"[EMA`, `IL_1]","body":"Hi [NAME_1], SSN [SSN_1]","n":[PHONE_1]}`)
	want := `{"to":"jane@doe.io","body":"Hi Jane Doe, SSN [SSN_1]","n":"415-555-0199"}`
	if got != want {
		t.Errorf("with a wildcard grant:\n got %s\nwant %s", got, want)
	}
	if !json.Valid([]byte(got)) {
		t.Errorf("the released arguments are not JSON: %s", got)
	}
}

func TestAReleasedValueIsEscapedInsideAJSONString(t *testing.T) {
	v := New([]Segment{{Text: `Ann "The Quill" O\Brien`}}, [][]Span{{{Start: 0, End: 23, Type: Name}}})
	ask, _ := ParseAsk(json.RawMessage(`{"release":[{"tool":"*","types":["NAME"]}]}`))
	got := restoreAll(v.ArgumentRestorer(ask.Releases("any")), `{"who":"[NAME_1] \"quoted\""}`)
	var decoded struct{ Who string }
	if err := json.Unmarshal([]byte(got), &decoded); err != nil || decoded.Who != `Ann "The Quill" O\Brien "quoted"` {
		t.Errorf("got %s (%v)", got, err)
	}
}

func TestRestoreNoneReleasesNothing(t *testing.T) {
	ask, err := ParseAsk(json.RawMessage(`{"restore":"none","release":[{"tool":"*","types":["*","SSN"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if ask.Releases("anything")(Name) || ask.Releases("anything")(SSN) {
		t.Error("restore none released a value")
	}
}

func FuzzAnySplitRestoresAsTheWholeDoes(f *testing.F) {
	f.Add("Call [NAME_1] at [PHONE_1] or EMAIL_1; [SSN_1]! NAME_12 [NAME_", 3, 7)
	f.Add("[[[NAME_1]]] NAME_1NAME_1 [PHONE_1", 1, 2)
	v := heroVeil()
	f.Fuzz(func(t *testing.T, text string, a, b int) {
		whole := restoreAll(v.Restorer(), text)
		cuts := []int{0, abs(a) % (len(text) + 1), abs(b) % (len(text) + 1), len(text)}
		if cuts[1] > cuts[2] {
			cuts[1], cuts[2] = cuts[2], cuts[1]
		}
		got := restoreAll(v.Restorer(), text[cuts[0]:cuts[1]], text[cuts[1]:cuts[2]], text[cuts[2]:cuts[3]])
		if got != whole {
			t.Errorf("split at %v: %q, whole: %q", cuts[1:3], got, whole)
		}
	})
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
