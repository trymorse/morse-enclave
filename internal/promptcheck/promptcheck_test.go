package promptcheck

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestASexualPromptIsRefusedOnlyWithAMinorOrANamedPerson(t *testing.T) {
	for name, c := range map[string]struct {
		ask    Ask
		scores Scores
		want   bool
	}{
		"nothing":                          {Ask{}, Scores{}, false},
		"sexual, adults alone":             {Ask{}, Scores{Sexual: 1}, false},
		"a minor, not sexual":              {Ask{}, Scores{Minor: 1}, false},
		"a named person, not sexual":       {Ask{}, Scores{RealPerson: 1}, false},
		"a minor and sexual":               {Ask{}, Scores{Minor: 0.2, Sexual: 0.2}, true},
		"a minor under the cut and sexual": {Ask{}, Scores{Minor: 0.19, Sexual: 1}, false},
		"a minor and sexual under the cut": {Ask{}, Scores{Minor: 1, Sexual: 0.19}, false},
		"a named person and sexual":        {Ask{}, Scores{RealPerson: 0.2, Sexual: 0.2}, true},
		"an adult model's sexual prompt":   {Ask{Adult: true}, Scores{Sexual: 1}, false},
		"a minor on an adult model":        {Ask{Adult: true}, Scores{Minor: 0.2}, true},
		"a named person on an adult model": {Ask{Adult: true}, Scores{RealPerson: 0.2}, true},
	} {
		if got, err := Refuses(c.ask, c.scores); err != nil || got != c.want {
			t.Errorf("%s: %v, %v, want %v", name, got, err, c.want)
		}
	}
}

func TestAScoreThatIsNoProbabilityIsNoVerdict(t *testing.T) {
	for _, s := range []Scores{{Minor: math.NaN()}, {RealPerson: -0.1}, {Sexual: 1.1}, {Sexual: math.Inf(1)}} {
		if _, err := Refuses(Ask{}, s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%+v: %v, want ErrMalformed", s, err)
		}
	}
}

func TestAnHourIsReportedOnlyOnceItEndedAndForgottenADayLater(t *testing.T) {
	var totals Totals
	at := time.Date(2026, 12, 1, 10, 59, 59, 0, time.UTC)
	totals.Add(at, Image, Refused)
	totals.Add(at, Image, Refused)
	totals.Add(at, Video, Allowed)
	if ended := totals.Ended(at); len(ended) != 0 {
		t.Errorf("an hour still open was reported: %v", ended)
	}
	want := []Total{
		{Hour: at.Truncate(time.Hour), Kind: Image, Outcome: Refused, N: 2},
		{Hour: at.Truncate(time.Hour), Kind: Video, Outcome: Allowed, N: 1},
	}
	for range 2 {
		if ended := totals.Ended(at.Add(time.Second)); !reflect.DeepEqual(ended, want) {
			t.Errorf("ended %v, want %v each time it is read", ended, want)
		}
	}
	totals.Add(at.Add(26*time.Hour), Image, Allowed)
	if ended := totals.Ended(at.Add(26 * time.Hour)); len(ended) != 0 {
		t.Errorf("a day-old hour was kept: %v", ended)
	}
}
