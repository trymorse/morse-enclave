package research

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"morse/backend/internal/jobs"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/web"
)

const inputCanary = "INPUT-CANARY-5c19"

func TestARequestIsAModelAndOneInputOfAtMostFifteenThousandCharacters(t *testing.T) {
	req, err := ParseRequest(strings.NewReader(`{"model":"parallel-research","input":"  ` + inputCanary + ` ü  "}`))
	if err != nil || req.Model != "parallel-research" || req.Input() != inputCanary+" ü" {
		t.Fatalf("%+v %v", req, err)
	}
	for _, text := range []string{req.String(), fmt.Sprintf("%v %+v %#v", req, req, *req)} {
		if strings.Contains(text, inputCanary) {
			t.Errorf("formatting a request shows its input: %s", text)
		}
	}
	if _, err := ParseRequest(strings.NewReader(`{"model":"m","input":"` + strings.Repeat("ü", MaxInputChars) + `"}`)); err != nil {
		t.Errorf("an input of exactly %d characters: %v", MaxInputChars, err)
	}
	for name, body := range map[string]string{
		"no model":       `{"input":"x"}`,
		"empty model":    `{"model":"","input":"x"}`,
		"no input":       `{"model":"m"}`,
		"blank input":    `{"model":"m","input":" \n "}`,
		"input a list":   `{"model":"m","input":["x"]}`,
		"input too long": `{"model":"m","input":"` + strings.Repeat("a", MaxInputChars+1) + `"}`,
		"unknown field":  `{"model":"m","input":"x","processor":"ultra"}`,
		"metadata":       `{"model":"m","input":"x","metadata":{"a":"b"}}`,
	} {
		var invalid strictjson.Invalid
		if _, err := ParseRequest(strings.NewReader(body)); !errors.As(err, &invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if escaped := len(`{"model":"parallel-research","input":"`) + MaxInputChars*len(`😀`)/2 + 2; escaped > MaxRequestBody {
		t.Errorf("an input of %d escaped characters takes %d bytes, over the %d byte body cap", MaxInputChars, escaped, MaxRequestBody)
	}
}

func TestEventsCarryOnlyTheirTypesFieldsWithinTheCaps(t *testing.T) {
	note, _ := Note(Plan, strings.Repeat("ü", MaxMessageChars+1))
	objective, _ := Objective(" find x ")
	query, _ := Query("x y")
	read, _ := Read(" https://example.com/a ")
	for e, want := range map[Event]string{
		State(jobs.Running):   `{"type":"state","status":"running"}`,
		note:                  `{"type":"note","kind":"plan","message":"` + strings.Repeat("ü", MaxMessageChars) + `"}`,
		objective:             `{"type":"search","objective":"find x"}`,
		query:                 `{"type":"search","query":"x y"}`,
		read:                  `{"type":"read","url":"https://example.com/a"}`,
		Stats(0, 0):           `{"type":"stats","considered":0,"read":0}`,
		Stats(525, -1):        `{"type":"stats","considered":525,"read":0}`,
		State(jobs.Failed):    `{"type":"state","status":"failed"}`,
		State(jobs.Queued):    `{"type":"state","status":"queued"}`,
		State(jobs.Completed): `{"type":"state","status":"completed"}`,
	} {
		if got, err := json.Marshal(e); err != nil || string(got) != want {
			t.Errorf("%s, want %s", got, want)
		}
	}
	for name, ok := range map[string]bool{
		"blank note":      second(Note(Result, "  ")),
		"blank query":     second(Query(" ")),
		"ftp read":        second(Read("ftp://example.com/")),
		"credentialed":    second(Read("https://u:p@example.com/")),
		"overlong url":    second(Read("https://example.com/" + strings.Repeat("a", 2048))),
		"empty objective": second(Objective("")),
	} {
		if ok {
			t.Errorf("%s was kept", name)
		}
	}
	if s := fmt.Sprintf("%v %#v", note, note); strings.Contains(s, "ü") {
		t.Errorf("formatting an event shows its text: %s", s)
	}
}

func second(_ Event, ok bool) bool { return ok }

func TestCitationsStopAtTheCapAndClipEachSourcesTitleAndExcerpts(t *testing.T) {
	var cs Citations
	long := strings.Repeat("ü", MaxCitationChars)
	title := strings.Repeat("t", web.MaxTitleChars+1)
	cs.Add("https://example.com/0", &title, []string{long + "over", "never"})
	cs.Add("https://example.com/0", nil, []string{"never either"})
	for i := 1; i <= MaxCitations; i++ {
		cs.Add(fmt.Sprintf("https://example.com/%d", i), nil, []string{"x"})
	}
	list := cs.List()
	if len(list) != MaxCitations {
		t.Fatalf("%d citations, want the cap of %d", len(list), MaxCitations)
	}
	if first := list[0]; len(first.Title) != web.MaxTitleChars || len(first.Excerpts) != 1 || first.Excerpts[0] != long {
		t.Errorf("first citation holds a %d-character title and %d excerpts, the first of %d characters", len(first.Title), len(first.Excerpts), len(first.Excerpts[0])/2)
	}
	if last := list[MaxCitations-1]; last.URL != fmt.Sprintf("https://example.com/%d", MaxCitations-1) {
		t.Errorf("the last citation kept is %s", last.URL)
	}
}
