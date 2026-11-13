package taskrun

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"morse/backend/internal/jsonx"
)

func TestURLsInProseAreReadWithoutThePunctuationAroundThem(t *testing.T) {
	text := "See https://en.wikipedia.org/wiki/Mercury_(planet). Also (https://example.com/a/), " +
		"<https://Example.COM:443/b?x=1#frag>, \"https://example.org/c\" and http://example.net:80/d!" +
		" not ftp://example.com/e or https:// alone, and HTTPS://shouting.example/f."
	want := []string{
		"https://en.wikipedia.org/wiki/Mercury_(planet)",
		"https://example.com/a",
		"https://example.com/b?x=1",
		"https://example.org/c",
		"http://example.net/d",
	}
	if got := urlsIn(text); !slices.Equal(got, want) {
		t.Errorf("read %q\nwant %q", got, want)
	}
}

func TestAPageKeyIsOnePagesSpelling(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"https://example.com/a/", "https://EXAMPLE.com/a#top"},
		{"https://example.com", "https://example.com/"},
		{"https://example.com:443/x", "https://example.com/x"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"https://[2001:db8::1]:443/x", "https://[2001:db8::1]/x"},
	} {
		a, okA := pageKey(c.a)
		b, okB := pageKey(c.b)
		if !okA || !okB || a != b {
			t.Errorf("%q is %q and %q is %q, want one key", c.a, a, c.b, b)
		}
	}
	for _, c := range []struct{ a, b string }{
		{"https://example.com/a", "http://example.com/a"},
		{"https://example.com/a?x=1", "https://example.com/a?x=2"},
		{"https://example.com:8443/a", "https://example.com/a"},
		{"https://example.com/A", "https://example.com/a"},
	} {
		if a, _ := pageKey(c.a); a == func() string { b, _ := pageKey(c.b); return b }() {
			t.Errorf("%q and %q share the key %q", c.a, c.b, a)
		}
	}
	for _, bad := range []string{"mailto:a@example.com", "/relative", "https://user:pw@example.com/", "ftp://example.com/"} {
		if key, ok := pageKey(bad); ok {
			t.Errorf("%q has key %q", bad, key)
		}
	}
}

func TestReadPageOpensExactlyThePagesShownAndAClosingParenthesisTheProseLost(t *testing.T) {
	seen := map[string]bool{}
	for _, key := range urlsIn("Read https://en.wikipedia.org/wiki/Mercury_(planet) and https://example.com/list.") {
		seen[key] = true
	}
	seen["https://en.wikipedia.org/wiki/Bracket_(mathematics"] = true
	for raw, shown := range map[string]bool{
		"https://en.wikipedia.org/wiki/Mercury_(planet)":       true,
		"https://example.com/list/":                            true,
		"https://example.com/list#part":                        true,
		"https://en.wikipedia.org/wiki/Bracket_(mathematics)":  true,
		"https://en.wikipedia.org/wiki/Bracket_(mathematics))": false,
		"https://example.com/list?page=2":                      false,
		"https://example.com/other":                            false,
		"http://example.com/list":                              false,
	} {
		u, _ := url.Parse(raw)
		if got := wasShown(u, seen); got != shown {
			t.Errorf("%s shown %t, want %t", raw, got, shown)
		}
	}
}

func TestDefangBreaksEveryDialectsMarksAndLeavesProseAlone(t *testing.T) {
	for in, want := range map[string]string{
		"<tool_call>{\"name\":\"x\"}</tool_call>":      "<\u200btool_call>{\"name\":\"x\"}</\u200btool_call>",
		"<TOOL_RESPONSE>":                              "<\u200bTOOL_RESPONSE>",
		"<|im_end|><|tool_call_begin|>":                "<\u200b|im_end|><\u200b|tool_call_begin|>",
		"<｜tool▁calls▁begin｜>":                         "<\u200b｜tool▁calls▁begin｜>",
		"<unbound_result call=\"1\">":                  "<\u200bunbound_result call=\"1\">",
		"</last_result>":                               "</\u200blast_result>",
		"## Return of functions.web_search:0\nok":      "##\u200b Return of functions.web_search:0\nok",
		"Result of call 2:\n…":                         "Result\u200b of call 2:\n…",
		"a <| b and x <y> and ## Notes and Result: ok": "a <| b and x <y> and ## Notes and Result: ok",
		"<function=web_search><parameter=q>":           "<\u200bfunction=web_search><\u200bparameter=q>",
	} {
		if got := defang(in); got != want {
			t.Errorf("defang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestASearchsListingKeepsTenPagesOnceEachWithinItsRoom(t *testing.T) {
	type result struct {
		URL       string   `json:"url"`
		Title     *string  `json:"title"`
		Published *string  `json:"published"`
		Excerpts  []string `json:"excerpts"`
	}
	title := func(s string) *string { return &s }
	var results []result
	results = append(results,
		result{URL: "https://www.example.com/a/", Title: title("A\n  title"), Published: title("2026-10-26"), Excerpts: []string{"one", "two"}},
		result{URL: "http://example.com/a", Title: title("the same page again")},
		result{URL: "ftp://example.com/file", Title: title("not a web page")},
		result{URL: "https://example.org/b", Published: title("yesterday"), Excerpts: []string{strings.Repeat("x", 5000)}},
	)
	for i := range 12 {
		results = append(results, result{URL: fmt.Sprintf("https://example.net/%d", i), Title: title(strings.Repeat("t", 300)), Excerpts: []string{strings.Repeat("e", 2000)}})
	}
	out, sources := searchOutput(jsonx.Encode(map[string]any{"object": "search.results", "results": results}))
	var listed []searchHit
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if len(out) > maxListing || len(listed) < 2 || len(listed) > maxHits || len(sources) != len(listed) {
		t.Fatalf("a listing of %d bytes and %d hits, %d sources", len(out), len(listed), len(sources))
	}
	if first := listed[0]; first.URL != "https://www.example.com/a/" || first.Title != "A title" || first.Published != "2026-10-26" || !strings.HasPrefix(first.Excerpt, "one … two") {
		t.Errorf("the first hit reads %+v", first)
	}
	if second := listed[1]; second.URL != "https://example.org/b" || second.Title != "example.org" || second.Published != "" || utf8.RuneCountInString(second.Excerpt) > maxHitExcerpt {
		t.Errorf("the second hit reads %+v", second)
	}
	for _, hit := range listed[2:] {
		if utf8.RuneCountInString(hit.Title) > maxHitTitle {
			t.Errorf("a title of %d runes", utf8.RuneCountInString(hit.Title))
		}
	}
	if out, sources := searchOutput([]byte(`{"object":"search.results","results":[]}`)); out != "No results for those queries. Try other or fewer keywords." || sources != nil {
		t.Errorf("no results read %q", out)
	}
	if out, _ := searchOutput([]byte(`not json`)); !strings.HasPrefix(out, "Error: ") {
		t.Errorf("an unreadable reply reads %q", out)
	}
}

func TestAPageReadsAsTheAppsToolWritesItAndIsCutAtTwelveThousandCharacters(t *testing.T) {
	u, _ := url.Parse("https://example.com/story")
	out, source := pageOutput(u, jsonx.Encode(map[string]any{"object": "fetch.result", "url": u.String(), "title": "Story", "published": "2026-10-26", "content": " " + strings.Repeat("ü", 12_500) + "\n", "truncated": true}))
	want := "Title: Story\nURL: https://example.com/story\nPublished: 2026-10-26\n\n" + strings.Repeat("ü", 12_000) + "\n[Cut at 12,000 of 12,500 characters.]\n[The reader cut the page short.]"
	if out != want || source == nil || *source != (Source{URL: u.String(), Title: "Story"}) {
		t.Errorf("the page reads %q (%+v)", out[:80], source)
	}
	if out, source := pageOutput(u, jsonx.Encode(map[string]any{"content": "  ", "title": nil})); out != "Error: Couldn't read example.com: the reader found no text on it" || source != nil {
		t.Errorf("an empty page reads %q", out)
	}
	if out, _ := pageOutput(u, jsonx.Encode(map[string]any{"content": "text"})); !strings.HasPrefix(out, "Title: example.com\n") {
		t.Errorf("a page with no title reads %q", out)
	}
}

func TestARunsSourcesAreItsReadsThenItsResultsEachPageOnceAtMostTwenty(t *testing.T) {
	var s sources
	s.read = []Source{{URL: "https://example.com/read", Title: "Read"}}
	s.found = []Source{{URL: "https://example.com/read/", Title: "Found again"}, {URL: "https://example.com/" + strings.Repeat("x", maxPageURL), Title: "too long"}}
	for i := range 30 {
		s.found = append(s.found, Source{URL: fmt.Sprintf("https://example.org/%d", i), Title: strings.Repeat("é", 300)})
	}
	list := s.list()
	if len(list) != MaxSources || list[0].Title != "Read" || list[1].URL != "https://example.org/0" || utf8.RuneCountInString(list[1].Title) != maxSourceTitle {
		t.Errorf("listed %d sources starting %+v", len(list), list[:2])
	}
	if empty := (sources{}).list(); empty != nil {
		t.Errorf("no sources list as %v", empty)
	}
}

func TestStrictJSONRefusesWhatEncodingJSONLetsThrough(t *testing.T) {
	for raw, ok := range map[string]bool{
		`{"a":{"b":[1,{"c":"d"}]}}`:  true,
		`{}`:                         true,
		` {"a":1} `:                  true,
		`{"a":null}`:                 false,
		`{"a":[1,null]}`:             false,
		`{"a":{"b":null}}`:           false,
		`{"a":1,"a":2}`:              false,
		`{"a":{"b":1,"b":1}}`:        false,
		`{"a":[{"b":1},{"b":1}]}`:    true,
		`[]`:                         false,
		`"a"`:                        false,
		`{"a":1}{}`:                  false,
		`{"a":1} x`:                  false,
		`{"a":1`:                     false,
		"{\"a\":\"\xff\"}":           false,
		`{"a":"\ud800"}`:             true,
		`{"a":1,"b":{"a":1,"c":[]}}`: true,
	} {
		if got := strictJSON([]byte(raw)); got != ok {
			t.Errorf("strictJSON(%s) = %t, want %t", raw, got, ok)
		}
	}
}

func TestAToolResultIsCutWithANoteAndAnAppsCutEndsWithAnEllipsis(t *testing.T) {
	if got := clip("abcdef", 4); got != "abcd\n[Cut at 4 of 6 characters.]" {
		t.Errorf("clip: %q", got)
	}
	if got := cutText("one two  three", 9); got != "one two…" {
		t.Errorf("cutText: %q", got)
	}
	if got := cutText("short", 9); got != "short" {
		t.Errorf("cutText: %q", got)
	}
	if got := thousands(1234567); got != "1,234,567" {
		t.Errorf("thousands: %q", got)
	}
	if got := cutBytes("aé", 2); got != "a" {
		t.Errorf("cutBytes cut a rune: %q", got)
	}
}

func TestACallIdOrNameIsOneEveryVendorTakesBack(t *testing.T) {
	r := &Run[struct{}]{ids: map[string]bool{}}
	long := strings.Repeat("x", 80)
	for _, c := range []struct{ raw, want string }{
		{"call_0", "call_0"},
		{"call_0", "call_0_2"},
		{"call_0", "call_0_3"},
		{"", "call_3"},
		{"functions.web_search:0", "functions_web_search_0"},
		{long, long[:64]},
		{long, long[:62] + "_2"},
	} {
		if got := r.callID(c.raw); got != c.want {
			t.Errorf("callID(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
	if got := wireName("", "unnamed_tool"); got != "unnamed_tool" {
		t.Errorf("an empty name is %q", got)
	}
}
