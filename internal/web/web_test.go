package web_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"morse/backend/internal/strictjson"
	"morse/backend/internal/web"
)

const (
	queryCanary     = "QUERY-CANARY-7d1a"
	objectiveCanary = "OBJECTIVE-CANARY-2b9e"
	pageCanary      = "PAGE-CANARY-5c3f"
)

func search(t *testing.T, body string) *web.SearchRequest {
	t.Helper()
	req, err := web.ParseSearchRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return req
}

func fetch(t *testing.T, body string) *web.FetchRequest {
	t.Helper()
	req, err := web.ParseFetchRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return req
}

func str(s string) *string { return &s }

func TestSearchRequestTrimsQueriesAndKeepsThemAndTheObjectiveOutOfFmtAndJSON(t *testing.T) {
	req := search(t, `{"model":"parallel-search","queries":["  `+queryCanary+` one ","two"],"objective":" `+objectiveCanary+` "}`)
	if req.Model != "parallel-search" || strings.Join(req.Queries(), "|") != queryCanary+" one|two" || req.Objective() != objectiveCanary {
		t.Errorf("request %v queries %q objective %q", req, req.Queries(), req.Objective())
	}
	req.Queries()[0] = "changed"
	if req.Queries()[0] == "changed" {
		t.Error("Queries hands out the request's own slice")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, req) + fmt.Sprintf(verb, *req); strings.Contains(out, queryCanary) || strings.Contains(out, objectiveCanary) {
			t.Errorf("%s leaks the query or objective: %s", verb, out)
		}
	}
	if b, _ := json.Marshal(req); bytes.Contains(b, []byte(queryCanary)) {
		t.Errorf("json.Marshal leaks the query: %s", b)
	}
	if none := search(t, `{"model":"m","queries":["q"],"objective":null}`); none.Objective() != "" {
		t.Errorf("null objective became %q", none.Objective())
	}
	edge := search(t, `{"model":"m","queries":["`+strings.Repeat("é", web.MaxQueryChars)+`","b","c"],"objective":"`+strings.Repeat("ü", web.MaxObjectiveChars)+`"}`)
	if len(edge.Queries()) != web.MaxQueries {
		t.Errorf("queries at the limits refused: %v", edge)
	}
}

func TestSearchRequestRefusesAnythingButTheThreeFields(t *testing.T) {
	invalid := map[string]string{
		"no model":            `{"queries":["q"]}`,
		"empty model":         `{"model":"","queries":["q"]}`,
		"no queries":          `{"model":"m"}`,
		"null queries":        `{"model":"m","queries":null}`,
		"zero queries":        `{"model":"m","queries":[]}`,
		"four queries":        `{"model":"m","queries":["a","b","c","d"]}`,
		"queries a string":    `{"model":"m","queries":"q"}`,
		"a numeric query":     `{"model":"m","queries":[1]}`,
		"a blank query":       `{"model":"m","queries":["a","   "]}`,
		"a long query":        `{"model":"m","queries":["` + strings.Repeat("x", web.MaxQueryChars+1) + `"]}`,
		"a long objective":    `{"model":"m","queries":["q"],"objective":"` + strings.Repeat("x", web.MaxObjectiveChars+1) + `"}`,
		"a numeric objective": `{"model":"m","queries":["q"],"objective":5}`,
		"session_id":          `{"model":"m","queries":["q"],"session_id":"s-1"}`,
		"client_model":        `{"model":"m","queries":["q"],"client_model":"gpt"}`,
		"location":            `{"model":"m","queries":["q"],"location":"us"}`,
		"mode":                `{"model":"m","queries":["q"],"mode":"advanced"}`,
		"search_queries":      `{"model":"m","search_queries":["q"]}`,
		"a case variant":      `{"model":"m","Queries":["q"]}`,
		"user":                `{"model":"m","queries":["q"],"user":"u-1"}`,
		"an array body":       `[{"model":"m","queries":["q"]}]`,
		"two objects":         `{"model":"m","queries":["q"]}{}`,
	}
	for name, body := range invalid {
		_, err := web.ParseSearchRequest(strings.NewReader(body))
		var refusal strictjson.Invalid
		if !errors.As(err, &refusal) {
			t.Errorf("%s: err %v, want strictjson.Invalid", name, err)
		}
	}
	if _, err := web.ParseSearchRequest(strings.NewReader(`{"model":"m","queries":["a"],"queries":["b"]}`)); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Errorf("a repeated key: %v", err)
	}
	for _, body := range []string{`{"model":`, `not json`, `{"model":"m",}`} {
		_, err := web.ParseSearchRequest(strings.NewReader(body))
		var refusal strictjson.Invalid
		if err == nil || errors.As(err, &refusal) {
			t.Errorf("%s: err %v, want a parse error", body, err)
		}
	}
}

func TestFetchRequestTakesOnlyAnHTTPURLWithoutCredentialsAndSendsItWithoutTheFragment(t *testing.T) {
	for raw, upstream := range map[string]string{
		"https://example.com/a?b=1":                                       "https://example.com/a?b=1",
		"http://example.com":                                              "http://example.com",
		"HTTPS://Example.com/x#section-2":                                 "HTTPS://Example.com/x",
		"https://de.wikipedia.org/wiki/Größe#Name":                        "https://de.wikipedia.org/wiki/Größe",
		"https://example.com/" + strings.Repeat("é", web.MaxURLLength-20): "https://example.com/" + strings.Repeat("é", web.MaxURLLength-20),
	} {
		req := fetch(t, `{"model":"parallel-extract","url":"`+raw+`"}`)
		if req.UpstreamURL() != upstream || req.Model != "parallel-extract" {
			t.Errorf("%s: upstream %q", raw, req.UpstreamURL())
		}
		if out := fmt.Sprintf("%v %+v %#v", req, *req, req); strings.Contains(out, "example.com") || strings.Contains(out, "wikipedia") {
			t.Errorf("fmt leaks the url: %s", out)
		}
	}
	for _, raw := range []string{
		"", "example.com/a", "/relative", "ftp://example.com/f", "javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
		"https://user:pw@example.com/", "https://user@example.com/", "https://@example.com/", "https://:pw@example.com/",
		"https://example.com/a b", "https://example.com/\u0000", "https:///path", "https://:443/", "mailto:a@example.com", "https:example.com",
		"https://example.com/" + strings.Repeat("a", web.MaxURLLength),
	} {
		body, _ := json.Marshal(map[string]string{"model": "m", "url": raw})
		if _, err := web.ParseFetchRequest(bytes.NewReader(body)); !errors.Is(err, web.ErrInvalidURL) {
			t.Errorf("%q: err %v, want ErrInvalidURL", raw, err)
		}
	}
	for name, body := range map[string]string{"missing": `{"model":"m"}`, "a number": `{"model":"m","url":5}`, "null": `{"model":"m","url":null}`} {
		if _, err := web.ParseFetchRequest(strings.NewReader(body)); !errors.Is(err, web.ErrInvalidURL) {
			t.Errorf("url %s: err %v", name, err)
		}
	}
	for name, body := range map[string]string{
		"session_id": `{"model":"m","url":"https://a.example","session_id":"s"}`,
		"objective":  `{"model":"m","url":"https://a.example","objective":"o"}`,
		"urls":       `{"model":"m","urls":["https://a.example"]}`,
		"no model":   `{"url":"https://a.example"}`,
	} {
		var refusal strictjson.Invalid
		if _, err := web.ParseFetchRequest(strings.NewReader(body)); !errors.As(err, &refusal) {
			t.Errorf("%s: err %v, want strictjson.Invalid", name, err)
		}
	}
}

func TestFetchRefusesHostsThatAreNotPublicAndPortsOtherThanTheWebDefaults(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/", "http://127.8.9.10:80/", "https://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/",
		"http://10.0.0.5/", "http://172.16.3.4/", "http://192.168.1.1/", "http://[fd00:ec2::254]/", "http://[fc00::1]/",
		"http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/", "http://[fe80::1%25eth0]/", "http://[fec0::1]/",
		"http://0.0.0.0/", "http://0.1.2.3/", "http://[::]/", "http://255.255.255.255/", "http://240.0.0.1/",
		"http://224.0.0.1/", "http://239.255.255.250/", "http://[ff02::1]/", "http://[ff05::2]/",
		"http://100.64.0.1/", "http://100.127.255.254/", "http://198.18.0.1/", "http://192.0.0.170/", "http://[::127.0.0.1]/", "http://[64:ff9b::a00:1]/",
		"http://[::ffff:100.64.0.1]/", "http://[::ffff:c612:1]/", "http://[fec0::1%25eth0]/", "http://[64:ff9b::a00:1%25x]/",
		"http://localhost/", "http://LOCALHOST./", "http://api.localhost/", "http://printer.local/", "http://metadata.google.internal/computeMetadata/v1/",
		"http://svc.cluster.internal/", "http://router.home.arpa/", "http://nas.lan/", "http://intranet/", "http://example.com../",
		"http://2130706433/", "http://0x7f000001/", "http://127.1/", "http://0177.0.0.1/", "http://10.0.0.0x1/", "http://example.0x1f/", "http://example.123/",
		"http://１２７.０.０.１/", "http://ｌｏｃａｌｈｏｓｔ/", "http://127。0。0。1/", "http://metadata。google。internal/", "http://127.0.0。1/", "http://metadata.google。internal/", "http://127.0.0．1/",
		"https://example.com:8443/", "http://example.com:22/", "http://example.com:0/", "http://example.com:080/", "https://example.com:65535/",
	} {
		body, _ := json.Marshal(map[string]string{"model": "m", "url": raw})
		if _, err := web.ParseFetchRequest(bytes.NewReader(body)); !errors.Is(err, web.ErrInvalidURL) {
			t.Errorf("%q: err %v, want ErrInvalidURL", raw, err)
		}
	}
	for _, raw := range []string{
		"https://example.com/", "http://example.com:80/", "https://example.com:443/a", "http://example.com:443/", "https://example.com:/",
		"https://8.8.8.8/", "http://[2606:4700::1111]/", "http://[::ffff:8.8.8.8]/", "https://example.com./", "https://münchen.de/",
		"https://xn--mnchen-3ya.de/", "https://localhost.example.com/", "https://local.example/", "https://internal.example.org/x",
		"https://100.63.255.255/", "https://100.128.0.1/", "https://172.32.0.1/", "https://1password.com/", "https://example.io/",
	} {
		body, _ := json.Marshal(map[string]string{"model": "m", "url": raw})
		if _, err := web.ParseFetchRequest(bytes.NewReader(body)); err != nil {
			t.Errorf("%q: %v, want it fetchable", raw, err)
		}
	}
}

func TestSearchResultsKeepLinksTheFetchCheckWouldRefuse(t *testing.T) {
	var rs web.Results
	rs.Add("http://localhost:8080/docs", nil, nil, []string{"x"})
	if rs.Len() != 1 {
		t.Errorf("a search result on a non-public host was dropped; the target check belongs to fetch only")
	}
}

type wireResults struct {
	Object  string `json:"object"`
	Results []struct {
		URL       string   `json:"url"`
		Title     string   `json:"title"`
		Published *string  `json:"published"`
		Excerpts  []string `json:"excerpts"`
	} `json:"results"`
}

func written(t *testing.T, rs web.Results) (wireResults, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := web.WriteResults(&buf, rs); err != nil {
		t.Fatal(err)
	}
	var out wireResults
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	return out, buf.String()
}

func TestResultsKeepTenSafeLinksAndAtMostTheExcerptBudget(t *testing.T) {
	var rs web.Results
	for _, bad := range []string{"ftp://example.com", "javascript:alert(1)", "https://u:p@example.com/", "", "https://example.com/" + strings.Repeat("a", web.MaxURLLength)} {
		rs.Add(bad, str("bad"), nil, []string{"x"})
	}
	long := strings.Repeat("é", 3000)
	for i := range 14 {
		rs.Add(fmt.Sprintf("https://example.com/%d", i), str(" T <&> "+strings.Repeat("t", web.MaxTitleChars)), str("2026-09-30"), []string{"", "   ", long})
	}
	out, raw := written(t, rs)
	if out.Object != "search.results" || len(out.Results) != web.MaxResults || rs.Len() != web.MaxResults {
		t.Fatalf("object %q, %d results", out.Object, len(out.Results))
	}
	total := 0
	for i, r := range out.Results {
		if r.URL != fmt.Sprintf("https://example.com/%d", i) || utf8.RuneCountInString(r.Title) != web.MaxTitleChars || !strings.HasPrefix(r.Title, "T <&> ") || r.Published == nil || *r.Published != "2026-09-30" || r.Excerpts == nil {
			t.Errorf("result %d: %+v", i, r)
		}
		for _, e := range r.Excerpts {
			total += utf8.RuneCountInString(e)
			if !utf8.ValidString(e) || e == "" {
				t.Errorf("result %d: excerpt cut mid-rune or empty", i)
			}
		}
	}
	if total != web.MaxExcerptChars {
		t.Errorf("excerpts total %d characters, want the budget %d", total, web.MaxExcerptChars)
	}
	if len(out.Results[3].Excerpts) != 0 || !strings.Contains(raw, `"excerpts":[]`) {
		t.Errorf("results past the budget should carry an empty excerpt list: %v", out.Results[3].Excerpts)
	}
	if !strings.Contains(raw, "<&>") {
		t.Error("the reply HTML-escapes markdown")
	}
	if s := fmt.Sprintf("%v %+v %#v", rs, rs, &rs); strings.Contains(s, "example.com") || strings.Contains(s, "éé") {
		t.Errorf("fmt leaks results: %s", s)
	}
}

func TestResultsDropMalformedDatesAndMissingTitles(t *testing.T) {
	var rs web.Results
	for i, date := range []*string{nil, str(""), str("2026-9-30"), str("2026-02-30"), str("30/09/2026"), str("2026-09-30T10:00:00Z"), str("2024-02-29")} {
		rs.Add(fmt.Sprintf("http://example.com/%d", i), nil, date, nil)
	}
	out, raw := written(t, rs)
	for i, r := range out.Results {
		want := i == 6
		if (r.Published != nil) != want || r.Title != "" || r.Excerpts == nil {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if strings.Count(raw, `"published":null`) != 6 {
		t.Errorf("reply %s", raw)
	}
	var empty web.Results
	if _, raw := written(t, empty); strings.TrimSpace(raw) != `{"object":"search.results","results":[]}` {
		t.Errorf("empty reply %s", raw)
	}
}

func TestPageIsCappedPrefersTheReportedLinkAndRedacts(t *testing.T) {
	req := fetch(t, `{"model":"m","url":"https://example.com/page#frag"}`)
	content := strings.Repeat("ö", web.MaxContentChars) + pageCanary
	page := web.NewPage(req, "ftp://elsewhere.example/", str("  "), str("2026-01-01"), content)
	var buf bytes.Buffer
	if err := web.WritePage(&buf, page); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Object    string  `json:"object"`
		URL       string  `json:"url"`
		Title     *string `json:"title"`
		Published *string `json:"published"`
		Content   string  `json:"content"`
		Truncated bool    `json:"truncated"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Object != "fetch.result" || out.URL != "https://example.com/page" || out.Title != nil || out.Published == nil || *out.Published != "2026-01-01" ||
		!out.Truncated || utf8.RuneCountInString(out.Content) != web.MaxContentChars || strings.Contains(out.Content, pageCanary) || !page.Truncated() {
		t.Errorf("page %+v", out)
	}
	whole := web.NewPage(req, "https://example.com/page/", str("Title"), nil, "# "+pageCanary)
	buf.Reset()
	web.WritePage(&buf, whole)
	if want := `{"object":"fetch.result","url":"https://example.com/page/","title":"Title","published":null,"content":"# ` + pageCanary + `","truncated":false}`; strings.TrimSpace(buf.String()) != want {
		t.Errorf("page\n%s\nwant\n%s", buf.String(), want)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, whole); strings.Contains(out, pageCanary) || strings.Contains(out, "example.com") {
			t.Errorf("%s leaks the page: %s", verb, out)
		}
	}
}
