package parallel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/health"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/web"
)

const (
	apiKey          = "par-key-123"
	queryCanary     = "QUERY-CANARY-a41c"
	objectiveCanary = "OBJECTIVE-CANARY-0f2d"
	vendorCanary    = "VENDOR-CANARY-session_99"
	pageCanary      = "PAGE-CANARY-e7b0"
)

type call struct {
	method, path, rawQuery string
	header                 http.Header
	body                   map[string]json.RawMessage
}

type standIn struct {
	mu    sync.Mutex
	calls []call
	reply func(w http.ResponseWriter, r *http.Request)
}

func (s *standIn) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.calls = append(s.calls, call{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		s.mu.Unlock()
		s.reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *standIn) only(t *testing.T) call {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) != 1 {
		t.Fatalf("%d calls to Parallel, want 1", len(s.calls))
	}
	return s.calls[0]
}

func replying(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func parseSearch(t *testing.T, body string) *web.SearchRequest {
	t.Helper()
	req, err := web.ParseSearchRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func parseFetch(t *testing.T, raw string) *web.FetchRequest {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"model": "parallel-extract", "url": raw})
	req, err := web.ParseFetchRequest(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

const searchReply = `{"search_id":"search_` + vendorCanary + `","session_id":"` + vendorCanary + `","warnings":[{"type":"warning","message":"` + vendorCanary + `"}],"usage":[{"name":"sku_search","count":1}],` +
	`"results":[{"url":"https://example.com/a","title":"A","publish_date":"2026-09-01","excerpts":["first","second"]},{"url":"https://example.com/b","title":null,"publish_date":null,"excerpts":[]}]}`

func TestSearchSendsOnlyTheModeQueriesObjectiveAndCapsAsAPost(t *testing.T) {
	for _, mode := range modes {
		s := &standIn{reply: replying(200, searchReply)}
		srv := s.serve(t)
		p, err := NewSearch(srv.URL, apiKey, mode, srv.Client())
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		results, err := p.Search(context.Background(), parseSearch(t, `{"model":"parallel-search","queries":["`+queryCanary+` <&>","q2"],"objective":"`+objectiveCanary+`"}`))
		if err != nil || results.Len() != 2 {
			t.Fatalf("%s: results %v err %v", mode, results, err)
		}
		c := s.only(t)
		if c.method != http.MethodPost || c.path != "/v1/search" || c.rawQuery != "" {
			t.Errorf("%s: %s %s?%s", mode, c.method, c.path, c.rawQuery)
		}
		if got := slices.Sorted(maps.Keys(c.body)); !slices.Equal(got, []string{"advanced_settings", "max_chars_total", "mode", "objective", "search_queries"}) {
			t.Errorf("%s: body keys %v", mode, got)
		}
		for field, want := range map[string]string{
			"mode": `"` + mode + `"`, "search_queries": `["` + queryCanary + ` <&>","q2"]`, "objective": `"` + objectiveCanary + `"`,
			"max_chars_total": "8000", "advanced_settings": `{"max_results":10}`,
		} {
			if string(c.body[field]) != want {
				t.Errorf("%s: %s = %s, want %s", mode, field, c.body[field], want)
			}
		}
		if c.header.Get("X-Api-Key") != apiKey || c.header.Get("Authorization") != "" || c.header.Get("Content-Type") != "application/json" || c.header.Get("Cookie") != "" {
			t.Errorf("%s: headers %v", mode, c.header)
		}
		for name := range c.header {
			if !slices.Contains([]string{"Accept", "Accept-Encoding", "Content-Length", "Content-Type", "User-Agent", "X-Api-Key"}, name) {
				t.Errorf("%s: unexpected header %s", mode, name)
			}
		}
	}
	if _, err := NewSearch("https://api.parallel.ai", apiKey, "pro", http.DefaultClient); err == nil || err.Error() != `"pro" is not a search mode parallel serves, one of turbo, fast, basic, advanced` {
		t.Errorf("an unknown mode: %v", err)
	}
	if _, err := NewExtract("https://api.parallel.ai", apiKey, "fast", http.DefaultClient); err == nil || err.Error() != `"fast" is not a fetch model parallel serves, only extract` {
		t.Errorf("a search mode as the fetch model: %v", err)
	}
}

func TestSearchWithoutAnObjectiveLeavesTheFieldOut(t *testing.T) {
	s := &standIn{reply: replying(200, searchReply)}
	srv := s.serve(t)
	p, _ := NewSearch(srv.URL, apiKey, "fast", srv.Client())
	p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["q"]}`))
	if body := s.only(t).body; body["objective"] != nil || string(body["mode"]) != `"fast"` {
		t.Errorf("body %v", body)
	}
}

func TestExtractAsksForTheFullPageOfOneURLAndCapsIt(t *testing.T) {
	long := strings.Repeat("x", web.MaxContentChars+1)
	s := &standIn{reply: replying(200, `{"extract_id":"e","session_id":"`+vendorCanary+`","errors":[],"results":[{"url":"https://example.com/p","title":"P","publish_date":"2025-12-31","excerpts":["`+vendorCanary+`"],"full_content":"`+long+`"}]}`)}
	srv := s.serve(t)
	page, err := mustExtract(t, srv.URL, srv.Client()).Fetch(context.Background(), parseFetch(t, "https://example.com/p?id=1#"+pageCanary))
	if err != nil || !page.Truncated() {
		t.Fatalf("page %v err %v", page, err)
	}
	c := s.only(t)
	if c.method != http.MethodPost || c.path != "/v1/extract" || !slices.Equal(slices.Sorted(maps.Keys(c.body)), []string{"advanced_settings", "urls"}) {
		t.Errorf("%s %s body %v", c.method, c.path, c.body)
	}
	if string(c.body["urls"]) != `["https://example.com/p?id=1"]` || string(c.body["advanced_settings"]) != `{"full_content":{"max_chars_per_result":100001},"fetch_policy":{"timeout_seconds":30}}` {
		t.Errorf("urls %s settings %s", c.body["urls"], c.body["advanced_settings"])
	}
	if c.header.Get("X-Api-Key") != apiKey || c.header.Get("Authorization") != "" {
		t.Errorf("headers %v", c.header)
	}
}

func TestUnreadablePagesAreFetchFailedAndMalformedRepliesAreUpstreamErrors(t *testing.T) {
	for name, c := range map[string]struct {
		reply string
		want  apierr.Error
	}{
		"listed as an error": {`{"extract_id":"e","session_id":"s","results":[],"errors":[{"url":"https://example.com/","error_type":"fetch_error","http_status_code":403,"content":"` + vendorCanary + `"}]}`, web.ErrFetchFailed},
		"no full content":    {`{"extract_id":"e","session_id":"s","results":[{"url":"https://example.com/","excerpts":["` + vendorCanary + `"],"full_content":null}],"errors":[]}`, web.ErrFetchFailed},
		"blank full content": {`{"extract_id":"e","session_id":"s","results":[{"url":"https://example.com/","excerpts":[],"full_content":"  \n"}],"errors":[]}`, web.ErrFetchFailed},
		"no results field":   {`{"extract_id":"e","session_id":"s"}`, web.ErrUpstream},
		"not json":           {`<html>` + vendorCanary + `</html>`, web.ErrUpstream},
	} {
		s := &standIn{reply: replying(200, c.reply)}
		srv := s.serve(t)
		_, err := mustExtract(t, srv.URL, srv.Client()).Fetch(context.Background(), parseFetch(t, "https://example.com/"))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal != c.want {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
	s := &standIn{reply: replying(200, `{"search_id":"s","session_id":"s"}`)}
	srv := s.serve(t)
	p, _ := NewSearch(srv.URL, apiKey, "fast", srv.Client())
	if _, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["q"]}`)); !errors.Is(err, web.ErrUpstream) {
		t.Errorf("a search reply without results: %v", err)
	}
}

func TestVendorStatusesBecomeProxyErrorsWithoutVendorOrQueryText(t *testing.T) {
	for status, want := range map[int]apierr.Error{
		400: web.ErrUpstream,
		401: web.ErrUpstream,
		402: web.ErrUpstreamUnavailable,
		403: web.ErrUpstream,
		404: web.ErrUpstream,
		408: web.ErrUpstream,
		422: web.ErrUpstream,
		429: web.ErrUpstreamBusy,
		500: web.ErrUpstream,
		502: web.ErrUpstream,
		503: web.ErrUpstream,
	} {
		echo := `{"type":"error","error":{"ref_id":"` + vendorCanary + `","message":"bad ` + queryCanary + `","detail":{"input":"` + queryCanary + `"}}}`
		s := &standIn{reply: replying(status, echo)}
		srv := s.serve(t)
		p, _ := NewSearch(srv.URL, apiKey, "fast", srv.Client())
		_, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["`+queryCanary+`"]}`))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal != want {
			t.Errorf("%d: err %v, want %v", status, err, want)
			continue
		}
		for _, text := range []string{err.Error(), string(refusal.Envelope())} {
			if strings.Contains(text, vendorCanary) || strings.Contains(text, queryCanary) {
				t.Errorf("%d: %s", status, text)
			}
		}
	}
}

func TestAnUnreachableOrOversizedVendorIsAnUpstreamErrorThatNamesNothing(t *testing.T) {
	const gone = "http://127.0.0.1:1"
	p, _ := NewSearch(gone, apiKey, "fast", &http.Client{})
	_, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["`+queryCanary+`"]}`))
	if !errors.Is(err, web.ErrUpstream) || strings.Contains(err.Error(), gone) || strings.Contains(err.Error(), queryCanary) || strings.Contains(err.Error(), apiKey) {
		t.Errorf("err %v", err)
	}
	huge := &standIn{reply: func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"results":[{"url":"https://example.com","excerpts":["`)
		io.WriteString(w, strings.Repeat("a", maxReplyBytes))
		io.WriteString(w, `"]}]}`)
	}}
	srv := huge.serve(t)
	p, _ = NewSearch(srv.URL, apiKey, "fast", srv.Client())
	if _, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["q"]}`)); !errors.Is(err, web.ErrUpstream) {
		t.Errorf("an oversized reply: %v", err)
	}
}

func TestHealthSeesAnUnreachableOrSlowVendorBehindTheProductError(t *testing.T) {
	unreachable, _ := NewSearch("http://127.0.0.1:1", apiKey, "fast", &http.Client{})
	hang := (&standIn{reply: func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }}).serve(t)
	slow, _ := NewSearch(hang.URL, apiKey, "fast", hang.Client())
	slow.Timeout = 10 * time.Millisecond
	for want, p := range map[health.Outcome]*Search{health.Unreachable: unreachable, health.Deadline: slow} {
		_, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["q"]}`))
		if got := health.Classify(health.Evidence{Err: err}); got != want || !errors.Is(err, web.ErrUpstream) {
			t.Errorf("err %v classified %v, want %v behind web.ErrUpstream", err, got, want)
		}
	}
}

func TestTheProviderDoesNotChangeTheCallersClient(t *testing.T) {
	shared := &http.Client{}
	NewSearch("https://api.parallel.ai", apiKey, "fast", shared)
	NewExtract("https://api.parallel.ai", apiKey, ExtractModel, shared)
	if shared.CheckRedirect != nil {
		t.Error("the shared upstream client's redirect policy was changed")
	}
}

func TestExtractBoundsTheLiveFetchInsideItsTimeout(t *testing.T) {
	extract := mustExtract(t, "https://api.parallel.ai", &http.Client{})
	if live := liveFetchSeconds * time.Second; live+10*time.Second > extract.Timeout {
		t.Errorf("Parallel's live fetch may take %v, leaving under 10s of the %v extract budget for the rest of its work", live, extract.Timeout)
	}
}

func stallingAfterHeaders(t *testing.T) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"results":[`)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
}

func TestAVendorThatStallsAfterItsHeadersIsAnUpstreamErrorAtTheTimeout(t *testing.T) {
	const timeout = 150 * time.Millisecond
	search := &standIn{reply: stallingAfterHeaders(t)}
	srv := search.serve(t)
	p, _ := NewSearch(srv.URL, apiKey, "fast", srv.Client())
	p.Timeout = timeout
	extract := &standIn{reply: stallingAfterHeaders(t)}
	esrv := extract.serve(t)
	e := mustExtract(t, esrv.URL, esrv.Client())
	e.Timeout = timeout
	for name, call := range map[string]func() error{
		"search": func() error {
			_, err := p.Search(context.Background(), parseSearch(t, `{"model":"m","queries":["q"]}`))
			return err
		},
		"extract": func() error {
			_, err := e.Fetch(context.Background(), parseFetch(t, "https://example.com/"))
			return err
		},
	} {
		started := time.Now()
		err := call()
		took := time.Since(started)
		if !errors.Is(err, web.ErrUpstream) {
			t.Errorf("%s: err %v, want ErrUpstream", name, err)
		}
		if took < timeout || took > timeout+2*time.Second {
			t.Errorf("%s returned after %v, want just past its %v timeout", name, took, timeout)
		}
	}
}

func mustExtract(t *testing.T, baseURL string, client *http.Client) *Extract {
	t.Helper()
	e, err := NewExtract(baseURL, apiKey, ExtractModel, client)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const orgRPM = 600

func TestTheSharedLimitsKeepTheirBucketsAndLeaveHeadroomUnderTheOrgLimit(t *testing.T) {
	if SearchLimit.Subject != "parallel/search" || ExtractLimit.Subject != "parallel/fetch" {
		t.Errorf("subjects %q and %q: renaming one starts a fresh bucket in the database", SearchLimit.Subject, ExtractLimit.Subject)
	}
	for _, l := range []limits.SharedLimit{SearchLimit, ExtractLimit} {
		if !l.Valid() || l.RPM*6 > orgRPM*5 {
			t.Errorf("%s: the shared limit of %d rpm leaves less than a sixth of Parallel's %d rpm org limit as headroom", l.Subject, l.RPM, orgRPM)
		}
		if worstMinute := l.RPM + 1 + l.RPM/10; worstMinute >= orgRPM {
			t.Errorf("%s: the shared limit admits up to %d calls in one minute, its rpm plus the burst of 1 + rpm/10 that take_rate_limit allows, which reaches Parallel's %d rpm org limit", l.Subject, worstMinute, orgRPM)
		}
	}
}
