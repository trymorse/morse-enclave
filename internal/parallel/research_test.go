package parallel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jobs"
	"morse/backend/internal/research"
	"morse/backend/internal/upstream"
	"morse/backend/internal/web"
)

const (
	inputCanary = "INPUT-CANARY-77d1"
	testRunID   = "trun_5275cd978ff644ce987e11b2086c7b74"
)

func mustResearch(t *testing.T, baseURL string, client *http.Client) *Research {
	t.Helper()
	r, err := NewResearch(baseURL, apiKey, "pro", client, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func parseResearch(t *testing.T, input string) *research.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"model": "parallel-research", "input": input})
	req, err := research.ParseRequest(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestStartSendsOnlyTheInputProcessorEventsAndATextSchema(t *testing.T) {
	for _, processor := range processors {
		s := &standIn{reply: replying(202, `{"run_id":"`+testRunID+`","interaction_id":"`+testRunID+`","status":"queued","is_active":true,"processor":"`+processor+`","metadata":{},"created_at":"2026-10-05T06:36:33.917090Z","modified_at":"2026-10-05T06:36:33.928325Z"}`)}
		srv := s.serve(t)
		r, err := NewResearch(srv.URL, apiKey, processor, srv.Client(), nil)
		if err != nil {
			t.Fatalf("%s: %v", processor, err)
		}
		id, err := r.Start(context.Background(), parseResearch(t, inputCanary+" <&>"))
		if err != nil || id != testRunID {
			t.Fatalf("%s: run %q err %v", processor, id, err)
		}
		c := s.only(t)
		if c.method != http.MethodPost || c.path != "/v1/tasks/runs" || c.rawQuery != "" {
			t.Errorf("%s: %s %s?%s", processor, c.method, c.path, c.rawQuery)
		}
		if got := slices.Sorted(maps.Keys(c.body)); !slices.Equal(got, []string{"enable_events", "input", "processor", "task_spec"}) {
			t.Errorf("%s: body keys %v", processor, got)
		}
		for field, want := range map[string]string{
			"input": `"` + inputCanary + ` <&>"`, "processor": `"` + processor + `"`, "enable_events": "true", "task_spec": `{"output_schema":{"type":"text"}}`,
		} {
			if string(c.body[field]) != want {
				t.Errorf("%s: %s = %s, want %s", processor, field, c.body[field], want)
			}
		}
		if c.header.Get("X-Api-Key") != apiKey || c.header.Get("Authorization") != "" || c.header.Get("Parallel-Beta") != "" {
			t.Errorf("%s: headers %v", processor, c.header)
		}
	}
	if _, err := NewResearch("https://api.parallel.ai", apiKey, "fast", http.DefaultClient, nil); err == nil || err.Error() != `"fast" is not a research processor parallel serves, one of pro, ultra, pro-fast, ultra-fast` {
		t.Errorf("a search mode as the processor: %v", err)
	}
}

func TestARunIDThatCouldLeaveTheRunsPathIsAnUpstreamErrorAndNeverSent(t *testing.T) {
	for _, bad := range []string{"", "../search", "trun_1/result", "trun 1", "trun_1?x=1", strings.Repeat("a", 129)} {
		s := &standIn{reply: replying(202, `{"run_id":`+string(mustJSON(bad))+`,"status":"queued"}`)}
		srv := s.serve(t)
		r := mustResearch(t, srv.URL, srv.Client())
		if _, err := r.Start(context.Background(), parseResearch(t, "q")); !errors.Is(err, research.ErrUpstream) {
			t.Errorf("created as %q: %v", bad, err)
		}
		before := len(s.calls)
		if _, err := r.Check(context.Background(), bad); !errors.Is(err, research.ErrUpstream) {
			t.Errorf("check %q: %v", bad, err)
		}
		if _, err := r.Output(context.Background(), bad); !errors.Is(err, research.ErrUpstream) {
			t.Errorf("output %q: %v", bad, err)
		}
		if _, err := r.Watch(context.Background(), bad); !errors.Is(err, research.ErrUpstream) {
			t.Errorf("watch %q: %v", bad, err)
		}
		if len(s.calls) != before {
			t.Errorf("run id %q reached Parallel", bad)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestCheckReadsEachParallelStatusAsOneOfTheFourTheClientSees(t *testing.T) {
	failed := jobs.Poll{Status: jobs.Failed, Failure: jobs.UpstreamError}
	for vendor, want := range map[string]jobs.Poll{
		"queued": {Status: jobs.Queued}, "running": {Status: jobs.Running}, "cancelling": {Status: jobs.Running}, "completed": {Status: jobs.Completed},
		"failed": failed, "cancelled": failed, "action_required": failed,
	} {
		s := &standIn{reply: replying(200, `{"run_id":"`+testRunID+`","status":"`+vendor+`","is_active":false,"error":{"ref_id":"`+vendorCanary+`","message":"`+inputCanary+`"}}`)}
		srv := s.serve(t)
		got, err := mustResearch(t, srv.URL, srv.Client()).Check(context.Background(), testRunID)
		if err != nil || got != want {
			t.Errorf("%s: %v err %v, want %v", vendor, got, err, want)
		}
		if c := s.only(t); c.method != http.MethodGet || c.path != "/v1/tasks/runs/"+testRunID || c.body != nil {
			t.Errorf("%s: %s %s body %v", vendor, c.method, c.path, c.body)
		}
	}
	s := &standIn{reply: replying(200, `{"run_id":"`+testRunID+`","status":"paused"}`)}
	srv := s.serve(t)
	if _, err := mustResearch(t, srv.URL, srv.Client()).Check(context.Background(), testRunID); !errors.Is(err, upstream.ErrMalformed) || upstream.Final(err, upstream.UnusableRetries) {
		t.Errorf("an unknown status: %v, want a malformed reply a later poll retries", err)
	}
}

func TestVendorStatusesOnTaskRunsBecomeProxyErrorsWithoutVendorOrInputText(t *testing.T) {
	echo := `{"type":"error","error":{"ref_id":"` + vendorCanary + `","message":"bad ` + inputCanary + `","detail":{"input":"` + inputCanary + `"}}}`
	for status, want := range map[int]apierr.Error{401: research.ErrUpstream, 402: research.ErrUpstreamUnavailable, 403: research.ErrUpstream, 404: research.ErrUpstream, 422: research.ErrUpstream, 429: research.ErrUpstreamBusy, 500: research.ErrUpstream} {
		s := &standIn{reply: replying(status, echo)}
		srv := s.serve(t)
		r := mustResearch(t, srv.URL, srv.Client())
		_, startErr := r.Start(context.Background(), parseResearch(t, inputCanary))
		_, checkErr := r.Check(context.Background(), testRunID)
		_, outputErr := r.Output(context.Background(), testRunID)
		_, watchErr := r.Watch(context.Background(), testRunID)
		for name, err := range map[string]error{"start": startErr, "check": checkErr, "output": outputErr, "watch": watchErr} {
			var refusal apierr.Error
			if !errors.As(err, &refusal) || refusal != want {
				t.Errorf("%d %s: err %v, want %v", status, name, err, want)
				continue
			}
			if strings.Contains(err.Error(), vendorCanary) || strings.Contains(err.Error(), inputCanary) || strings.Contains(string(refusal.Envelope()), inputCanary) {
				t.Errorf("%d %s: %v", status, name, err)
			}
			if final := upstream.Final(err, upstream.UnusableRetries); final == (status == 429 || status >= 500) {
				t.Errorf("%d %s: final %t", status, name, final)
			}
		}
	}
}

func TestOutputIsTheReportAndItsCitationsFlattenedOncePerURL(t *testing.T) {
	sample, err := os.ReadFile("testdata/result.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{reply: replying(200, string(sample))}
	srv := s.serve(t)
	out, err := mustResearch(t, srv.URL, srv.Client()).Output(context.Background(), testRunID)
	if err != nil {
		t.Fatal(err)
	}
	if c := s.only(t); c.method != http.MethodGet || c.path != "/v1/tasks/runs/"+testRunID+"/result" || c.rawQuery != "" {
		t.Errorf("%s %s?%s", c.method, c.path, c.rawQuery)
	}
	if !strings.HasPrefix(out.Content, "# ") || !strings.Contains(out.Content, "## References") || len(out.Content) != 9871 {
		t.Errorf("content %d bytes: %.80q", len(out.Content), out.Content)
	}
	var urls []string
	for _, c := range out.Citations {
		urls = append(urls, c.URL)
	}
	if want := []string{
		"https://www.claymath.org/wp-content/uploads/2022/06/navierstokes.pdf", "https://www.claymath.org/millennium/Navier-Stokes-Equation",
		"https://www.claymath.org/news/navier-stokes-announcement", "https://arxiv.org/abs/2509.25116", "https://arxiv.org/abs/2609.35406",
		"https://openai.com/index/navier-stokes-solution",
	}; !slices.Equal(urls, want) {
		t.Errorf("citations %v", urls)
	}
	if c := out.Citations[1]; c.Title != "Navier-Stokes Equation - Clay Mathematics Institute" || len(c.Excerpts) != 1 {
		t.Errorf("citation %+v", c)
	}

	twice := `{"run":{"run_id":"r","status":"completed"},"output":{"type":"text","content":"report","basis":[` +
		`{"field":"a","citations":[{"url":"https://example.com/a","title":null,"excerpts":["one","two"]},{"url":"javascript:alert(1)","title":"x","excerpts":["x"]}]},` +
		`{"field":"b","citations":[{"url":"https://example.com/a","title":"later","excerpts":["two","three"]},{"url":"https://user:pw@example.com/","excerpts":[]}]}]}}`
	s = &standIn{reply: replying(200, twice)}
	srv = s.serve(t)
	out, err = mustResearch(t, srv.URL, srv.Client()).Output(context.Background(), testRunID)
	got, _ := json.Marshal(out)
	if want := `{"content":"report","citations":[{"url":"https://example.com/a","title":"","excerpts":["one","two","three"]}]}`; err != nil || string(got) != want {
		t.Errorf("output %s err %v, want %s", got, err, want)
	}
	for name, reply := range map[string]string{
		"no output":       `{"run":{"run_id":"r","status":"completed"},"output":null}`,
		"a json output":   `{"run":{"run_id":"r","status":"completed"},"output":{"type":"json","content":{"answer":"x"},"basis":[]}}`,
		"not json at all": `<html>` + vendorCanary + `</html>`,
	} {
		s := &standIn{reply: replying(200, reply)}
		srv := s.serve(t)
		if _, err := mustResearch(t, srv.URL, srv.Client()).Output(context.Background(), testRunID); !errors.Is(err, research.ErrUpstream) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s = &standIn{reply: replying(200, `{"output":{"type":"text","content":"r","basis":[]}}`)}
	srv = s.serve(t)
	if out, err := mustResearch(t, srv.URL, srv.Client()).Output(context.Background(), testRunID); err != nil || out.Citations == nil {
		t.Errorf("an uncited report: %+v %v, want an empty list of citations", out, err)
	}
}

// Two real runs of the same question, 2026-10-13: one wrote its report as markdown, the other as
// Parallel's answer object followed by the References.
const (
	leakedResult = `{"run":{"run_id":"trun_5275cd978ff644ce8c180d64ff749e7d","interaction_id":"trun_5275cd978ff644ce8c180d64ff749e7d","status":"completed","is_active":false,"processor":"pro","metadata":{},"created_at":"2026-10-13T08:19:30.805312Z","modified_at":"2026-10-13T08:20:07.021696Z"},"output":{"basis":[{"field":"answer","citations":[{"title":"133 years and 330 metres - The Eiffel Tower","url":"https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet","excerpts":["133 years and 1,083 feet!","There are just a few days between the Eiffel Tower celebrating its new height of 1,083 feet (March 22) and its 133rd birthday (March 31). [**The monument has just grown 20 feet**](https://www.toureiffel.paris/en/news/events/eiffel-tower-grows-330-meters-tall) , with the installation of a new digital radio (DAB+) antenna."]}],"reasoning":"Reasoning: The user query asks for the current height of the Eiffel Tower including antennas. The provided field_answer states: 330 metres (1,083 feet) tall including antennas, which directly answers the question. The excerpts corroborate this by mentioning 1,083 feet and 330 metres and noting the antenna installation that increased height (20 feet), aligning with the figures in the field_answer. Therefore, the field_answer is complete and supported by excerpts.","confidence":"high"}],"type":"text","content":"{\"answer\": \"The Eiffel Tower is **330 metres (1,083 feet) tall, including its antennas**. Its height increased by 6 metres with the installation of a new digital radio antenna in 2022. The Eiffel Tower\\u2019s height after the new antenna installation was **1,083 feet (330 metres)**, an increase of **20 feet**. [1]\", \"prior_context_usage\": \"not_used\"}\n\n## References\n\n1. *133 years and 330 metres - The Eiffel Tower*. https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet\n"}}`
	plainResult  = `{"run":{"run_id":"trun_5275cd978ff644ce991cd1b3c49a588f","interaction_id":"trun_5275cd978ff644ce991cd1b3c49a588f","status":"completed","is_active":false,"processor":"pro","metadata":{},"created_at":"2026-10-13T08:17:27.640383Z","modified_at":"2026-10-13T08:17:49.557875Z"},"output":{"basis":[{"field":"answer","citations":[{"title":"133 years and 330 metres - The Eiffel Tower","url":"https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet","excerpts":["After 2 years, 2 months and 5 days of construction works , the Eiffel Tower was completed on March 31, 1889."]}],"reasoning":"The user asked for the year the Eiffel Tower opened. The field answer provides the year 1889, which directly answers the query. The excerpt confirms that construction completed in 1889, which aligns with the opening year and supports the answer. Therefore, completeness is true. Since the excerpts mention the 1889 completion/opening year context, the field answer is supported by the excerpts. No contradictions found.","confidence":"high"}],"type":"text","content":"The Eiffel Tower opened in **1889**. [1]\n\n## References\n\n1. *133 years and 330 metres - The Eiffel Tower*. https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet\n"}}`
)

const eiffelReferences = "\n\n## References\n\n1. *133 years and 330 metres - The Eiffel Tower*. https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet\n"

func unwrapping(t *testing.T, s *standIn) (*Research, *[]string) {
	t.Helper()
	srv := s.serve(t)
	var runs []string
	r, err := NewResearch(srv.URL, apiKey, "pro", srv.Client(), func(id string) { runs = append(runs, id) })
	if err != nil {
		t.Fatal(err)
	}
	return r, &runs
}

func TestAReportWrittenAsParallelsAnswerObjectIsTheAnswerAndTheReferencesAfterIt(t *testing.T) {
	r, runs := unwrapping(t, &standIn{reply: replying(200, leakedResult)})
	out, err := r.Output(context.Background(), testRunID)
	want := "The Eiffel Tower is **330 metres (1,083 feet) tall, including its antennas**. Its height increased by 6 metres with the installation of a new digital radio antenna in 2022. The Eiffel Tower’s height after the new antenna installation was **1,083 feet (330 metres)**, an increase of **20 feet**. [1]" + eiffelReferences
	if err != nil || out.Content != want {
		t.Fatalf("content %q err %v, want %q", out.Content, err, want)
	}
	if len(out.Citations) != 1 || out.Citations[0].URL != "https://www.toureiffel.paris/en/news/history-and-culture/133-years-and-1083-feet" {
		t.Errorf("citations %+v", out.Citations)
	}
	if !slices.Equal(*runs, []string{testRunID}) {
		t.Errorf("reported runs %q, want the one run", *runs)
	}

	r, runs = unwrapping(t, &standIn{reply: replying(200, plainResult)})
	out, err = r.Output(context.Background(), testRunID)
	if want := "The Eiffel Tower opened in **1889**. [1]" + eiffelReferences; err != nil || out.Content != want || len(*runs) != 0 {
		t.Errorf("a markdown report: content %q err %v reported runs %q", out.Content, err, *runs)
	}
}

func TestOnlyAnObjectWithAnAnswerThatIsNonEmptyTextIsUnwrappedAndAnythingElseIsTheReportAsWritten(t *testing.T) {
	refs := "\n\n## References\n\n1. *A page*. https://example.com/a\n"
	cases := map[string]struct{ content, want string }{
		"the object alone":        {`{"answer": "The answer. [1]", "prior_context_usage": "not_used"}`, "The answer. [1]"},
		"leading whitespace":      {" \n\t" + `{"answer":"The answer."}` + refs, " \n\tThe answer." + refs},
		"text right after it":     {`{"answer":"The answer."}` + "and more", "The answer.and more"},
		"an object in the answer": {`{"answer":"Use {\"a\": \"}\"}."}` + refs, `Use {"a": "}"}.` + refs},
	}
	untouched := map[string]string{
		"a markdown report":           "# Title\n\nText [1]." + refs,
		"a json code block":           "```json\n" + `{"answer": "The answer."}` + "\n```" + refs,
		"no answer":                   `{"summary": "The answer.", "prior_context_usage": "not_used"}` + refs,
		"an answer in another case":   `{"Answer": "The answer."}` + refs,
		"an empty answer":             `{"answer": "", "prior_context_usage": "not_used"}` + refs,
		"a null answer":               `{"answer": null}` + refs,
		"a number answer":             `{"answer": 330}` + refs,
		"an object answer":            `{"answer": {"text": "The answer."}}` + refs,
		"malformed json":              `{"answer": "The answer.",}` + refs,
		"an object that never closes": `{"answer": "The answer.` + refs,
		"an array":                    `[{"answer": "The answer."}]` + refs,
		"whitespace alone":            " \n",
	}
	for name, content := range untouched {
		cases[name] = struct{ content, want string }{content, content}
	}
	for name, c := range cases {
		r, runs := unwrapping(t, &standIn{reply: replying(200, `{"output":{"type":"text","content":`+string(mustJSON(c.content))+`,"basis":[]}}`)})
		out, err := r.Output(context.Background(), testRunID)
		if err != nil || out.Content != c.want {
			t.Errorf("%s: content %q err %v, want %q", name, out.Content, err, c.want)
		}
		if _, asWritten := untouched[name]; asWritten != (len(*runs) == 0) {
			t.Errorf("%s: reported runs %q", name, *runs)
		}
	}
}

func streaming(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}
}

func relayed(t *testing.T, r *Research) ([]string, error) {
	t.Helper()
	stream, err := r.Watch(context.Background(), testRunID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	var got []string
	err = stream.Each(func(e research.Event) error {
		b, _ := json.Marshal(e)
		got = append(got, string(b))
		return nil
	})
	return got, err
}

func TestARealEventStreamIsRelayedAsTheAllowlistedShapesAlone(t *testing.T) {
	sample, err := os.ReadFile("testdata/events.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{reply: streaming(string(sample))}
	srv := s.serve(t)
	got, err := relayed(t, mustResearch(t, srv.URL, srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	c := s.only(t)
	if c.method != http.MethodGet || c.path != "/v1/tasks/runs/"+testRunID+"/events" || c.header.Get("Accept") != "text/event-stream" || c.header.Get("X-Api-Key") != apiKey {
		t.Errorf("%s %s headers %v", c.method, c.path, c.header)
	}
	if len(got) != 56 || got[0] != `{"type":"state","status":"queued"}` || got[len(got)-1] != `{"type":"state","status":"completed"}` {
		t.Fatalf("%d events, first %s last %s", len(got), got[0], got[len(got)-1])
	}
	counts := map[string]int{}
	for _, e := range got {
		var fields map[string]any
		if err := json.Unmarshal([]byte(e), &fields); err != nil {
			t.Fatal(err)
		}
		keys := slices.Sorted(maps.Keys(fields))
		shape := fields["type"].(string) + " " + strings.Join(keys, ",")
		counts[shape]++
		if strings.Contains(e, "Listing tools") || strings.Contains(e, "sources_read_sample") || strings.Contains(e, "progress_meter") || strings.Contains(e, "Navier-Stokes Millennium Prize Problem |") {
			t.Errorf("relayed vendor detail: %s", e)
		}
	}
	want := map[string]int{
		"state status,type": 2, "note kind,message,type": 8, "search objective,type": 13, "search query,type": 17,
		"read type,url": 5, "stats considered,read,type": 11,
	}
	if !maps.Equal(counts, want) {
		t.Errorf("shapes %v, want %v", counts, want)
	}
	for _, e := range []string{
		`{"type":"note","kind":"status","message":"Starting research"}`,
		`{"type":"search","objective":"Find Clay Mathematics Institute official 3D Navier-Stokes Millennium problem statement and current status"}`,
		`{"type":"search","query":"Clay Navier Stokes existence smoothness unsolved official problem"}`,
		`{"type":"read","url":"https://www.claymath.org/millennium/Navier-Stokes-Equation"}`,
		`{"type":"stats","considered":0,"read":0}`,
		`{"type":"stats","considered":255,"read":0}`,
	} {
		if !slices.Contains(got, e) {
			t.Errorf("missing %s", e)
		}
	}
}

func TestEventsAreCappedAndAnythingUnknownOrMalformedIsDropped(t *testing.T) {
	long := strings.Repeat("ü", research.MaxMessageChars+50)
	huge := strings.Repeat("x", 2*maxEventBytes)
	stream := strings.Join([]string{
		`data: {"type":"task_run.state","run":{"run_id":"r","status":"running","is_active":true},"output":null}`,
		`data: {"type":"task_run.progress_msg.plan","message":"` + long + `"}`,
		`data: {"type":"task_run.progress_msg.plan","message":"` + huge + `"}`,
		`data: {"type":"task_run.progress_msg.result","message":"   "}`,
		`data: {"type":"task_run.progress_msg.tool_call","message":"` + vendorCanary + `"}`,
		`data: {"type":"error","message":"` + vendorCanary + `","error":{"ref_id":"` + vendorCanary + `"}}`,
		`data: {"type":"task_run.progress_msg.search","message":"Lookup: ` + vendorCanary + `"}`,
		`data: {"type":"task_run.progress_msg.search","message":"Query:   spaced  "}`,
		`data: {"type":"task_run.progress_msg.extract","message":"Extract: javascript:alert(1)"}`,
		`data: {"type":"task_run.progress_msg.extract","message":"Extract: https://example.com/` + strings.Repeat("a", web.MaxURLLength) + `"}`,
		`data: {"type":"task_run.progress_msg.extract","message":"Read: https://example.com/"}`,
		`data: {"type":"task_run.progress_stats","source_stats":{"num_sources_considered":-4,"num_sources_read":7,"sources_read_sample":["https://` + vendorCanary + `"]},"progress_meter":12.5}`,
		`data: {"type":"task_run.progress_stats"}`,
		`data: {"type":"task_run.state","run":{"run_id":"r","status":"teleported"}}`,
		`data: not json ` + vendorCanary,
		`data: {"type":"task_run.state","run":{"run_id":"r","status":"completed","is_active":false},"output":{"type":"text","content":"` + huge + `"}}`,
		`data: {"type":"task_run.progress_msg.plan","message":"after the end"}`,
	}, "\n\n") + "\n\n"
	s := &standIn{reply: streaming(stream)}
	srv := s.serve(t)
	got, err := relayed(t, mustResearch(t, srv.URL, srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"type":"state","status":"running"}`,
		`{"type":"note","kind":"plan","message":"` + strings.Repeat("ü", research.MaxMessageChars) + `"}`,
		`{"type":"search","query":"spaced"}`,
		`{"type":"stats","considered":0,"read":7}`,
		`{"type":"state","status":"completed"}`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("relayed\n%v\nwant\n%v", got, want)
	}
	for _, e := range got {
		if strings.Contains(e, vendorCanary) {
			t.Errorf("vendor text reached the client: %s", e)
		}
	}
}

func TestAStreamThatEndsWhileTheRunIsActiveEndsQuietlyAndAnEmitErrorStopsIt(t *testing.T) {
	s := &standIn{reply: streaming(`data: {"type":"task_run.state","run":{"status":"running"}}` + "\n\n" + `data: {"type":"task_run.progress_msg.plan","message":"p"}` + "\n\n")}
	srv := s.serve(t)
	r := mustResearch(t, srv.URL, srv.Client())
	if got, err := relayed(t, r); err != nil || len(got) != 2 {
		t.Errorf("relayed %v err %v", got, err)
	}
	stream, err := r.Watch(context.Background(), testRunID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	gone := errors.New("client gone")
	calls := 0
	if err := stream.Each(func(research.Event) error { calls++; return gone }); !errors.Is(err, gone) || calls != 1 {
		t.Errorf("err %v after %d events", err, calls)
	}
}

const tasksRPM = 2000

func TestTheResearchLimitKeepsItsBucketAndLeavesHeadroomUnderTheTasksLimit(t *testing.T) {
	if ResearchLimit.Subject != "parallel/research" {
		t.Errorf("subject %q: renaming it starts a fresh bucket in the database", ResearchLimit.Subject)
	}
	if worstMinute := ResearchLimit.RPM + 1 + ResearchLimit.RPM/10; !ResearchLimit.Valid() || worstMinute*2 > tasksRPM {
		t.Errorf("the research limit admits up to %d runs a minute, more than half of Parallel's %d task runs a minute", worstMinute, tasksRPM)
	}
}
