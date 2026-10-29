package parallel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"morse/backend/internal/jobs"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/research"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const (
	runsPath      = "/v1/tasks/runs"
	researchRPM   = 300
	maxEventBytes = 64 << 10
)

var ResearchLimit = limits.SharedLimit{Subject: "parallel/research", RPM: researchRPM}

var (
	processors = []string{"pro", "ultra", "pro-fast", "ultra-fast"}
	runID      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

type Research struct {
	client
	processor string
	unwrapped func(runID string)
}

// unwrapped, when not nil, is called with the run id each time Output reads a report that Parallel wrote as its
// answer object.
func NewResearch(baseURL, apiKey, processor string, httpClient *http.Client, unwrapped func(runID string)) (*Research, error) {
	if !slices.Contains(processors, processor) {
		return nil, fmt.Errorf("%q is not a research processor parallel serves, one of %s", processor, strings.Join(processors, ", "))
	}
	if unwrapped == nil {
		unwrapped = func(string) {}
	}
	return &Research{client: newClient(baseURL, apiKey, httpClient, researchErrors), processor: processor, unwrapped: unwrapped}, nil
}

type outputSchema struct {
	Type string `json:"type"`
}

type taskSpec struct {
	OutputSchema outputSchema `json:"output_schema"`
}

// Parallel keeps a run's metadata with the run, so the proxy sends none, and no memory_scope_key, which
// would save the input and output to an application memory.
type runRequest struct {
	Input        string   `json:"input"`
	Processor    string   `json:"processor"`
	EnableEvents bool     `json:"enable_events"`
	TaskSpec     taskSpec `json:"task_spec"`
}

type run struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
}

func (r *Research) Start(ctx context.Context, req *research.Request) (string, error) {
	body := runRequest{Input: req.Input(), Processor: r.processor, EnableEvents: true, TaskSpec: taskSpec{OutputSchema: outputSchema{Type: "text"}}}
	var got run
	if err := r.call(ctx, upstream.Request{Method: http.MethodPost, Path: runsPath, Body: jsonx.Encode(body)}, &got); err != nil {
		return "", err
	}
	if !runID.MatchString(got.RunID) {
		return "", research.ErrUpstream
	}
	return got.RunID, nil
}

func runPath(id string) (string, error) {
	if !runID.MatchString(id) {
		return "", research.ErrUpstream
	}
	return runsPath + "/" + id, nil
}

// A run Parallel reports failed, cancelled or waiting on an action never completes, so each one is
// the client's upstream_error; only the proxy's own deadline makes a timeout.
var statuses = map[string]jobs.Poll{
	"queued":          {Status: jobs.Queued},
	"running":         {Status: jobs.Running},
	"cancelling":      {Status: jobs.Running},
	"completed":       {Status: jobs.Completed},
	"failed":          jobs.Unserved,
	"cancelled":       jobs.Unserved,
	"action_required": jobs.Unserved,
}

func (r *Research) Check(ctx context.Context, id string) (jobs.Poll, error) {
	path, err := runPath(id)
	if err != nil {
		return jobs.Poll{}, err
	}
	var got run
	if err := r.call(ctx, upstream.Request{Method: http.MethodGet, Path: path}, &got); err != nil {
		return jobs.Poll{}, err
	}
	poll, known := statuses[got.Status]
	if !known {
		return jobs.Poll{}, upstream.ErrMalformed
	}
	return poll, nil
}

type citation struct {
	URL      string   `json:"url"`
	Title    *string  `json:"title"`
	Excerpts []string `json:"excerpts"`
}

type basis struct {
	Citations []citation `json:"citations"`
}

type runResult struct {
	Output *struct {
		Content json.RawMessage `json:"content"`
		Basis   []basis         `json:"basis"`
	} `json:"output"`
}

func (r *Research) Output(ctx context.Context, id string) (research.Output, error) {
	path, err := runPath(id)
	if err != nil {
		return research.Output{}, err
	}
	var got runResult
	if err := r.call(ctx, upstream.Request{Method: http.MethodGet, Path: path + "/result"}, &got); err != nil {
		return research.Output{}, err
	}
	var content string
	if got.Output == nil || json.Unmarshal(got.Output.Content, &content) != nil {
		return research.Output{}, research.ErrUpstream
	}
	if answer, leaked := unwrapAnswer(content); leaked {
		r.unwrapped(id)
		content = answer
	}
	var cited research.Citations
	for _, b := range got.Output.Basis {
		for _, c := range b.Citations {
			cited.Add(c.URL, c.Title, c.Excerpts)
		}
	}
	return research.Output{Content: content, Citations: cited.List()}, nil
}

// Parallel sometimes writes a text run's content as its own answer object, {"answer": "..."},
// followed by the References, so the report is the answer and whatever follows the object. What
// follows leaves the whole content short of JSON, so the decoder reads the first value alone.
func unwrapAnswer(content string) (string, bool) {
	object := strings.TrimLeft(content, " \t\r\n")
	if !strings.HasPrefix(object, "{") {
		return content, false
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(object))
	if dec.Decode(&fields) != nil {
		return content, false
	}
	var answer string
	if json.Unmarshal(fields["answer"], &answer) != nil || answer == "" {
		return content, false
	}
	return content[:len(content)-len(object)] + answer + object[dec.InputOffset():], true
}

func (r *Research) Watch(ctx context.Context, id string) (research.Stream, error) {
	path, err := runPath(id)
	if err != nil {
		return nil, err
	}
	resp, err := r.vendor.Open(ctx, upstream.Request{Method: http.MethodGet, Path: path + "/events", Header: http.Header{"Accept": {"text/event-stream"}}})
	if err != nil {
		return nil, err
	}
	return events{resp.Body}, nil
}

type events struct{ body io.ReadCloser }

func (e events) Close() error { return e.body.Close() }

var errRunEnded = errors.New("parallel: the run is no longer active")

func (e events) Each(emit func(research.Event) error) error {
	err := sse.Each(e.body, maxEventBytes, sse.Clip, func(data []byte) (bool, error) {
		event, ok := normalize(data)
		if !ok {
			return false, nil
		}
		if err := emit(event); err != nil {
			return true, err
		}
		if s, isState := event.Status(); isState && !s.Active() {
			return true, errRunEnded
		}
		return false, nil
	})
	if errors.Is(err, sse.ErrTruncated) || errors.Is(err, errRunEnded) {
		return nil
	}
	return err
}

type stats struct {
	Considered int `json:"num_sources_considered"`
	Read       int `json:"num_sources_read"`
}

type vendorEvent struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Run     *run   `json:"run"`
	Stats   *stats `json:"source_stats"`
}

var notes = map[string]research.NoteKind{
	"task_run.progress_msg.plan":        research.Plan,
	"task_run.progress_msg.result":      research.Result,
	"task_run.progress_msg.exec_status": research.Progress,
}

func normalize(data []byte) (research.Event, bool) {
	v := peek(data)
	if kind, isNote := notes[v.Type]; isNote {
		return research.Note(kind, v.Message)
	}
	switch v.Type {
	case "task_run.state":
		if v.Run == nil {
			return research.Event{}, false
		}
		poll, known := statuses[v.Run.Status]
		return research.State(poll.Status), known
	case "task_run.progress_msg.search":
		if objective, ok := strings.CutPrefix(v.Message, "Objective:"); ok {
			return research.Objective(objective)
		}
		if query, ok := strings.CutPrefix(v.Message, "Query:"); ok {
			return research.Query(query)
		}
	case "task_run.progress_msg.extract":
		if link, ok := strings.CutPrefix(v.Message, "Extract:"); ok {
			return research.Read(link)
		}
	case "task_run.progress_stats":
		if v.Stats != nil {
			return research.Stats(v.Stats.Considered, v.Stats.Read), true
		}
	}
	return research.Event{}, false
}

// A completed run's state event carries the whole report after its run object, past the clip, so
// peek reads the object's fields in order and keeps what it read before the JSON broke off.
func peek(data []byte) vendorEvent {
	var v vendorEvent
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return vendorEvent{}
	}
	fields := map[string]any{"type": &v.Type, "message": &v.Message, "run": &v.Run, "source_stats": &v.Stats}
	for dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			return v
		}
		into, wanted := fields[key]
		if !wanted {
			into = new(json.RawMessage)
		}
		if dec.Decode(into) != nil {
			return v
		}
		if v.Type == "task_run.state" && v.Run != nil {
			return v
		}
	}
	return v
}
