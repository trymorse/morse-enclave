package research

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/enum"
	"morse/backend/internal/jobs"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/web"
)

const (
	MaxInputChars = 15_000
	// A character escaped as a JSON surrogate pair takes 12 bytes.
	MaxRequestBody   = 12*MaxInputChars + 4<<10
	MaxMessageChars  = 2_000
	MaxCitations     = 100
	MaxCitationChars = 4_000
)

var (
	ErrUpstreamBusy        = apierr.Error{Status: 503, Type: "upstream_error", Code: "upstream_busy", Message: "The research provider is busy. Try again shortly."}
	ErrUpstreamUnavailable = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_unavailable", Message: "The research provider is unavailable."}
	ErrUpstream            = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_error", Message: "The research provider failed."}
)

type Request struct {
	Model string
	input string
}

func (r Request) ModelName() string { return r.Model }
func (r Request) Input() string     { return r.input }
func (r Request) String() string {
	return fmt.Sprintf("research.Request(%s, %d characters)", r.Model, utf8.RuneCountInString(r.input))
}
func (r Request) GoString() string { return r.String() }

func ParseRequest(body io.Reader) (*Request, error) {
	fields, err := strictjson.Object(body, "model", "input")
	if err != nil {
		return nil, err
	}
	var model, input string
	if json.Unmarshal(fields["model"], &model) != nil || model == "" {
		return nil, strictjson.Invalid("model is required.")
	}
	invalid := strictjson.Invalid(fmt.Sprintf("input must be a string of 1 to %d characters.", MaxInputChars))
	if json.Unmarshal(fields["input"], &input) != nil {
		return nil, invalid
	}
	if input = strings.TrimSpace(input); input == "" || utf8.RuneCountInString(input) > MaxInputChars {
		return nil, invalid
	}
	return &Request{Model: model, input: input}, nil
}

var Statuses = enum.Names[jobs.Status]{jobs.Queued: "queued", jobs.Running: "running", jobs.Completed: "completed", jobs.Failed: "failed", jobs.Expired: "expired"}

type Citation struct {
	URL      string   `json:"url"`
	Title    string   `json:"title"`
	Excerpts []string `json:"excerpts"`
}

type Output struct {
	Content   string     `json:"content"`
	Citations []Citation `json:"citations"`
}

func (o Output) String() string {
	return fmt.Sprintf("research.Output(%d bytes, %d citations)", len(o.Content), len(o.Citations))
}
func (o Output) GoString() string { return o.String() }

type Citations struct {
	list  []Citation
	chars []int
	seen  map[string]int
}

func (cs *Citations) Add(link string, title *string, excerpts []string) {
	link, ok := web.PageURL(link)
	if !ok {
		return
	}
	if cs.seen == nil {
		cs.seen = map[string]int{}
	}
	i, seen := cs.seen[link]
	if !seen {
		if len(cs.list) == MaxCitations {
			return
		}
		i = len(cs.list)
		cs.seen[link] = i
		cs.list = append(cs.list, Citation{URL: link, Title: web.TitleOf(title), Excerpts: []string{}})
		cs.chars = append(cs.chars, 0)
	}
	c := &cs.list[i]
	for _, e := range excerpts {
		left := MaxCitationChars - cs.chars[i]
		if left <= 0 {
			return
		}
		if strings.TrimSpace(e) == "" || slices.Contains(c.Excerpts, e) {
			continue
		}
		e, _ = web.Clip(e, left)
		cs.chars[i] += utf8.RuneCountInString(e)
		c.Excerpts = append(c.Excerpts, e)
	}
}

func (cs Citations) List() []Citation {
	if cs.list == nil {
		return []Citation{}
	}
	return cs.list
}

type Researcher interface {
	Start(ctx context.Context, req *Request) (runID string, err error)
	Check(ctx context.Context, runID string) (jobs.Poll, error)
	Output(ctx context.Context, runID string) (Output, error)
	Watch(ctx context.Context, runID string) (Stream, error)
}

// Each delivers the run's events in order and returns nil once the vendor ends the stream or the run
// stops being active.
type Stream interface {
	Each(emit func(Event) error) error
	Close() error
}
