package worker

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
)

// A step is one upstream call of a run, admitted under the handle the worker's own openChat, openSearch, or openFetch
// gave it, so the relay charges and runs it as it would a client's request. What runs under the handle is the step:
// it runs the opened request into a capture, keeps what the reply said for the run, and answers the relay with the
// status a client would have seen and {}, or the refusal envelope a client would have seen, never the content.

// A stepper is a request the worker opened that runs under a grant: an openedChat or an openedCall.
type stepper interface {
	opened
	runs
}

type stepState uint8

const (
	stepIssued stepState = iota
	stepRunning
	stepRan
)

type taskStep struct {
	owner *taskRun
	kind  catalog.Kind
	// body is the request the step was opened from, which opens it again under a new handle if it never ran.
	body []byte
	// tools is whether a chat pass sent the tools' definitions, callable whether the model may call them.
	tools, callable bool
	// call is the tool call a search or a page read answers, page the page a read opens.
	call  *taskCall
	page  *url.URL
	inner stepper
	// handle and state are the run's, read and written under its lock.
	handle Handle
	state  stepState
	got    stepGot
}

func (s *taskStep) cut(reason measure.Cut) { s.inner.cut(reason) }

func (s *taskStep) run(ctx context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	if !s.owner.starting(s) {
		return unrunnable(reply)
	}
	c := &stepCapture{header: http.Header{}, chat: s.kind == catalog.KindChat}
	m := s.inner.run(ctx, w, h, g, c)
	s.owner.ran(s, c.got(m))
	c.answer(reply)
	return m
}

// again is the step to issue in place of s, which never ran: the same request under a new handle.
func (s *taskStep) again() *taskStep {
	return &taskStep{owner: s.owner, kind: s.kind, body: s.body, tools: s.tools, callable: s.callable, call: s.call, page: s.page}
}

// stepGot is what a step's reply said: whether it was served, and if not, the status and the code a client would
// have seen; for a chat pass, its answer and calls; for a search or a page read, its JSON.
type stepGot struct {
	served  bool
	status  int
	code    string
	content string
	calls   []capturedCall
	finish  string
	body    []byte
}

type capturedCall struct {
	index      int
	id, name   string
	args       []byte
	overflowed bool
}

const (
	// maxCapturedContent bounds the answer a pass keeps, well past what a result carries.
	maxCapturedContent = 1 << 20
	// maxCapturedArgs bounds one call's arguments, and maxCapturedCalls the calls a pass keeps.
	maxCapturedArgs  = 64 << 10
	maxCapturedCalls = 64
	// maxCapturedBody bounds a search's or a page's JSON, and a refusal's envelope.
	maxCapturedBody = 4 << 20
	maxCapturedSSE  = 4 << 20
)

// stepCapture is the reply writer a step's request runs into. A chat pass streams, so its events are read as they
// come and only the answer and calls are kept; any other reply is kept whole, within its bound.
type stepCapture struct {
	header  http.Header
	status  int
	chat    bool
	decided bool
	sse     bool
	pending []byte
	body    []byte
	content bytes.Buffer
	calls   []*capturedCall
	finish  string
	failed  string
	broken  bool
}

func (c *stepCapture) Header() http.Header { return c.header }

func (c *stepCapture) WriteHeader(code int) {
	if c.status == 0 && code >= http.StatusOK {
		c.status = code
	}
}

func (c *stepCapture) Write(p []byte) (int, error) {
	c.WriteHeader(http.StatusOK)
	if !c.decided {
		c.decided = true
		c.sse = c.chat && c.status/100 == 2 && streamed(c.header.Get("Content-Type"))
	}
	if !c.sse {
		c.body = append(c.body, p[:min(len(p), max(0, maxCapturedBody-len(c.body)))]...)
		return len(p), nil
	}
	c.pending = append(c.pending, p...)
	for {
		end := bytes.Index(c.pending, []byte("\n\n"))
		if end < 0 {
			break
		}
		c.event(c.pending[:end])
		c.pending = append(c.pending[:0], c.pending[end+2:]...)
	}
	if len(c.pending) > maxCapturedSSE {
		c.pending, c.broken = nil, true
	}
	return len(p), nil
}

// FlushError lets the chat writers flush, which a capture needs nothing for.
func (c *stepCapture) FlushError() error { return nil }

// event reads one event of the worker's own stream: a chunk, a keepalive comment, the error event a stream that
// failed after it began ends with, or [DONE].
func (c *stepCapture) event(block []byte) {
	var data []byte
	for line := range bytes.SplitSeq(block, []byte("\n")) {
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(value, []byte(" "))...)
		}
	}
	if data == nil || string(data) == "[DONE]" {
		return
	}
	c.chunk(data)
}

// chunk reads one chat completion object: a streamed chunk, whose choices carry deltas, or a whole completion, whose
// choices carry messages.
func (c *stepCapture) chunk(data []byte) {
	var chunk struct {
		ID      string `json:"id"`
		Choices []struct {
			Index   int             `json:"index"`
			Delta   *chunkDelta     `json:"delta"`
			Message *chunkDelta     `json:"message"`
			Finish  json.RawMessage `json:"finish_reason"`
		} `json:"choices"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &chunk) != nil {
		c.broken = true
		return
	}
	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		c.failed = cmp.Or(codeOf(data), apierr.ErrUpstream.Code)
		return
	}
	for _, choice := range chunk.Choices {
		if choice.Index != 0 {
			continue
		}
		var finish string
		if json.Unmarshal(choice.Finish, &finish) == nil && finish != "" {
			c.finish = finish
		}
		for _, part := range []struct {
			name string
			d    *chunkDelta
		}{{"delta", choice.Delta}, {"message", choice.Message}} {
			if part.d != nil {
				c.delta(part.d)
			}
		}
	}
}

type chunkDelta struct {
	Content   json.RawMessage `json:"content"`
	ToolCalls []struct {
		Index    *int   `json:"index"`
		ID       string `json:"id"`
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

func (c *stepCapture) delta(d *chunkDelta) {
	var text string
	if json.Unmarshal(d.Content, &text) == nil {
		if c.content.Len() < maxCapturedContent {
			c.content.WriteString(text[:min(len(text), maxCapturedContent-c.content.Len())])
		}
	}
	for _, tc := range d.ToolCalls {
		call := c.callFor(tc.Index, tc.ID)
		if call == nil {
			continue
		}
		if tc.ID != "" && call.id == "" {
			call.id = tc.ID
		}
		call.name += tc.Function.Name
		var piece string
		if json.Unmarshal(tc.Function.Arguments, &piece) != nil && len(tc.Function.Arguments) > 0 && string(tc.Function.Arguments) != "null" {
			piece = string(tc.Function.Arguments)
		}
		if len(call.args)+len(piece) > maxCapturedArgs {
			call.overflowed = true
			continue
		}
		call.args = append(call.args, piece...)
	}
}

// callFor is the call a tool call delta adds to: the one of its index, or with none, a new call when it carries an
// id and the last call otherwise.
func (c *stepCapture) callFor(index *int, id string) *capturedCall {
	if index != nil {
		for _, call := range c.calls {
			if call.index == *index {
				return call
			}
		}
	} else if id == "" && len(c.calls) > 0 {
		return c.calls[len(c.calls)-1]
	}
	if len(c.calls) == maxCapturedCalls {
		return nil
	}
	call := &capturedCall{index: len(c.calls)}
	if index != nil {
		call.index = *index
	}
	c.calls = append(c.calls, call)
	return call
}

// got is what the reply came to, given how the step ran: a refusal's status and code, or for a served chat pass
// whose stream held together, its answer and calls.
func (c *stepCapture) got(m Measured) stepGot {
	status := cmp.Or(c.status, http.StatusOK)
	if c.chat && !c.sse && status/100 == 2 && len(c.body) > 0 {
		c.chunk(c.body)
	}
	g := stepGot{status: status, finish: c.finish}
	switch {
	case status/100 != 2:
		g.code = codeOf(c.body)
	case c.failed != "":
		g.code = c.failed
	case c.broken:
		g.code = apierr.ErrUpstream.Code
	}
	g.served = m.Served && status/100 == 2 && c.failed == "" && !c.broken
	if !g.served {
		return g
	}
	if !c.chat {
		g.body = c.body
		return g
	}
	g.content = c.content.String()
	for _, call := range c.calls {
		if !call.overflowed {
			g.calls = append(g.calls, *call)
		}
	}
	return g
}

// answer writes the relay what a client would have seen of the reply's status, and nothing of its content.
func (c *stepCapture) answer(reply http.ResponseWriter) {
	status := cmp.Or(c.status, http.StatusOK)
	reply.Header().Set("Content-Type", "application/json")
	reply.WriteHeader(status)
	if status/100 == 2 || len(c.body) == 0 {
		io.WriteString(reply, "{}")
		return
	}
	reply.Write(c.body)
}

func codeOf(envelope []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(envelope, &e) != nil {
		return ""
	}
	return e.Error.Code
}

// wrapStep makes the handle a's admission names run s: the admission is exactly what /open would answer, and the
// request it opened runs under s.
func (w *InProcess) wrapStep(a Admission, s *taskStep) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[a.Handle()]
	if e == nil || e.phase != waiting {
		return false
	}
	inner, ok := e.opened.(stepper)
	if !ok {
		return false
	}
	s.inner, s.handle = inner, a.Handle()
	e.opened = s
	return true
}
