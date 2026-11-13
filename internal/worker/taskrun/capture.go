package taskrun

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"morse/backend/internal/apierr"
)

type Got struct {
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
	maxCapturedContent = 1 << 20
	maxCapturedArgs    = 64 << 10
	maxCapturedCalls   = 64
	maxCapturedBody    = 4 << 20
	maxCapturedSSE     = 4 << 20
	eventStreamType    = "text/event-stream"
)

type Capture struct {
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

func NewCapture(chat bool) *Capture { return &Capture{header: http.Header{}, chat: chat} }

func (c *Capture) Header() http.Header { return c.header }

func (c *Capture) WriteHeader(code int) {
	if c.status == 0 && code >= http.StatusOK {
		c.status = code
	}
}

func (c *Capture) Write(p []byte) (int, error) {
	c.WriteHeader(http.StatusOK)
	if !c.decided {
		c.decided = true
		c.sse = c.chat && c.status/100 == 2 && strings.HasPrefix(strings.ToLower(c.header.Get("Content-Type")), eventStreamType)
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

func (c *Capture) FlushError() error { return nil }

func (c *Capture) event(block []byte) {
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

func (c *Capture) chunk(data []byte) {
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
		for _, d := range []*chunkDelta{choice.Delta, choice.Message} {
			if d != nil {
				c.delta(d)
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

func (c *Capture) delta(d *chunkDelta) {
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

func (c *Capture) callFor(index *int, id string) *capturedCall {
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

func (c *Capture) Got(served bool) Got {
	status := cmp.Or(c.status, http.StatusOK)
	if c.chat && !c.sse && status/100 == 2 && len(c.body) > 0 {
		c.chunk(c.body)
	}
	g := Got{status: status, finish: c.finish}
	switch {
	case status/100 != 2:
		g.code = codeOf(c.body)
	case c.failed != "":
		g.code = c.failed
	case c.broken:
		g.code = apierr.ErrUpstream.Code
	}
	g.served = served && status/100 == 2 && c.failed == "" && !c.broken
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

func (c *Capture) Answer(reply http.ResponseWriter) {
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
