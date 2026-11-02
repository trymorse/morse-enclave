package completions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const maxEvent = 16 << 20

var ErrStreamFailed = errors.New("completions: the upstream stream failed")

var errMalformedToolCall = errors.New("completions: the upstream started a tool call without an id or name, or twice")

type Translator interface {
	Request(conv Conversation) (path, accept string, body any)
	Events(w *Writer) func(data []byte) (done bool, err error)
}

type Events map[string]func(data []byte) (done bool, err error)

func On[E any](handle func(E) (done bool, err error)) func([]byte) (bool, error) {
	return func(data []byte) (bool, error) {
		var e E
		if json.Unmarshal(data, &e) != nil {
			return false, ErrStreamFailed
		}
		return handle(e)
	}
}

// ByType handles an event by its type field. It skips an event of a type no handler names and fails on a
// handled event that does not decode.
func (es Events) ByType(data []byte) (bool, error) {
	var peek struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &peek) != nil {
		return false, ErrStreamFailed
	}
	handle, handled := es[peek.Type]
	if !handled {
		return false, nil
	}
	return handle(data)
}

type Provider struct {
	upstream.Endpoint
	Translator Translator
	// ReadsToEnd marks a vendor whose stream has no closing event: once the reply has finished, the end of the
	// stream is its clean end.
	ReadsToEnd bool
}

var _ chat.Provider = (*Provider)(nil)

func (p *Provider) Stream(ctx context.Context, c chat.Call, emit func(chat.Chunk) error) (chat.Usage, error) {
	conv, err := parseConversation(c)
	if err != nil {
		return chat.Usage{}, err
	}
	out := newEnvelope(c.Model)
	usage, detailed, err := p.run(ctx, conv, &Writer{emit: func(d delta, finish *Finish) error {
		return emit(chat.NewChunk(out.Chunk(d, finish)))
	}})
	if err != nil || !c.IncludeUsage {
		return usage, err
	}
	return usage, emit(chat.NewChunk(out.Usage(usage, detailed)))
}

func (p *Provider) Complete(ctx context.Context, c chat.Call) (chat.Chunk, chat.Usage, error) {
	conv, err := parseConversation(c)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	var r reply
	usage, detailed, err := p.run(ctx, conv, &Writer{emit: r.add})
	if err != nil {
		return chat.Chunk{}, usage, err
	}
	return chat.NewChunk(newEnvelope(c.Model).Completion(&r, usage, detailed)), usage, nil
}

func (p *Provider) run(ctx context.Context, conv Conversation, w *Writer) (chat.Usage, bool, error) {
	path, accept, body := p.Translator.Request(conv)
	resp, err := p.Open(ctx, upstream.Request{Method: http.MethodPost, Path: path, Header: http.Header{"Accept": {accept}}, Body: jsonx.Encode(body)})
	if err != nil {
		return chat.Usage{}, false, err
	}
	defer resp.Body.Close()
	err = sse.Each(resp.Body, maxEvent, sse.Refuse, p.Translator.Events(w))
	if p.ReadsToEnd && w.finished && errors.Is(err, sse.ErrTruncated) {
		err = nil
	}
	return w.usage.Normalized(), w.detailed, err
}

type toolCall struct {
	index        int
	hasArguments bool
}

type Writer struct {
	emit     func(delta, *Finish) error
	started  bool
	finished bool
	calls    map[int]*toolCall
	usage    chat.Usage
	detailed bool
}

func (w *Writer) Count(u chat.Usage, detailed bool) { w.usage, w.detailed = u, detailed }

func (w *Writer) Start() error {
	if w.started {
		return nil
	}
	w.started = true
	return w.emit(delta{Role: "assistant", Content: new(string)}, nil)
}

// Fail answers a vendor error event. Once a delta has gone out the status line is already sent, so
// the vendor's code can no longer choose the answer.
func (w *Writer) Fail(code string, otherwise apierr.Error) error {
	if w.started {
		return fmt.Errorf("%w: %w", ErrStreamFailed, chat.ErrorChunkCoded(code))
	}
	if known, ok := apierr.VendorCode(code); ok {
		return known
	}
	return otherwise
}

func (w *Writer) Calls() int { return len(w.calls) }

func (w *Writer) Text(fragment string) error {
	if err := w.Start(); err != nil || fragment == "" {
		return err
	}
	return w.emit(delta{Content: &fragment}, nil)
}

func (w *Writer) Refusal(fragment string) error {
	if err := w.Start(); err != nil || fragment == "" {
		return err
	}
	return w.emit(delta{Refusal: &fragment}, nil)
}

func (w *Writer) ToolStart(key int, id, name string) error {
	if err := w.Start(); err != nil {
		return err
	}
	if _, seen := w.calls[key]; seen || id == "" || name == "" {
		return errMalformedToolCall
	}
	if w.calls == nil {
		w.calls = map[int]*toolCall{}
	}
	call := &toolCall{index: len(w.calls)}
	w.calls[key] = call
	return w.emit(toolDelta(call.index, ToolCall{ID: id, Type: "function", Function: FunctionCall{Name: name}}), nil)
}

func (w *Writer) ToolArguments(key int, fragment string) error {
	call := w.calls[key]
	if call == nil || fragment == "" {
		return nil
	}
	call.hasArguments = true
	return w.emit(toolDelta(call.index, ToolCall{Function: FunctionCall{Arguments: fragment}}), nil)
}

func (w *Writer) ToolEnd(key int, final string) error {
	call := w.calls[key]
	if call == nil || call.hasArguments {
		return nil
	}
	if final == "" {
		final = EmptyArguments
	}
	call.hasArguments = true
	return w.emit(toolDelta(call.index, ToolCall{Function: FunctionCall{Arguments: final}}), nil)
}

func (w *Writer) Finished() bool { return w.finished }

func (w *Writer) Finish(reason Finish) error {
	if err := w.Start(); err != nil {
		return err
	}
	w.finished = true
	return w.emit(delta{}, &reason)
}
