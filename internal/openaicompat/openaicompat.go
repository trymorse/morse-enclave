package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"morse/backend/internal/capped"
	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const (
	chatCompletionsPath = "/v1/chat/completions"
	maxEvent            = 1 << 20
	MaxCompletionBody   = 16 << 20
)

var anonymousFields = []string{"stream", "tools", "tool_choice", "parallel_tool_calls"}

var retentionSwitches = []string{"store"}

var forwardedMessageKeys = map[string][]string{
	"assistant": {"content", "tool_calls"},
	"tool":      {"content", "tool_call_id"},
}

func messageKeys(role string) []string {
	if keys, ok := forwardedMessageKeys[role]; ok {
		return keys
	}
	return []string{"content"}
}

type LimitField uint8

const (
	MaxCompletionTokens LimitField = iota
	MaxTokens
)

var limitFieldNames = [...]string{MaxCompletionTokens: "max_completion_tokens", MaxTokens: "max_tokens"}

var (
	errNotAnObject = errors.New("openaicompat: upstream sent a reply that is not a JSON object")
)

type Sender interface {
	Stream(ctx context.Context, body []byte, header http.Header, each func(data []byte) (done bool, err error)) error
	Complete(ctx context.Context, body []byte, header http.Header) ([]byte, error)
}

type Provider struct {
	Sender          Sender
	Model           string
	Force           map[string]json.RawMessage
	LimitField      LimitField
	KeepEnvelope    bool
	ContinuousUsage bool
	// UsageOnFinalChoice marks an upstream that sends a stream's usage on the chunk that finishes its choice.
	UsageOnFinalChoice bool
	// AnswersInReasoning marks an upstream that can send a whole answer as reasoning and stop with no content, as
	// OpenRouter does when a model skips its thinking. That text reaches the client as content too: in a stream,
	// before the stop.
	AnswersInReasoning bool
	NamesHost          bool
	// Admit refuses a call before it is sent, or is nil to send every call.
	Admit func(chat.Call) error
	// Headers adds headers to the request that carries a call, or is nil to add none.
	Headers func(chat.Call) http.Header
	// ChargeFields are the usage fields that carry what the vendor charged the proxy, which the client is not shown.
	ChargeFields []string
	VendorCost   func(usage json.RawMessage) chat.VendorCost
	Bill         func(usage json.RawMessage) (json.RawMessage, error)
}

var _ chat.Provider = (*Provider)(nil)

func (p *Provider) Stream(ctx context.Context, c chat.Call, emit func(chat.Chunk) error) (chat.Usage, error) {
	if err := p.admit(c); err != nil {
		return chat.Usage{}, err
	}
	body, err := p.encode(c, true)
	if err != nil {
		return chat.Usage{}, err
	}
	id := chat.NewReplyID()
	var usage chat.Usage
	var answered bool
	var thought strings.Builder
	err = p.Sender.Stream(ctx, body, p.headers(c), func(data []byte) (bool, error) {
		if isDone(data) {
			return true, nil
		}
		r, err := p.decodeReply(data)
		if err != nil {
			return false, err
		}
		if r.usage != nil {
			usage = r.domainUsage()
		}
		if errEvent, ok := r.value("error"); ok && string(errEvent) != "null" {
			return false, chat.ErrorChunkOf(errEvent)
		}
		if r.choices == 0 && r.usage != nil && !c.IncludeUsage {
			return false, nil
		}
		if p.AnswersInReasoning && !answered {
			d := chat.NewChunk(data).Delta()
			answered = d.Answers()
			thought.WriteString(d.Reasoning)
			if !answered && d.Finish == chat.FinishStop && strings.TrimSpace(thought.String()) != "" {
				answer, err := p.disguise(r.withContent(thought.String()), id, c.Model)
				if err != nil {
					return false, err
				}
				if err := emit(chat.NewChunk(answer).WithHost(r.host)); err != nil {
					return false, err
				}
				answered = true
			}
		}
		// A usage object on a chunk that carries choices is not OpenAI's shape: OpenAI sends usage only on
		// the final, choice-less chunk, and only to a client that asked. Phala sends it on every chunk with
		// continuous_usage_stats, so the proxy reads it and keeps it from the client. OpenRouter sends it
		// once, on the chunk that finishes the choice, so a client that asked gets it after that chunk.
		var trailing json.RawMessage
		if r.choices > 0 && r.usage != nil {
			if p.UsageOnFinalChoice && c.IncludeUsage {
				trailing, _ = r.value("usage")
			}
			r.drop("usage")
		}
		data, err = p.disguise(r, id, c.Model)
		if err != nil {
			return false, err
		}
		if err := emit(chat.NewChunk(data).WithHost(r.host)); err != nil || trailing == nil {
			return false, err
		}
		r.set("choices", json.RawMessage("[]"))
		r.set("usage", trailing)
		data, err = p.disguise(r, id, c.Model)
		if err != nil {
			return false, err
		}
		return false, emit(chat.NewChunk(data).WithHost(r.host))
	})
	return usage, err
}

func (p *Provider) Complete(ctx context.Context, c chat.Call) (chat.Chunk, chat.Usage, error) {
	if err := p.admit(c); err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	reqBody, err := p.encode(c, false)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	body, err := p.Sender.Complete(ctx, reqBody, p.headers(c))
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	r, err := p.decodeReply(body)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	if d := chat.NewChunk(body).Delta(); p.AnswersInReasoning && !d.Answers() && d.Finish == chat.FinishStop && strings.TrimSpace(d.Reasoning) != "" {
		if err := r.answer(d.Reasoning); err != nil {
			return chat.Chunk{}, chat.Usage{}, err
		}
	}
	var usage chat.Usage
	if r.usage != nil {
		usage = r.domainUsage()
	}
	body, err = p.disguise(r, chat.NewReplyID(), c.Model)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	return chat.NewChunk(body).WithHost(r.host), usage, nil
}

func (p *Provider) admit(c chat.Call) error {
	if p.Admit == nil {
		return nil
	}
	return p.Admit(c)
}

type envelope struct {
	ID      string          `json:"id"`
	Object  json.RawMessage `json:"object,omitempty"`
	Created json.RawMessage `json:"created,omitempty"`
	Model   string          `json:"model"`
	Choices json.RawMessage `json:"choices"`
	Usage   json.RawMessage `json:"usage,omitempty"`
}

func (p *Provider) disguise(r reply, id, model string) ([]byte, error) {
	if p.KeepEnvelope {
		return r.kept(), nil
	}
	choices, ok := r.value("choices")
	if !ok {
		return nil, errNotAnObject
	}
	choices, err := uniformChoices(choices)
	if err != nil {
		return nil, err
	}
	object, _ := r.value("object")
	created, _ := r.value("created")
	usage, _ := r.value("usage")
	return jsonx.Encode(envelope{ID: id, Object: object, Created: created, Model: model, Choices: choices, Usage: usage}), nil
}

// answerFields are what a client sees of a delta or a message, in order. Hosts add fields of their own (Fireworks's
// tools, Together's annotations, OpenRouter's reasoning_details) and send different nulls, which would tell a client
// which of a tier's hosts served.
var answerFields = []string{"role", "content", "reasoning", "reasoning_content", "refusal", "tool_calls", "function_call", "audio"}

// uniformChoices gives every choice one shape whichever host sent it: index, its delta or message, finish_reason, and
// logprobs when there are any, which no request asks for. A choice's other fields (raw_output, matched_stop,
// stop_reason, token_ids, native_finish_reason, a per-choice usage) are the host's own.
func uniformChoices(raw json.RawMessage) (json.RawMessage, error) {
	if string(raw) == "null" {
		return raw, nil
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choices); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('[')
	for i, c := range choices {
		if i > 0 {
			out.WriteByte(',')
		}
		w := objectWriter{out: &out}
		for _, name := range [...]string{"index", "delta", "message", "finish_reason", "logprobs"} {
			v, ok := c[name]
			switch {
			case !ok || name == "logprobs" && isNull(v):
				continue
			case name == "delta" || name == "message":
				answer, err := uniformAnswer(v, name == "message")
				if err != nil {
					return nil, err
				}
				v = answer
			}
			w.field(name, v)
		}
		w.close()
	}
	out.WriteByte(']')
	return out.Bytes(), nil
}

func uniformAnswer(raw json.RawMessage, message bool) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return raw, nil
	}
	var out bytes.Buffer
	w := objectWriter{out: &out}
	for _, name := range answerFields {
		switch v := fields[name]; {
		case !isNull(v):
			w.field(name, v)
		case message && name == "content":
			w.field(name, json.RawMessage("null"))
		}
	}
	w.close()
	return out.Bytes(), nil
}

func isNull(v json.RawMessage) bool { return v == nil || string(v) == "null" }

type objectWriter struct {
	out  *bytes.Buffer
	more bool
}

func (w *objectWriter) field(name string, value json.RawMessage) {
	if w.more {
		w.out.WriteByte(',')
	} else {
		w.out.WriteByte('{')
	}
	w.more = true
	w.out.WriteString(strconv.Quote(name))
	w.out.WriteByte(':')
	w.out.Write(value)
}

func (w *objectWriter) close() {
	if !w.more {
		w.out.WriteByte('{')
	}
	w.out.WriteByte('}')
}

func pinned(model string, force map[string]json.RawMessage) map[string]json.RawMessage {
	set := maps.Clone(force)
	if set == nil {
		set = map[string]json.RawMessage{}
	}
	set["model"], _ = json.Marshal(model)
	return set
}

func (p *Provider) encode(c chat.Call, stream bool) ([]byte, error) {
	set := pinned(p.Model, p.Force)
	set[limitFieldNames[p.LimitField]] = json.RawMessage(strconv.Itoa(c.OutputLimit))
	if effort, ok := c.ForwardedEffort(); ok {
		set["reasoning_effort"], _ = json.Marshal(effort)
	}
	if stream {
		set["stream"] = json.RawMessage("true")
		set["stream_options"] = json.RawMessage(`{"include_usage":true}`)
		if p.ContinuousUsage {
			set["stream_options"] = json.RawMessage(`{"include_usage":true,"continuous_usage_stats":true}`)
		}
	}
	if _, ok := c.Field("messages"); ok {
		msgs, err := c.Messages()
		if err != nil {
			return nil, err
		}
		set["messages"] = chat.EncodeMessages(msgs, messageKeys)
	}
	for _, name := range retentionSwitches {
		if _, forced := set[name]; forced || slices.Contains(anonymousFields, name) {
			return nil, fmt.Errorf("openaicompat: the request to %s would carry %s, which asks a vendor to keep the conversation", p.Model, name)
		}
	}
	return c.EncodeOnly(anonymousFields, set), nil
}

func (p *Provider) headers(c chat.Call) http.Header {
	if p.Headers == nil {
		return nil
	}
	return p.Headers(c)
}

type HTTPSender struct{ upstream.Endpoint }

var _ Sender = HTTPSender{}

func (s HTTPSender) Stream(ctx context.Context, body []byte, header http.Header, each func(data []byte) (bool, error)) error {
	resp, err := s.Open(ctx, upstream.Request{Method: http.MethodPost, Path: chatCompletionsPath, Header: accepting(header, "text/event-stream"), Body: body})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return sse.Each(resp.Body, maxEvent, sse.Refuse, each)
}

func (s HTTPSender) Complete(ctx context.Context, body []byte, header http.Header) ([]byte, error) {
	resp, err := s.Open(ctx, upstream.Request{Method: http.MethodPost, Path: chatCompletionsPath, Header: accepting(header, "application/json"), Body: body})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return capped.ReadAll(resp.Body, MaxCompletionBody)
}

func accepting(header http.Header, accept string) http.Header {
	h := header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Accept", accept)
	return h
}

func isDone(data []byte) bool { return string(data) == "[DONE]" }
