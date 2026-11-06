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
	"time"

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
	// OneThingPerChunk sends each field of a delta as a chunk of its own, and a finish_reason on a chunk with an empty
	// delta, for a host that packs them together.
	OneThingPerChunk bool
	// AnswersInReasoning marks a model that can send a whole answer as reasoning and stop with no content, as Ling 3.0
	// Flash does when it skips its thinking. That text reaches the client as content too: in a stream, before the stop.
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
	h := morseHead{id: chat.NewReplyID(), model: c.Model, object: "chat.completion.chunk", created: time.Now().Unix()}
	var usage chat.Usage
	// final is the last event that carried usage. Billing reads its usage, and so does the one usage chunk a client
	// that asked gets at the end of the stream, so the two never differ. Hosts send usage on the finish chunk, on a
	// choice-less chunk after it, on both with different counts, or on every chunk (Phala's continuous_usage_stats,
	// Fireworks for some models); only the last is what the reply cost.
	var final []byte
	var answered bool
	var thought strings.Builder
	opened := opening{}
	var spoken *reply
	send := func(data []byte, r reply) error {
		chunks := [][]byte{data}
		if !p.KeepEnvelope {
			if first := opened.firstOf(data); len(first) > 0 {
				if err := emit(chat.NewChunk(p.opener(h, first)).WithHost(r.host)); err != nil {
					return err
				}
			}
			if bare(data) {
				return nil
			}
			if pieces := apart(data); pieces != nil {
				chunks = pieces
			}
		}
		for _, piece := range chunks {
			parts := [][]byte{piece}
			if p.OneThingPerChunk {
				parts = splitChunk(piece)
			}
			for _, part := range parts {
				if err := emit(chat.NewChunk(part).WithHost(r.host)); err != nil {
					return err
				}
			}
		}
		return nil
	}
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
			final = slices.Clone(data)
		}
		if errEvent, ok := r.value("error"); ok && string(errEvent) != "null" {
			return false, chat.ErrorChunkOf(errEvent)
		}
		if r.usage != nil {
			if r.choices == 0 {
				return false, nil
			}
			r.drop("usage")
		}
		spoken = &r
		if p.AnswersInReasoning && !answered {
			d := chat.NewChunk(data).Delta()
			answered = d.Answers()
			thought.WriteString(d.Reasoning)
			if !answered && d.Finish == chat.FinishStop && strings.TrimSpace(thought.String()) != "" {
				answer, err := p.disguise(r.withContent(thought.String()), h)
				if err != nil {
					return false, err
				}
				if err := send(answer, r); err != nil {
					return false, err
				}
				answered = true
			}
		}
		data, err = p.disguise(r, h)
		if err != nil {
			return false, err
		}
		return false, send(data, r)
	})
	if err == nil && spoken != nil && len(opened) == 0 && !p.KeepEnvelope {
		err = emit(chat.NewChunk(p.opener(h, []int{0})).WithHost(spoken.host))
	}
	if err != nil || !c.IncludeUsage || final == nil {
		return usage, err
	}
	r, err := p.decodeReply(final)
	if err != nil {
		return usage, err
	}
	if r.choices > 0 {
		r.set("choices", json.RawMessage("[]"))
	}
	data, err := p.disguise(r, h)
	if err != nil {
		return usage, err
	}
	return usage, emit(chat.NewChunk(data).WithHost(r.host))
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
	body, err = p.disguise(r, morseHead{id: chat.NewReplyID(), model: c.Model, object: "chat.completion", created: time.Now().Unix()})
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

type morseHead struct {
	id, model, object string
	created           int64
}

type envelope struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Choices json.RawMessage `json:"choices"`
	Usage   json.RawMessage `json:"usage,omitempty"`
}

func (p *Provider) disguise(r reply, h morseHead) ([]byte, error) {
	if p.KeepEnvelope {
		return r.kept(), nil
	}
	choices, ok := r.value("choices")
	if !ok {
		return nil, errNotAnObject
	}
	choices, err := uniformChoices(choices, h.id)
	if err != nil {
		return nil, err
	}
	return jsonx.Encode(envelope{ID: h.id, Object: h.object, Created: h.created, Model: h.model, Choices: choices, Usage: r.uniformUsage()}), nil
}

// opening tracks which choices of a stream have had their opening delta sent.
type opening map[int]bool

// firstOf returns the choices of a disguised chunk that say something and have not been opened, and marks them opened.
func (o opening) firstOf(data []byte) []int {
	var c struct {
		Choices []struct {
			Index        *int                       `json:"index"`
			Delta        map[string]json.RawMessage `json:"delta"`
			FinishReason json.RawMessage            `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	var first []int
	for position, ch := range c.Choices {
		index := position
		if ch.Index != nil {
			index = *ch.Index
		}
		if !o[index] && (len(ch.Delta) > 0 || !isNull(ch.FinishReason)) {
			o[index] = true
			first = append(first, index)
		}
	}
	return first
}

// opener is the chunk that opens a reply for the given choices: role assistant and content "", the shape OpenAI sends.
func (p *Provider) opener(h morseHead, indexes []int) []byte {
	var choices bytes.Buffer
	choices.WriteByte('[')
	for i, index := range indexes {
		if i > 0 {
			choices.WriteByte(',')
		}
		fmt.Fprintf(&choices, `{"index":%d,"delta":{"role":"assistant","content":""},"finish_reason":null}`, index)
	}
	choices.WriteByte(']')
	return jsonx.Encode(envelope{ID: h.id, Object: h.object, Created: h.created, Model: h.model, Choices: choices.Bytes()})
}

// answerFields are what a client sees of a delta or a message, in order. Hosts add fields of their own (Fireworks's
// tools, Together's annotations, OpenRouter's reasoning_details) and send different nulls, which would tell a client
// which of a tier's hosts served.
var answerFields = []string{"role", "content", "reasoning", "reasoning_content", "refusal", "tool_calls"}

// uniformChoices gives every choice one shape whichever host sent it: index, its delta or message, finish_reason, and
// logprobs when there are any, which no request asks for. A choice's other fields (raw_output, matched_stop,
// stop_reason, token_ids, native_finish_reason, a per-choice usage) are the host's own.
func uniformChoices(raw json.RawMessage, replyID string) (json.RawMessage, error) {
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
			case name == "finish_reason" && !ok && c["delta"] != nil:
				v = json.RawMessage("null")
			case !ok || name == "logprobs" && isNull(v):
				continue
			case name == "delta" || name == "message":
				answer, err := uniformAnswer(v, name == "message", replyID, i)
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

// uniformAnswer drops the empty strings hosts disagree on. A delta keeps a text field only when it has text, and never
// carries role: the Stream opens each reply with one delta of role and content "", the shape OpenAI sends, whichever
// way the host opened or whether it repeated role on every chunk. A message with tool_calls and no text has content
// null. A host that sends its reasoning twice, as reasoning and reasoning_content, or with one of them empty, sends it
// once, as reasoning_content: the first of reasoning_content and reasoning that has text.
func uniformAnswer(raw json.RawMessage, message bool, replyID string, choice int) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return raw, nil
	}
	hasCalls := !isNull(fields["tool_calls"]) && string(fields["tool_calls"]) != "[]"
	thought := fields["reasoning_content"]
	if isNull(thought) || string(thought) == `""` {
		thought = fields["reasoning"]
	}
	var out bytes.Buffer
	w := objectWriter{out: &out}
	for _, name := range answerFields {
		switch v := fields[name]; {
		case name == "role" && !message:
		case !isNull(v) && name == "tool_calls":
			calls, err := uniformToolCalls(v, message, replyID, choice)
			if err != nil {
				return nil, err
			}
			if calls != nil {
				w.field(name, calls)
			}
		case name == "content" && message && (isNull(v) || hasCalls && string(v) == `""`):
			w.field(name, json.RawMessage("null"))
		case name == "reasoning":
		case name == "reasoning_content":
			if !isNull(thought) && string(thought) != `""` {
				w.field(name, thought)
			}
		case string(v) == `""` && emptyDropped[name]:
		case !isNull(v):
			w.field(name, v)
		}
	}
	w.close()
	return out.Bytes(), nil
}

var emptyDropped = map[string]bool{"content": true, "refusal": true}

// bare reports whether a disguised chunk says nothing a client reads: choices whose deltas are empty, with no finish
// reason, and no usage. A host's empty content delta is one, and Together sends none.
func bare(data []byte) bool {
	var c struct {
		Choices []struct {
			Delta        map[string]json.RawMessage `json:"delta"`
			FinishReason json.RawMessage            `json:"finish_reason"`
		} `json:"choices"`
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(data, &c) != nil || len(c.Choices) == 0 || !isNull(c.Usage) {
		return false
	}
	for _, ch := range c.Choices {
		if len(ch.Delta) > 0 || !isNull(ch.FinishReason) {
			return false
		}
	}
	return true
}

// apart splits a disguised chunk into the chunks Together would have sent for it: for each choice, one delta of its
// text, one delta per tool call, then its finish_reason with an empty delta. Morph sends the last text or every tool
// call whole on the chunk that carries finish_reason. It returns nil when the chunk is already in that shape.
func apart(data []byte) [][]byte {
	var e envelope
	var choices []struct {
		Index        json.RawMessage            `json:"index"`
		Delta        map[string]json.RawMessage `json:"delta"`
		FinishReason json.RawMessage            `json:"finish_reason"`
		Logprobs     json.RawMessage            `json:"logprobs"`
	}
	if json.Unmarshal(data, &e) != nil || json.Unmarshal(e.Choices, &choices) != nil {
		return nil
	}
	type piece struct{ index, delta, finish, logprobs json.RawMessage }
	var pieces []piece
	for _, c := range choices {
		var calls []json.RawMessage
		json.Unmarshal(c.Delta["tool_calls"], &calls)
		var text bytes.Buffer
		w := objectWriter{out: &text}
		for _, name := range answerFields {
			if v, ok := c.Delta[name]; ok && name != "tool_calls" {
				w.field(name, v)
			}
		}
		w.close()
		first := len(pieces)
		if text.String() != "{}" {
			pieces = append(pieces, piece{index: c.Index, delta: text.Bytes()})
		}
		for _, call := range calls {
			pieces = append(pieces, piece{index: c.Index, delta: jsonx.Encode(map[string][]json.RawMessage{"tool_calls": {call}})})
		}
		if !isNull(c.FinishReason) || len(pieces) == first {
			pieces = append(pieces, piece{index: c.Index, delta: json.RawMessage("{}"), finish: c.FinishReason})
		}
		if !isNull(c.Logprobs) {
			pieces[first].logprobs = c.Logprobs
		}
	}
	if len(pieces) <= len(choices) {
		return nil
	}
	chunks := make([][]byte, len(pieces))
	for i, p := range pieces {
		if p.finish == nil {
			p.finish = json.RawMessage("null")
		}
		var choice bytes.Buffer
		choice.WriteByte('[')
		w := objectWriter{out: &choice}
		if p.index != nil {
			w.field("index", p.index)
		}
		w.field("delta", p.delta)
		w.field("finish_reason", p.finish)
		if p.logprobs != nil {
			w.field("logprobs", p.logprobs)
		}
		w.close()
		choice.WriteByte(']')
		one := e
		one.Choices = choice.Bytes()
		if i < len(pieces)-1 {
			one.Usage = nil
		}
		chunks[i] = jsonx.Encode(one)
	}
	return chunks
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
