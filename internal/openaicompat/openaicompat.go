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
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const (
	ChatCompletionsPath = "/v1/chat/completions"
	maxEvent            = 1 << 20
	MaxCompletionBody   = 16 << 20
)

var anonymousFields = []string{"stream", "tools", "tool_choice", "parallel_tool_calls"}

var toolFields = []string{"tools", "tool_choice", "parallel_tool_calls"}

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
	Fixes           catalog.Fixes
	ThinkingField   string
	Admit           func(chat.Call) error
	Headers         func(chat.Call) http.Header
	ChargeFields    []string
	Bill            func(usage json.RawMessage) (json.RawMessage, error)
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
	s := &stream{p: p, emit: emit, opened: opening{}, calls: openedCalls{}, fixes: p.replyFixes(c),
		head: morseHead{id: chat.NewReplyID(), model: c.Model, object: "chat.completion.chunk", created: time.Now().Unix()}}
	if err := p.Sender.Stream(ctx, body, p.headers(c), s.event); err != nil {
		return s.usage, err
	}
	if err := s.sendHeldThinking(); err != nil {
		return s.usage, err
	}
	if err := s.openSilentReply(); err != nil {
		return s.usage, err
	}
	return s.usage, s.sendUsage(c.IncludeUsage)
}

type stream struct {
	p      *Provider
	head   morseHead
	emit   func(chat.Chunk) error
	usage  chat.Usage
	final  []byte
	spoke  bool
	opened opening
	calls  openedCalls
	fixes  replyFixes
}

func (s *stream) event(data []byte) (bool, error) {
	if isDone(data) {
		return true, nil
	}
	r, err := s.p.decodeReply(data)
	if err != nil {
		return false, err
	}
	if r.usage != nil {
		s.usage, s.final = r.usage.Domain(), slices.Clone(data)
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
	s.spoke = true
	text, ok, err := s.fixes.edit(&r, deltaPart)
	if err != nil {
		return false, err
	}
	if ok {
		if err := s.send(r.withContent(text)); err != nil {
			return false, err
		}
	}
	return false, s.send(r)
}

func (s *stream) send(r reply) error {
	data, err := s.p.disguise(r, s.head, s.calls, &s.fixes)
	if err != nil {
		return err
	}
	if s.p.KeepEnvelope {
		return s.emit(chat.NewChunk(data))
	}
	if first := s.opened.firstOf(data); len(first) > 0 {
		if err := s.emit(chat.NewChunk(s.head.opener(first))); err != nil {
			return err
		}
	}
	for _, chunk := range canonical(data) {
		if err := s.emit(chat.NewChunk(chunk)); err != nil {
			return err
		}
	}
	return nil
}

func (s *stream) sendHeldThinking() error {
	if s.fixes.think == nil {
		return nil
	}
	if r, ok := s.fixes.think.flushed(); ok {
		return s.send(r)
	}
	return nil
}

func (s *stream) openSilentReply() error {
	if s.spoke && len(s.opened) == 0 && !s.p.KeepEnvelope {
		return s.emit(chat.NewChunk(s.head.opener([]int{0})))
	}
	return nil
}

func (s *stream) sendUsage(includeUsage bool) error {
	if !includeUsage || s.final == nil {
		return nil
	}
	r, err := s.p.decodeReply(s.final)
	if err != nil {
		return err
	}
	if r.choices > 0 {
		r.set("choices", json.RawMessage("[]"))
	}
	data, err := s.p.disguise(r, s.head, s.calls, &s.fixes)
	if err != nil {
		return err
	}
	return s.emit(chat.NewChunk(data))
}

type replyFixes struct {
	think               *thinkSplit
	answer              reasoningAnswer
	toolCallsFinishStop bool
}

func (p *Provider) replyFixes(c chat.Call) replyFixes {
	f := replyFixes{answer: reasoningAnswer{on: p.Fixes.AnswersInReasoning}, toolCallsFinishStop: p.Fixes.ToolCallsFinishStop}
	if p.Fixes.ReasoningInContent && !p.turnsThinkingOff(c) {
		f.think = &thinkSplit{}
	}
	return f
}

func (f *replyFixes) edit(r *reply, part answerPart) (string, bool, error) {
	if f.think != nil {
		if err := f.think.splitThinking(r, part); err != nil {
			return "", false, err
		}
	}
	text, ok := f.answer.answerFromReasoning(chat.NewChunk(r.kept()).Delta())
	return text, ok, nil
}

type reasoningAnswer struct {
	on, settled bool
	thought     strings.Builder
}

func (a *reasoningAnswer) answerFromReasoning(d chat.Delta) (string, bool) {
	if !a.on || a.settled {
		return "", false
	}
	a.settled = d.Answers()
	a.thought.WriteString(d.Reasoning)
	if a.settled || d.Finish != chat.FinishStop || strings.TrimSpace(a.thought.String()) == "" {
		return "", false
	}
	a.settled = true
	return a.thought.String(), true
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
	fixes := p.replyFixes(c)
	text, ok, err := fixes.edit(&r, messagePart)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	if ok {
		if err := r.answer(text); err != nil {
			return chat.Chunk{}, chat.Usage{}, err
		}
	}
	var usage chat.Usage
	if r.usage != nil {
		usage = r.usage.Domain()
	}
	body, err = p.disguise(r, morseHead{id: chat.NewReplyID(), model: c.Model, object: "chat.completion", created: time.Now().Unix()}, nil, &fixes)
	if err != nil {
		return chat.Chunk{}, chat.Usage{}, err
	}
	return chat.NewChunk(body), usage, nil
}

func (p *Provider) admit(c chat.Call) error {
	if err := NamedFunctions(c); err != nil || p.Admit == nil {
		return err
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

func (p *Provider) disguise(r reply, h morseHead, calls openedCalls, fixes *replyFixes) ([]byte, error) {
	if p.KeepEnvelope {
		return r.kept(), nil
	}
	choices, ok := r.value("choices")
	if !ok {
		return nil, errNotAnObject
	}
	choices, err := uniformChoices(choices, h.id, calls, fixes)
	if err != nil {
		return nil, err
	}
	return jsonx.Encode(envelope{ID: h.id, Object: h.object, Created: h.created, Model: h.model, Choices: choices, Usage: r.uniformUsage()}), nil
}

type opening map[int]bool

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

func (h morseHead) opener(indexes []int) []byte {
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

var answerFields = []string{"role", "content", "reasoning", "reasoning_content", "refusal", "tool_calls"}

func uniformChoices(raw json.RawMessage, replyID string, calls openedCalls, fixes *replyFixes) (json.RawMessage, error) {
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
			case name == "finish_reason" && fixes.toolCallsFinishStop && string(v) == `"stop"` && calledTool(c, i, calls):
				v = json.RawMessage(`"tool_calls"`)
			case name == "delta" || name == "message":
				answer, err := uniformAnswer(v, name == "message", replyID, i, calls)
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

func uniformAnswer(raw json.RawMessage, message bool, replyID string, choice int, opened openedCalls) (json.RawMessage, error) {
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
			calls, err := uniformToolCalls(v, message, replyID, choice, opened)
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

func calledTool(c map[string]json.RawMessage, i int, calls openedCalls) bool {
	for key := range calls {
		if key[0] == i {
			return true
		}
	}
	var message struct {
		ToolCalls []json.RawMessage `json:"tool_calls"`
	}
	return json.Unmarshal(c["message"], &message) == nil && len(message.ToolCalls) > 0
}

var emptyDropped = map[string]bool{"content": true, "refusal": true}

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
	if p.turnsThinkingOff(c) {
		set[p.ThinkingField] = json.RawMessage("false")
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
	keep := slices.Concat(anonymousFields, c.Settings)
	if p.Fixes.NoTools {
		keep = slices.DeleteFunc(keep, func(name string) bool { return slices.Contains(toolFields, name) })
	}
	return c.EncodeOnly(keep, set), nil
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
	resp, err := s.Open(ctx, upstream.Request{Method: http.MethodPost, Path: ChatCompletionsPath, Header: accepting(header, "text/event-stream"), Body: body})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return sse.Each(resp.Body, maxEvent, sse.Refuse, each)
}

func (s HTTPSender) Complete(ctx context.Context, body []byte, header http.Header) ([]byte, error) {
	resp, err := s.Open(ctx, upstream.Request{Method: http.MethodPost, Path: ChatCompletionsPath, Header: accepting(header, "application/json"), Body: body})
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
