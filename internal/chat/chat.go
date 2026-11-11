package chat

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"

	"morse/backend/internal/apierr"
	"morse/backend/internal/dataurl"
	"morse/backend/internal/enum"
	"morse/backend/internal/strictjson"
)

type Request struct {
	Model        string
	Stream       bool
	IncludeUsage bool

	raw          []byte
	fields       map[string]json.RawMessage
	outputLimits []int
	effort       *string
	messages     func() ([]Message, error)
}

type Call struct {
	*Request
	OutputLimit int
	RouteEffort string
	// Efforts are the efforts the route's model accepts, which every plaintext provider forwards Effort through.
	Efforts []string
	// Settings are the request fields an API key lets reach the host beside the ones every chat sends, such as
	// temperature; nil sends none.
	Settings []string
}

var (
	errMissingModel       = errors.New("chat: request has no model")
	ErrInvalidOutputLimit = errors.New("chat: max_tokens and max_completion_tokens must be positive JSON integers")
	errInvalidEffort      = strictjson.Invalid("reasoning_effort must be one of none, minimal, low, medium, high, xhigh, and max.")
	errLegacyFunctions    = strictjson.Invalid("functions and function_call are not supported. Send tools and tool_choice.")
)

var legacyToolFields = []string{"functions", "function_call"}

func ParseRequest(body io.Reader) (*Request, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if err := checkShape(raw); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	req := &Request{raw: raw, fields: fields}
	req.messages = sync.OnceValues(req.parseMessages)
	if err := unmarshalField(fields, "model", &req.Model); err != nil {
		return nil, err
	}
	if req.Model == "" {
		return nil, errMissingModel
	}
	if err := unmarshalField(fields, "stream", &req.Stream); err != nil {
		return nil, err
	}
	var opts struct {
		IncludeUsage bool `json:"include_usage"`
	}
	if err := unmarshalField(fields, "stream_options", &opts); err != nil {
		return nil, err
	}
	req.IncludeUsage = opts.IncludeUsage
	if req.outputLimits, err = parseOutputLimits(fields); err != nil {
		return nil, err
	}
	if unmarshalField(fields, "reasoning_effort", &req.effort) != nil || req.effort != nil && !slices.Contains(EffortLadder, *req.effort) {
		return nil, errInvalidEffort
	}
	for _, name := range legacyToolFields {
		if _, ok := fields[name]; ok {
			return nil, errLegacyFunctions
		}
	}
	return req, nil
}

var completionLimitFields = []string{"max_completion_tokens", "max_tokens"}

func parseOutputLimits(fields map[string]json.RawMessage) ([]int, error) {
	var limits []int
	for _, name := range completionLimitFields {
		raw, ok := fields[name]
		if !ok || string(raw) == "null" {
			continue
		}
		var n int
		if json.Unmarshal(raw, &n) != nil || n <= 0 {
			return nil, ErrInvalidOutputLimit
		}
		limits = append(limits, n)
	}
	return limits, nil
}

func unmarshalField(fields map[string]json.RawMessage, name string, into any) error {
	raw, ok := fields[name]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, into)
}

// ErrSealedBody answers every read of a request whose body is sealed whole.
var ErrSealedBody = errors.New("chat: the body is sealed whole, so the proxy can't read its messages")

// SealedBodyRequest is a request whose body is sealed whole (BodySealed): the clear headers name its model and
// output limit, and it streams, with usage the upstream counts outside the seal.
func SealedBodyRequest(raw []byte, model string, limit int) *Request {
	return &Request{Model: model, Stream: true, IncludeUsage: true, raw: raw, outputLimits: []int{limit}, messages: func() ([]Message, error) { return nil, ErrSealedBody }}
}

func (r *Request) Size() int { return len(r.raw) }

func (r *Request) ModelName() string { return r.Model }

func (r *Request) OutputLimits() []int { return r.outputLimits }

var ReasoningEfforts = []string{"minimal", "low", "medium", "high", "xhigh", "max"}

const NoEffort = "none"

var EffortLadder = append([]string{NoEffort}, ReasoningEfforts...)

// ForwardedEffort sends a requested effort as the lowest accepted effort at or above it, and one above every
// accepted effort as the highest accepted, so a model that tops out below max still reasons its hardest.
func ForwardedEffort(requested string, accepted []string) (string, bool) {
	at := slices.Index(EffortLadder, requested)
	if at < 0 {
		return "", false
	}
	for _, effort := range EffortLadder[at:] {
		if slices.Contains(accepted, effort) {
			return effort, true
		}
	}
	for _, effort := range slices.Backward(EffortLadder[:at]) {
		if slices.Contains(accepted, effort) {
			return effort, true
		}
	}
	return "", false
}

func (c Call) Effort() string {
	if c.effort != nil {
		return *c.effort
	}
	return c.RouteEffort
}

// ForwardedEffort is the effort the vendor is sent, or false when the call asks for none or the model takes none.
func (c Call) ForwardedEffort() (string, bool) { return ForwardedEffort(c.Effort(), c.Efforts) }

func (c Call) ReasoningRequested() bool { return slices.Contains(ReasoningEfforts, c.Effort()) }

// Reasoning is when a route's model reasons.
type Reasoning uint8

const (
	ReasonsWhenAsked  Reasoning = iota // at an effort the client names or the route defaults to
	ReasonsUnlessNone                  // at the vendor's default effort too, and only an effort of none stops it
	ReasonsAlways                      // whatever the request says
)

// Reasoned says whether a model that reasons at r reasoned on c.
func (c Call) Reasoned(r Reasoning) bool {
	switch r {
	case ReasonsAlways:
		return true
	case ReasonsUnlessNone:
		return c.Effort() != NoEffort
	}
	return c.ReasoningRequested()
}

func (r *Request) FieldNames() []string { return slices.Sorted(maps.Keys(r.fields)) }

func (r *Request) Verbatim() []byte { return r.raw }

func (r *Request) Field(name string) (json.RawMessage, bool) {
	raw, ok := r.fields[name]
	return raw, ok
}

func (r *Request) Decode(name string, into any) error { return unmarshalField(r.fields, name, into) }

// Stops is whether the request sets a stop string.
func (r *Request) Stops() bool {
	var stop any
	if r.Decode("stop", &stop) != nil {
		return false
	}
	switch s := stop.(type) {
	case string:
		return s != ""
	case []any:
		return len(s) > 0
	}
	return false
}

func (r *Request) EncodeOnly(keep []string, set map[string]json.RawMessage) []byte {
	fields := map[string]json.RawMessage{}
	for _, name := range keep {
		if value, ok := r.fields[name]; ok {
			fields[name] = value
		}
	}
	maps.Copy(fields, set)
	return encodeObject(fields)
}

func encodeObject(fields map[string]json.RawMessage) []byte {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, name := range slices.Sorted(maps.Keys(fields)) {
		if i > 0 {
			out.WriteByte(',')
		}
		key, _ := json.Marshal(name)
		out.Write(key)
		out.WriteByte(':')
		out.Write(fields[name])
	}
	out.WriteByte('}')
	return out.Bytes()
}

func EncodeMessages(msgs []Message, keep func(role string) []string) json.RawMessage {
	var out bytes.Buffer
	out.WriteByte('[')
	for i, m := range msgs {
		if i > 0 {
			out.WriteByte(',')
		}
		fields := map[string]json.RawMessage{}
		for _, key := range keep(m.Role) {
			if value, ok := m.raw[key]; ok {
				fields[key] = value
			}
		}
		fields["role"], _ = json.Marshal(m.Role)
		out.Write(encodeObject(fields))
	}
	out.WriteByte(']')
	return out.Bytes()
}

type Message struct {
	Role  string
	raw   map[string]json.RawMessage
	parts []Part
}

type Part struct {
	Type   string
	Text   *string
	fields map[string]json.RawMessage
}

func (p Part) ImageURL() json.RawMessage { return p.fields["image_url"] }

func (m Message) Parts() []Part { return m.parts }

func (m Message) Text() (string, bool) {
	var joined strings.Builder
	for _, p := range m.parts {
		if p.Type != "text" || p.Text == nil {
			return "", false
		}
		joined.WriteString(*p.Text)
	}
	return joined.String(), true
}

func (m Message) TextBytes() int {
	n := 0
	for _, p := range m.parts {
		if p.Text != nil {
			n += len(*p.Text)
		}
	}
	return n
}

func (m Message) Keys() []string { return slices.Sorted(maps.Keys(m.raw)) }

func (m Message) Raw(key string) json.RawMessage { return m.raw[key] }

var (
	errMalformedMessages = fmt.Errorf("%w: messages must be an array of objects with a string role", apierr.ErrMalformedRequest)
	ErrMessageRole       = fmt.Errorf("%w: every message needs a non-empty string role", apierr.ErrMalformedRequest)
)

var (
	mediaURLKeys   = []string{"image_url", "video_url", "audio_url", "file_url"}
	inlineFileKeys = []string{"file_data", "filename"}
	attachmentKeys = append(slices.Clone(mediaURLKeys), "file", "input_audio")
)

func (r *Request) Messages() ([]Message, error) { return r.messages() }

// PromptTexts is the prompt as countable text, or false when a message is not plain text
// or tools are in play, which the tokenizer cannot count the way the upstream does.
func (r *Request) PromptTexts() ([]string, bool) {
	if _, hasTools := r.fields["tools"]; hasTools {
		return nil, false
	}
	msgs, err := r.Messages()
	if err != nil {
		return nil, false
	}
	var texts []string
	for _, m := range msgs {
		if m.ToolCalls() != nil {
			return nil, false
		}
		text, ok := m.Text()
		if !ok {
			return nil, false
		}
		if text != "" {
			texts = append(texts, text)
		}
	}
	return texts, true
}

// PromptTextBytes is the size of the text the model reads: every text part of every message, the assistant's
// tool calls and the tool definitions. An image, file, audio or video part counts nothing, whatever it carries
// inline, and neither does the JSON around the text.
func (r *Request) PromptTextBytes() (int, error) {
	msgs, err := r.Messages()
	if err != nil {
		return 0, err
	}
	n := len(r.fields["tools"])
	for _, m := range msgs {
		n += len(m.ToolCalls()) + m.TextBytes()
	}
	return n, nil
}

func (r *Request) Attachments() (n, bytes int, err error) {
	msgs, err := r.Messages()
	if err != nil {
		return 0, 0, err
	}
	for _, m := range msgs {
		for _, p := range m.parts {
			parts, size := p.attachment()
			n, bytes = n+parts, bytes+size
		}
	}
	return n, bytes, nil
}

func (p Part) attachment() (n, bytes int) {
	for _, key := range attachmentKeys {
		if ref, ok := p.fields[key]; ok {
			return 1, len(ref)
		}
	}
	return 0, 0
}

func (r *Request) parseMessages() ([]Message, error) {
	var raw []map[string]json.RawMessage
	if err := unmarshalField(r.fields, "messages", &raw); err != nil {
		return nil, errMalformedMessages
	}
	msgs := make([]Message, 0, len(raw))
	for _, m := range raw {
		var role string
		if err := json.Unmarshal(m["role"], &role); err != nil || role == "" {
			return nil, ErrMessageRole
		}
		parts, err := parseParts(m["content"])
		if err != nil {
			return nil, err
		}
		msg := Message{Role: role, raw: m, parts: parts}
		for _, part := range msg.parts {
			if err := part.checkInlineMedia(); err != nil {
				return nil, err
			}
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func parseParts(content json.RawMessage) ([]Part, error) {
	if len(content) == 0 {
		return nil, nil
	}
	var text string
	if json.Unmarshal(content, &text) == nil {
		return []Part{{Type: "text", Text: &text}}, nil
	}
	var elements []json.RawMessage
	if json.Unmarshal(content, &elements) != nil {
		return nil, errMalformedMessages
	}
	parts := make([]Part, 0, len(elements))
	for _, raw := range elements {
		part, err := parsePart(raw)
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	return parts, nil
}

func parsePart(raw json.RawMessage) (Part, error) {
	var text *string
	if json.Unmarshal(raw, &text) == nil && text != nil {
		return Part{Text: text}, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return Part{}, errMalformedMessages
	}
	part := Part{fields: fields}
	json.Unmarshal(fields["type"], &part.Type)
	json.Unmarshal(fields["text"], &part.Text)
	return part, nil
}

func (p Part) checkInlineMedia() error {
	for _, key := range mediaURLKeys {
		if ref, ok := p.fields[key]; ok {
			if _, err := dataurl.Parse(PartURL(ref)); errors.Is(err, apierr.ErrRemoteMedia) {
				return apierr.ErrRemoteMedia
			}
		}
	}
	if file, ok := p.fields["file"]; ok && !isInlineFile(file) {
		return apierr.ErrRemoteMedia
	}
	return nil
}

func PartURL(ref json.RawMessage) string {
	var url string
	if json.Unmarshal(ref, &url) == nil {
		return url
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(ref, &fields)
	json.Unmarshal(fields["url"], &url)
	return url
}

func isInlineFile(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for key := range fields {
		if !slices.Contains(inlineFileKeys, key) {
			return false
		}
	}
	if data, ok := fields["file_data"]; ok {
		var url string
		if json.Unmarshal(data, &url) != nil {
			return false
		}
		if _, err := dataurl.Parse(url); errors.Is(err, apierr.ErrRemoteMedia) {
			return false
		}
	}
	return true
}

func (m Message) ToolCalls() json.RawMessage {
	if m.Role != "assistant" {
		return nil
	}
	return m.raw["tool_calls"]
}

func (m Message) ToolCallID() json.RawMessage {
	if m.Role != "tool" {
		return nil
	}
	return m.raw["tool_call_id"]
}

func (m Message) String() string   { return fmt.Sprintf("chat.Message{role=%q}", m.Role) }
func (m Message) GoString() string { return m.String() }

func (r Request) String() string {
	return fmt.Sprintf("chat.Request{model=%q stream=%t include_usage=%t}", r.Model, r.Stream, r.IncludeUsage)
}

func (r Request) GoString() string { return r.String() }

func NewReplyID() string { return "chatcmpl-" + rand.Text() }

type Chunk struct {
	object []byte
}

func NewChunk(object []byte) Chunk { return Chunk{object: bytes.Clone(object)} }

func (c Chunk) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(c.object)
	return int64(n), err
}

func (c Chunk) MarkUnanswered() Chunk {
	dec := json.NewDecoder(bytes.NewReader(c.object))
	if open, err := dec.Token(); err != nil || open != json.Delim('{') {
		return c
	}
	for dec.More() {
		key, _ := dec.Token()
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return c
		}
		if key != "usage" || len(value) < 2 || value[0] != '{' {
			continue
		}
		end := int(dec.InputOffset()) - 1
		marker := `,"unanswered":true`
		if string(bytes.TrimSpace(value[1:len(value)-1])) == "" {
			marker = marker[1:]
		}
		c.object = slices.Concat(c.object[:end], []byte(marker), c.object[end:])
		return c
	}
	return c
}

// Ending is the chunk that ends choice 0 of c's reply with finish and says nothing more: c's id, object, created and
// model, as the stream's other chunks carry them, and no usage.
func (c Chunk) Ending(finish Finish) Chunk {
	var head struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
	}
	json.Unmarshal(c.object, &head)
	reason, _ := json.Marshal(finish.String())
	ending, _ := json.Marshal(struct {
		ID      string          `json:"id"`
		Object  string          `json:"object"`
		Created int64           `json:"created"`
		Model   string          `json:"model"`
		Choices json.RawMessage `json:"choices"`
	}{head.ID, head.Object, head.Created, head.Model, json.RawMessage(`[{"index":0,"delta":{},"finish_reason":` + string(reason) + `}]`)})
	return Chunk{object: ending}
}

type Finish uint8

const (
	FinishNone Finish = iota
	FinishStop
	FinishLength
	FinishToolCalls
	FinishContentFilter
)

var finishNames = enum.Names[Finish]{FinishNone: "none", FinishStop: "stop", FinishLength: "length", FinishToolCalls: "tool_calls", FinishContentFilter: "content_filter"}

func Finishes() []Finish { return finishNames.Values() }

func ParseFinish(name string) (Finish, bool) { return finishNames.Parse(name) }

func (f Finish) String() string { return finishNames.String(f) }

func (f Finish) MarshalText() ([]byte, error) { return finishNames.MarshalText(f) }

func (f *Finish) UnmarshalText(text []byte) error { return finishNames.UnmarshalText(f, text) }

type Delta struct {
	Content, Reasoning, ToolArguments string
	Refused, ToolCalled               bool
	Finish                            Finish
	Unreadable                        bool
}

func (d Delta) Answers() bool { return strings.TrimSpace(d.Content) != "" || d.Refused || d.ToolCalled }

func (d Delta) Reasons() bool { return d.Reasoning != "" }

func (d Delta) Shown() bool { return d.Answers() || d.Reasons() }

// Delivered does not trim the content: whitespace alone is not an answer, but the client still received it.
func (d Delta) Delivered() bool { return d.Content != "" || d.Refused || d.ToolCalled || d.Reasons() }

func (d Delta) VisibleBytes() int { return len(d.Content) + len(d.Reasoning) + len(d.ToolArguments) }

func (c Chunk) Delta() Delta { return deltaOf(c.object) }

type deltaView struct {
	Content          *string         `json:"content"`
	Refusal          json.RawMessage `json:"refusal"`
	ReasoningContent *string         `json:"reasoning_content"`
	Reasoning        *string         `json:"reasoning"`
	ToolCalls        []struct {
		Function struct {
			Arguments *string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

var noValue = []string{"", "null", `""`, "[]"}

func deltaOf(object []byte) Delta {
	var view struct {
		Choices []struct {
			Delta   *deltaView `json:"delta"`
			Message *deltaView `json:"message"`
			Finish  string     `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(object, &view) != nil {
		return Delta{Unreadable: true}
	}
	var d Delta
	text := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	for _, choice := range view.Choices {
		if finish, ok := finishNames.Parse(choice.Finish); ok {
			d.Finish = finish
		}
		for _, v := range []*deltaView{choice.Delta, choice.Message} {
			if v == nil {
				continue
			}
			d.Content += text(v.Content)
			d.Reasoning += cmp.Or(text(v.ReasoningContent), text(v.Reasoning))
			d.Refused = d.Refused || !slices.Contains(noValue, string(v.Refusal))
			d.ToolCalled = d.ToolCalled || len(v.ToolCalls) > 0
			for _, call := range v.ToolCalls {
				d.ToolArguments += text(call.Function.Arguments)
			}
		}
	}
	return d
}

func (c Chunk) String() string   { return fmt.Sprintf("chat.Chunk(%d bytes)", len(c.object)) }
func (c Chunk) GoString() string { return c.String() }

type Usage struct {
	PromptTokens           int
	CompletionTokens       int
	CachedPromptTokens     int
	CacheWritePromptTokens int
	ReasoningTokens        int
}

func (u Usage) Normalized() Usage {
	u.PromptTokens = max(u.PromptTokens, 0)
	u.CompletionTokens = max(u.CompletionTokens, 0)
	u.CachedPromptTokens = min(max(u.CachedPromptTokens, 0), u.PromptTokens)
	u.CacheWritePromptTokens = min(max(u.CacheWritePromptTokens, 0), u.PromptTokens-u.CachedPromptTokens)
	u.ReasoningTokens = min(max(u.ReasoningTokens, 0), u.CompletionTokens)
	return u
}

type Provider interface {
	Stream(ctx context.Context, c Call, emit func(Chunk) error) (Usage, error)
	Complete(ctx context.Context, c Call) (Chunk, Usage, error)
}

type Attestation struct {
	Report      json.RawMessage
	BindModel   string
	GPUVerdicts json.RawMessage
	// VendorPins names the vendor pin set the attesting enclave judged the report by. Nil when the attester is not an enclave worker.
	VendorPins *VendorPins
}

// VendorPins says which vendor pin set is active: the one compiled in, or a signed release of the pins repository.
type VendorPins struct {
	// Sequence is the release's, and 0 for the compiled-in set.
	Sequence uint64 `json:"sequence,omitempty"`
	// StatementSHA256 is the hex sha256 of the release's vendor statement, or "embedded".
	StatementSHA256 string `json:"statement_sha256"`
}

type Attester interface {
	Attest(ctx context.Context, nonce string) (Attestation, error)
}

type InvalidNonce struct{ Form string }

func (e *InvalidNonce) Error() string { return "chat: attestation nonce must be " + e.Form }
