package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"morse/backend/internal/capped"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	nearseal "morse/backend/internal/e2ee/near"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

// A Sealer runs one call under a fresh client key pair and a model key a verified report lists now. It owns the
// key's lifecycle around the call, such as forgetting a key the vendor says it rotated.
type Sealer interface {
	Seal(call func(Sealing) error) error
}

type Sealing interface {
	chat.E2EE
	SealContent(message int, plaintext string) (string, error)
	Open(replyID string, f e2ee.ResponseField, sealed string) ([]byte, error)
}

// why: NEAR seals tool fields on version 3, which binds each field's label and the client key into its seal
// (nearai/inference-proxy docs/e2ee.md).
type ToolSealing interface {
	Sealing
	SealField(label string, plaintext []byte) (string, error)
}

type SealedSender struct {
	upstream.Endpoint
	Sealer Sealer
}

var _ Sender = SealedSender{}

func (s SealedSender) Stream(ctx context.Context, body []byte, header http.Header, each func([]byte) (bool, error)) error {
	return s.Sealer.Seal(func(seal Sealing) error {
		resp, seal, err := s.open(ctx, body, accepting(header, "text/event-stream"), seal)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		o := opener{seal: seal}
		return sse.Each(resp.Body, maxEvent, sse.Refuse, func(data []byte) (bool, error) {
			if isDone(data) {
				return each(data)
			}
			opened, err := o.open(data)
			if err != nil {
				return false, err
			}
			return each(opened)
		})
	})
}

func (s SealedSender) Complete(ctx context.Context, body []byte, header http.Header) ([]byte, error) {
	var opened []byte
	err := s.Sealer.Seal(func(seal Sealing) error {
		resp, seal, err := s.open(ctx, body, accepting(header, "application/json"), seal)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		reply, err := capped.ReadAll(resp.Body, MaxCompletionBody)
		if err != nil {
			return err
		}
		opened, err = (&opener{seal: seal}).open(reply)
		return err
	})
	return opened, err
}

func (s SealedSender) open(ctx context.Context, body []byte, header http.Header, seal Sealing) (*http.Response, Sealing, error) {
	if err := upstream.CheckEgress(ctx, body); err != nil {
		return nil, nil, err
	}
	sealed, seal, err := sealBody(body, seal)
	if err != nil {
		return nil, nil, err
	}
	seal.Forward(header.Set)
	resp, err := s.Endpoint.Open(upstream.WithoutEgress(ctx), upstream.Request{Method: http.MethodPost, Path: ChatCompletionsPath, Header: header, Body: sealed})
	if err != nil {
		return nil, nil, err
	}
	if err := seal.Confirm(resp.Header.Get); err != nil {
		resp.Body.Close()
		return nil, nil, brokenSeal(err.Error())
	}
	return resp, seal, nil
}

type UnsealableField struct{ Name string }

func (e *UnsealableField) Error() string {
	return "openaicompat: " + e.Name + " would travel outside the seal"
}

var (
	sealableFields = map[string]bool{"model": true, "messages": true, "max_tokens": true, "max_completion_tokens": true,
		"stream": true, "stream_options": true, "temperature": true, "top_p": true, "frequency_penalty": true,
		"presence_penalty": true, "seed": true, "n": true, "reasoning_effort": true, "reasoning": true, "provider": true}
	sealableRoles = map[string]bool{"system": true, "user": true, "assistant": true}
	textTurnKeys  = map[string]bool{"role": true, "content": true}
)

func Unsealable(req *chat.Request, tools bool) error {
	for _, field := range req.FieldNames() {
		if !sealableFields[field] && !(tools && sealableToolField(req, field)) {
			return &UnsealableField{Name: field}
		}
	}
	msgs, err := req.Messages()
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if err := unsealableMessage(m, tools); err != nil {
			return err
		}
	}
	return nil
}

func sealableToolField(req *chat.Request, field string) bool {
	raw, _ := req.Field(field)
	switch field {
	case "tools":
		return nearseal.Tools(raw, nearseal.Plain)
	case "tool_choice":
		return nearseal.IsToolChoice(raw)
	}
	return false
}

func unsealableMessage(m chat.Message, tools bool) error {
	allowed := textTurnKeys
	switch {
	case tools && m.Role == "tool":
		allowed = nearseal.ToolTurnKeys
	case tools && m.Role == "assistant":
		allowed = nearseal.CallingKeys
	case !sealableRoles[m.Role]:
		return &UnsealableField{Name: "messages.role"}
	}
	for _, key := range m.Keys() {
		if !allowed[key] && !(m.Role == "assistant" && chat.ReplaysReasoning(key)) {
			return &UnsealableField{Name: "messages." + key}
		}
	}
	if m.Role == "tool" && !nearseal.IsCallID(m.Raw("tool_call_id")) {
		return &UnsealableField{Name: "messages.tool_call_id"}
	}
	if calls := m.Raw("tool_calls"); calls != nil {
		if !nearseal.Calls(calls, nearseal.Plain) {
			return &UnsealableField{Name: "messages.tool_calls"}
		}
		if content := m.Raw("content"); content == nil || string(content) == "null" {
			return nil
		}
	}
	if _, ok := contentText(m); !ok {
		return &UnsealableField{Name: "messages.content"}
	}
	return nil
}

func carriesTools(req *chat.Request) bool {
	if _, ok := req.Field("tools"); ok {
		return true
	}
	if _, ok := req.Field("tool_choice"); ok {
		return true
	}
	msgs, _ := req.Messages()
	return slices.ContainsFunc(msgs, func(m chat.Message) bool { return m.Role == "tool" || m.Raw("tool_calls") != nil })
}

func LooksSealed(req *chat.Request) bool {
	msgs, err := req.Messages()
	if err != nil || len(msgs) == 0 {
		return false
	}
	for _, m := range msgs {
		content := m.Raw("content")
		if !e2ee.X25519.IsCiphertext(content) && !e2ee.Secp256k1.IsCiphertext(content) && !nearseal.IsCiphertext(content) {
			return false
		}
	}
	return true
}

func contentText(m chat.Message) (string, bool) {
	raw := m.Raw("content")
	var text string
	return text, len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &text) == nil
}

type sealedMessage struct {
	Role       string          `json:"role"`
	Content    *string         `json:"content"`
	ToolCallID json.RawMessage `json:"tool_call_id,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
}

func sealBody(body []byte, seal Sealing) ([]byte, Sealing, error) {
	req, err := chat.ParseRequest(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	fields, sealsFields := seal.(ToolSealing)
	if err := Unsealable(req, sealsFields); err != nil {
		return nil, nil, brokenSeal(err.Error())
	}
	set := map[string]json.RawMessage{}
	if sealsFields && carriesTools(req) {
		if raw, ok := req.Field("tools"); ok {
			if set["tools"], err = nearseal.SealTools(raw, fields.SealField); err != nil {
				return nil, nil, err
			}
		}
	} else {
		fields = nil
	}
	msgs, err := req.Messages()
	if err != nil {
		return nil, nil, err
	}
	sealed := make([]sealedMessage, len(msgs))
	for i, m := range msgs {
		sealed[i] = sealedMessage{Role: m.Role, ToolCallID: m.Raw("tool_call_id")}
		text, _ := contentText(m)
		if calls := m.Raw("tool_calls"); calls != nil {
			if sealed[i].ToolCalls, err = nearseal.SealCalls(calls, fields.SealField); err != nil {
				return nil, nil, err
			}
			if text == "" {
				continue
			}
		}
		content, err := seal.SealContent(i, text)
		if err != nil {
			return nil, nil, err
		}
		sealed[i].Content = &content
	}
	if set["messages"], err = json.Marshal(sealed); err != nil {
		return nil, nil, err
	}
	if !sealedThroughout(set, seal) {
		return nil, nil, brokenSeal("a field it sealed holds no ciphertext")
	}
	return req.EncodeOnly(req.FieldNames(), set), seal, nil
}

func sealedThroughout(set map[string]json.RawMessage, seal Sealing) bool {
	ciphertext := func(_ string, raw json.RawMessage) bool { return seal.IsCiphertext(raw) }
	if tools, ok := set["tools"]; ok && !nearseal.Tools(tools, ciphertext) {
		return false
	}
	var msgs []sealedMessage
	if json.Unmarshal(set["messages"], &msgs) != nil {
		return false
	}
	for _, m := range msgs {
		switch {
		case m.ToolCalls != nil && !nearseal.Calls(m.ToolCalls, ciphertext):
			return false
		case m.Content == nil && m.ToolCalls == nil:
			return false
		case m.Content != nil && !seal.IsCiphertext(jsonString(*m.Content)):
			return false
		}
	}
	return true
}

type opener struct {
	seal  Sealing
	id    string
	sawID bool
}

var (
	openedReplyFields  = fieldChecks{"id": isString, "object": isString, "created": isInteger, "model": isString}
	openedChoiceFields = fieldChecks{"index": isInteger, "finish_reason": isFinishReason}
	openedPartFields   = fieldChecks{"role": isAssistant}
	finishReasons      = map[string]bool{"stop": true, "length": true, "tool_calls": true, "content_filter": true, "function_call": true, "abort": true, "error": true, "repetition": true}
	openedUsage        = usageShape{"prompt_tokens": nil, "completion_tokens": nil, "total_tokens": nil, "reasoning_tokens": nil, "cost": nil,
		"prompt_tokens_details":     {"cached_tokens": nil, "audio_tokens": nil},
		"completion_tokens_details": {"reasoning_tokens": nil, "audio_tokens": nil, "accepted_prediction_tokens": nil, "rejected_prediction_tokens": nil}}
	errorCodeText = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
)

type usageShape map[string]usageShape

type fieldChecks map[string]func(json.RawMessage) bool

func (o *opener) open(data []byte) ([]byte, error) {
	g := gate{sealed: o.seal}
	if !g.passes(data) {
		return nil, brokenSeal("a reply field is not ciphertext")
	}
	var reply map[string]json.RawMessage
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, err
	}
	opened, err := kept(reply, openedReplyFields)
	if err != nil {
		return nil, err
	}
	var id string
	if raw, ok := opened["id"]; ok {
		json.Unmarshal(raw, &id)
		if o.sawID && id != o.id {
			return nil, brokenSeal("a frame's id is not the first frame's")
		}
		o.id, o.sawID = id, true
	}
	if raw, ok := reply["usage"]; ok && string(raw) != "null" {
		if opened["usage"], err = counts(raw, openedUsage); err != nil {
			return nil, err
		}
	}
	if raw, ok := reply["error"]; ok && !isEmpty(raw) {
		if opened["error"], err = errorCode(raw); err != nil {
			return nil, err
		}
	}
	raw, ok := reply["choices"]
	if !ok {
		return json.Marshal(opened)
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choices); err != nil {
		return nil, err
	}
	openedChoices := make([]map[string]json.RawMessage, len(choices))
	for i, choice := range choices {
		index := i
		json.Unmarshal(choice["index"], &index)
		if openedChoices[i], err = kept(choice, openedChoiceFields); err != nil {
			return nil, err
		}
		for _, part := range [...]string{"delta", "message"} {
			raw, ok := choice[part]
			if !ok {
				continue
			}
			fields, err := o.openPart(raw, id, index, part)
			if err != nil {
				return nil, err
			}
			openedChoices[i][part] = fields
		}
	}
	opened["choices"], _ = json.Marshal(openedChoices)
	return json.Marshal(opened)
}

func (o *opener) openPart(raw json.RawMessage, id string, choice int, part string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return json.RawMessage("null"), err
	}
	// why: NEAR writes "role":null on every streamed delta of a chat that carries tools, which names no role.
	if string(fields["role"]) == "null" {
		delete(fields, "role")
	}
	opened, err := kept(fields, openedPartFields)
	if err != nil {
		return nil, err
	}
	for name := range textFields {
		value, ok := fields[name]
		switch {
		case !ok:
		case isEmpty(value):
			opened[name] = value
		case name == "tool_calls":
			if opened[name], err = o.openCalls(value, id, choice, part); err != nil {
				return nil, err
			}
		default:
			var sealed string
			json.Unmarshal(value, &sealed)
			f := e2ee.ResponseField{Choice: choice, Part: part, Name: name}
			plain, err := o.seal.Open(id, f, sealed)
			if err != nil {
				return nil, brokenSeal(fmt.Sprintf("%s did not open: %v", f, err))
			}
			opened[name], _ = json.Marshal(string(plain))
		}
	}
	return json.Marshal(opened)
}

// why: NEAR sends a call's index, id, and type in the clear and seals its name and each fragment of its arguments.
func (o *opener) openCalls(raw json.RawMessage, id string, choice int, part string) (json.RawMessage, error) {
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, brokenSeal("tool_calls is not a list of calls")
	}
	opened := make([]map[string]json.RawMessage, len(calls))
	for i, call := range calls {
		opened[i] = map[string]json.RawMessage{}
		for _, key := range [...]string{"index", "id", "type"} {
			if value, ok := call[key]; ok {
				opened[i][key] = value
			}
		}
		var fn map[string]json.RawMessage
		if json.Unmarshal(call["function"], &fn) != nil || fn == nil {
			continue
		}
		openedFn := map[string]json.RawMessage{}
		for key, value := range fn {
			if isEmpty(value) {
				openedFn[key] = value
				continue
			}
			var sealed string
			json.Unmarshal(value, &sealed)
			f := e2ee.ResponseField{Choice: choice, Part: part, Name: "tool_calls.function." + key}
			plain, err := o.seal.Open(id, f, sealed)
			if err != nil {
				return nil, brokenSeal(fmt.Sprintf("%s did not open: %v", f, err))
			}
			openedFn[key], _ = json.Marshal(string(plain))
		}
		opened[i]["function"], _ = json.Marshal(openedFn)
	}
	return json.Marshal(opened)
}

func kept(object map[string]json.RawMessage, fields fieldChecks) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	for name, valid := range fields {
		if value, ok := object[name]; ok {
			if !valid(value) {
				return nil, brokenSeal(name + " is not of the type OpenAI sends")
			}
			out[name] = value
		}
	}
	return out, nil
}

func counts(raw json.RawMessage, shape usageShape) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, brokenSeal("usage is not an object")
	}
	out := map[string]json.RawMessage{}
	for name, value := range fields {
		details, known := shape[name]
		switch {
		case !known, string(value) == "null":
		case details != nil:
			nested, err := counts(value, details)
			if err != nil {
				return nil, err
			}
			out[name] = nested
		case isCount(value), name == "cost" && isAmount(value):
			out[name] = value
		default:
			return nil, brokenSeal("usage." + name + " is not a count")
		}
	}
	return json.Marshal(out)
}

func errorCode(raw json.RawMessage) (json.RawMessage, error) {
	var e struct {
		Code json.RawMessage `json:"code,omitempty"`
	}
	json.Unmarshal(raw, &e)
	var code string
	if len(e.Code) > 0 && string(e.Code) != "null" && !isNumber(e.Code) && (json.Unmarshal(e.Code, &code) != nil || !errorCodeText.MatchString(code)) {
		return nil, brokenSeal("error.code is neither an identifier nor a number")
	}
	return json.Marshal(e)
}

func isString(raw json.RawMessage) bool {
	var s string
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil
}

func isInteger(raw json.RawMessage) bool {
	var n int64
	return string(raw) != "null" && json.Unmarshal(raw, &n) == nil
}

func isCount(raw json.RawMessage) bool {
	var n uint64
	return string(raw) != "null" && json.Unmarshal(raw, &n) == nil
}

func isNumber(raw json.RawMessage) bool {
	var n float64
	return string(raw) != "null" && json.Unmarshal(raw, &n) == nil
}

func isAmount(raw json.RawMessage) bool {
	var n float64
	return string(raw) != "null" && json.Unmarshal(raw, &n) == nil && n >= 0
}

func isFinishReason(raw json.RawMessage) bool {
	var reason string
	return string(raw) == "null" || json.Unmarshal(raw, &reason) == nil && finishReasons[reason]
}

func isAssistant(raw json.RawMessage) bool { return string(raw) == `"assistant"` }

func brokenSeal(reason string) error { return fmt.Errorf("%w: %s", chat.ErrSealBroken, reason) }
