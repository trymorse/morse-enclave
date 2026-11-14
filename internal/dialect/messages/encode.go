package messages

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
)

var stopReasons = map[chat.Finish]string{
	chat.FinishNone:          "end_turn",
	chat.FinishStop:          "end_turn",
	chat.FinishToolCalls:     "tool_use",
	chat.FinishLength:        "max_tokens",
	chat.FinishContentFilter: "refusal",
}

type usage struct {
	InputTokens              int `json:"input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	OutputTokens             int `json:"output_tokens"`
}

// usageOf splits the prompt as Anthropic does: input_tokens counts only the prompt read neither from nor into the
// cache.
func usageOf(u chat.Usage) usage {
	u = u.Normalized()
	return usage{
		InputTokens:              u.PromptTokens - u.CachedPromptTokens - u.CacheWritePromptTokens,
		CacheCreationInputTokens: u.CacheWritePromptTokens,
		CacheReadInputTokens:     u.CachedPromptTokens,
		OutputTokens:             u.CompletionTokens,
	}
}

type blockKind uint8

const (
	noBlock blockKind = iota
	textBlock
	thinkingBlock
	toolBlock
)

type encoder struct {
	id, model    string
	showThinking bool
	started      bool
	open         blockKind
	opened       int
	openTool     int
	finish       chat.Finish
	now          func() time.Time
	lastSent     time.Time
}

// pingAfter is how long reasoning the client does not see may run before a ping fills the silence. Cloudflare cuts a
// reply that sends nothing for 100 seconds, and a client's idle watchdog may give up sooner.
const pingAfter = 15 * time.Second

func newEncoder(model string, showThinking bool) *encoder {
	return &encoder{id: "msg_" + rand.Text(), model: model, showThinking: showThinking, now: time.Now}
}

func event(name string, data any) dialect.Event {
	body, _ := json.Marshal(data)
	return dialect.Event{Name: name, Data: body}
}

func (e *encoder) message(content []any, stop *string, u usage) map[string]any {
	return map[string]any{"id": e.id, "type": "message", "role": "assistant", "model": e.model, "content": content, "stop_reason": stop, "stop_sequence": nil, "usage": u}
}

func (e *encoder) start() []dialect.Event {
	if e.started {
		return nil
	}
	e.started = true
	return []dialect.Event{event("message_start", map[string]any{"type": "message_start", "message": e.message([]any{}, nil, usage{})})}
}

func (e *encoder) close() []dialect.Event {
	if e.open == noBlock {
		return nil
	}
	e.open = noBlock
	return []dialect.Event{event("content_block_stop", map[string]any{"type": "content_block_stop", "index": e.opened - 1})}
}

func (e *encoder) begin(kind blockKind, block map[string]any) []dialect.Event {
	events := e.close()
	e.open = kind
	e.opened++
	return append(events, event("content_block_start", map[string]any{"type": "content_block_start", "index": e.opened - 1, "content_block": block}))
}

func (e *encoder) delta(delta map[string]any) dialect.Event {
	return event("content_block_delta", map[string]any{"type": "content_block_delta", "index": e.opened - 1, "delta": delta})
}

func (e *encoder) Chunk(c chat.Chunk) []dialect.Event {
	events := e.chunk(c)
	now := e.now()
	if len(events) > 0 {
		e.lastSent = now
	}
	return events
}

func (e *encoder) chunk(c chat.Chunk) []dialect.Event {
	events := e.start()
	hidden := false
	for _, choice := range dialect.ViewOf(c).Choices {
		if finish, ok := chat.ParseFinish(choice.Finish); ok {
			e.finish = finish
		}
		d := choice.Delta
		if d == nil {
			continue
		}
		thought := d.ReasoningText()
		hidden = hidden || thought != "" && !e.showThinking
		if thought != "" && e.showThinking {
			if e.open != thinkingBlock {
				events = append(events, e.begin(thinkingBlock, map[string]any{"type": "thinking", "thinking": "", "signature": ""})...)
			}
			events = append(events, e.delta(map[string]any{"type": "thinking_delta", "thinking": thought}))
		}
		if text := d.Text(); text != "" {
			if e.open != textBlock {
				events = append(events, e.begin(textBlock, map[string]any{"type": "text", "text": ""})...)
			}
			events = append(events, e.delta(map[string]any{"type": "text_delta", "text": text}))
		}
		for _, call := range d.ToolCalls {
			if e.open != toolBlock || call.Index != e.openTool {
				events = append(events, e.begin(toolBlock, map[string]any{"type": "tool_use", "id": toolUseID(call.ID), "name": call.Function.Name, "input": map[string]any{}})...)
				e.openTool = call.Index
			}
			if call.Function.Arguments != "" {
				events = append(events, e.delta(map[string]any{"type": "input_json_delta", "partial_json": call.Function.Arguments}))
			}
		}
	}
	if len(events) == 0 && hidden && e.now().Sub(e.lastSent) >= pingAfter {
		events = append(events, event("ping", map[string]any{"type": "ping"}))
	}
	return events
}

func toolUseID(id string) string {
	if id == "" {
		return "toolu_" + rand.Text()
	}
	return id
}

func (e *encoder) End(u chat.Usage) []dialect.Event {
	events := append(e.start(), e.close()...)
	stop := stopReasons[e.finish]
	return append(events,
		event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": usageOf(u)}),
		event("message_stop", map[string]any{"type": "message_stop"}),
	)
}

func (e *encoder) Failed(refusal apierr.Error) []dialect.Event {
	return []dialect.Event{{Name: "error", Data: Envelope(refusal)}}
}

func (e *encoder) Whole(c chat.Chunk, u chat.Usage) []byte {
	content := []any{}
	finish := chat.FinishNone
	for _, choice := range dialect.ViewOf(c).Choices {
		if f, ok := chat.ParseFinish(choice.Finish); ok {
			finish = f
		}
		m := choice.Message
		if m == nil {
			continue
		}
		if thought := m.ReasoningText(); thought != "" && e.showThinking {
			content = append(content, map[string]any{"type": "thinking", "thinking": thought, "signature": ""})
		}
		if text := m.Text(); text != "" {
			content = append(content, map[string]any{"type": "text", "text": text})
		}
		for _, call := range m.ToolCalls {
			content = append(content, map[string]any{"type": "tool_use", "id": toolUseID(call.ID), "name": call.Function.Name, "input": inputOf(call.Function.Arguments)})
		}
	}
	stop := stopReasons[finish]
	body, _ := json.Marshal(e.message(content, &stop, usageOf(u)))
	return body
}

// inputOf is a tool call's arguments as the object a tool_use block's input is. Arguments that are no JSON object
// are sent as an empty one, since a tool_use input is always an object.
func inputOf(arguments string) json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(arguments), &object) != nil || object == nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(arguments)
}

// errorTypes are Anthropic's error types by status. Morse answers 503 when a model host is busy or the service is
// restarting, which is what Anthropic's overloaded_error reports.
var errorTypes = map[int]string{
	http.StatusBadRequest:            "invalid_request_error",
	http.StatusUnauthorized:          "authentication_error",
	http.StatusPaymentRequired:       "billing_error",
	http.StatusForbidden:             "permission_error",
	http.StatusNotFound:              "not_found_error",
	http.StatusRequestEntityTooLarge: "request_too_large",
	http.StatusTooManyRequests:       "rate_limit_error",
	http.StatusServiceUnavailable:    "overloaded_error",
	http.StatusGatewayTimeout:        "timeout_error",
}

func Envelope(e apierr.Error) []byte {
	typ, ok := errorTypes[e.Status]
	switch {
	case ok:
	case e.Status >= 500:
		typ = "api_error"
	default:
		typ = "invalid_request_error"
	}
	body, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": e.Message}})
	return body
}
