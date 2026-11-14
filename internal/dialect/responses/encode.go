package responses

import (
	"cmp"
	"crypto/rand"
	"encoding/json"
	"strings"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
)

type echo struct {
	model           string
	instructions    json.RawMessage
	maxOutputTokens json.RawMessage
	tools           []json.RawMessage
	toolChoice      json.RawMessage
	parallel        bool
	effort          *string
	summary         *string
	temperature     *float64
	topP            *float64
	metadata        json.RawMessage
	custom          map[string]bool
	namespaced      map[string]qualified
	summarize       bool
}

func echoOf(req request, t tools, r reasoning) echo {
	e := echo{model: req.Model, instructions: req.Instructions, maxOutputTokens: req.MaxOutputTokens, tools: t.echo, toolChoice: t.choice,
		parallel: req.ParallelToolCalls == nil || *req.ParallelToolCalls, effort: r.Effort, summary: r.Summary, temperature: req.Temperature,
		topP: req.TopP, metadata: req.Metadata, custom: t.custom, namespaced: t.namespaced, summarize: r.summarized()}
	if e.summary == nil {
		e.summary = r.GenerateSummary
	}
	return e
}

func orNull(raw json.RawMessage) json.RawMessage {
	if null(raw) {
		return json.RawMessage("null")
	}
	return raw
}

type itemKind uint8

const (
	messageItem itemKind = iota
	reasoningItem
	callItem
)

type outItem struct {
	kind      itemKind
	id        string
	index     int
	text      strings.Builder
	callID    string
	name      string
	namespace string
	custom    bool
}

func (it *outItem) call(status string) map[string]any {
	call := map[string]any{"id": it.id, "type": "function_call", "status": status, "call_id": it.callID, "name": it.name}
	if it.custom {
		call["type"] = "custom_tool_call"
	}
	if it.namespace != "" {
		call["namespace"] = it.namespace
	}
	return call
}

func (it *outItem) object(status string) map[string]any {
	text := it.text.String()
	switch it.kind {
	case messageItem:
		return map[string]any{"id": it.id, "type": "message", "status": status, "role": "assistant", "content": []any{outputText(text)}}
	case reasoningItem:
		return map[string]any{"id": it.id, "type": "reasoning", "summary": []any{summaryText(text)}}
	case callItem:
		call := it.call(status)
		switch {
		case it.custom && status == "in_progress":
			call["input"] = ""
		case it.custom:
			call["input"] = customInput(text)
		default:
			call["arguments"] = text
		}
		return call
	}
	return nil
}

func (it *outItem) opened() map[string]any {
	switch it.kind {
	case messageItem:
		return map[string]any{"id": it.id, "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}
	case reasoningItem:
		return map[string]any{"id": it.id, "type": "reasoning", "summary": []any{}}
	case callItem:
		return it.object("in_progress")
	}
	return nil
}

func outputText(text string) map[string]any {
	return map[string]any{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": []any{}}
}

func summaryText(text string) map[string]any {
	return map[string]any{"type": "summary_text", "text": text}
}

func customInput(arguments string) string {
	var wrapped struct {
		Input *string `json:"input"`
	}
	if json.Unmarshal([]byte(arguments), &wrapped) != nil || wrapped.Input == nil {
		return arguments
	}
	return *wrapped.Input
}

type encoder struct {
	echo
	id        string
	createdAt int64
	sequence  int
	started   bool
	items     []*outItem
	message   *outItem
	reasoning *outItem
	calls     map[int]*outItem
	finish    chat.Finish
	now       func() time.Time
	lastSent  time.Time
}

// pingAfter is how long content the client does not see yet may run before an event fills the silence. Cloudflare cuts
// a reply that sends nothing for 100 seconds, and a client's idle watchdog may give up sooner.
const pingAfter = 15 * time.Second

func newEncoder(e echo) *encoder {
	return &encoder{echo: e, id: "resp_" + rand.Text(), createdAt: time.Now().Unix(), calls: map[int]*outItem{}, now: time.Now}
}

func (e *encoder) event(name string, fields map[string]any) dialect.Event {
	fields["type"] = name
	fields["sequence_number"] = e.sequence
	e.sequence++
	body, _ := json.Marshal(fields)
	return dialect.Event{Name: name, Data: body}
}

func usageOf(u chat.Usage) map[string]any {
	u = u.Normalized()
	return map[string]any{
		"input_tokens":          u.PromptTokens,
		"input_tokens_details":  map[string]int{"cached_tokens": u.CachedPromptTokens},
		"output_tokens":         u.CompletionTokens,
		"output_tokens_details": map[string]int{"reasoning_tokens": u.ReasoningTokens},
		"total_tokens":          u.PromptTokens + u.CompletionTokens,
	}
}

func (e *encoder) response(status string, output []any, usage any, incomplete, failure any) map[string]any {
	choice := orNull(e.toolChoice)
	if null(e.toolChoice) {
		choice = json.RawMessage(`"auto"`)
	}
	tools := e.tools
	if tools == nil {
		tools = []json.RawMessage{}
	}
	metadata := orNull(e.metadata)
	if null(e.metadata) {
		metadata = json.RawMessage(`{}`)
	}
	return map[string]any{
		"id": e.id, "object": "response", "created_at": e.createdAt, "status": status, "background": false, "error": failure,
		"incomplete_details": incomplete, "instructions": orNull(e.instructions), "max_output_tokens": orNull(e.maxOutputTokens),
		"model": e.model, "output": output, "parallel_tool_calls": e.parallel, "previous_response_id": nil,
		"reasoning": map[string]any{"effort": e.effort, "summary": e.summary}, "store": false, "temperature": e.temperature,
		"top_p": e.topP, "text": map[string]any{"format": map[string]string{"type": "text"}}, "tool_choice": choice, "tools": tools,
		"truncation": "disabled", "usage": usage, "user": nil, "metadata": metadata,
	}
}

func (e *encoder) start() []dialect.Event {
	if e.started {
		return nil
	}
	e.started = true
	return []dialect.Event{
		e.event("response.created", map[string]any{"response": e.response("in_progress", []any{}, nil, nil, nil)}),
		e.event("response.in_progress", map[string]any{"response": e.response("in_progress", []any{}, nil, nil, nil)}),
	}
}

func (e *encoder) open(it *outItem) []dialect.Event {
	it.index = len(e.items)
	e.items = append(e.items, it)
	events := []dialect.Event{e.event("response.output_item.added", map[string]any{"output_index": it.index, "item": it.opened()})}
	switch it.kind {
	case messageItem:
		events = append(events, e.event("response.content_part.added", map[string]any{"item_id": it.id, "output_index": it.index, "content_index": 0, "part": outputText("")}))
	case reasoningItem:
		events = append(events, e.event("response.reasoning_summary_part.added", map[string]any{"item_id": it.id, "output_index": it.index, "summary_index": 0, "part": summaryText("")}))
	}
	return events
}

func (e *encoder) Chunk(c chat.Chunk) []dialect.Event {
	events := e.chunk(c)
	now := e.now()
	if len(events) > 0 {
		e.lastSent = now
	}
	return events
}

// chunk fills a silence while it holds content back (reasoning the client did not ask to see, or a custom tool's
// arguments until End) with response.in_progress, carrying the items opened so far as the client has seen them:
// OpenAI's Responses stream has no ping event.
func (e *encoder) chunk(c chat.Chunk) []dialect.Event {
	events := e.start()
	held := false
	for _, choice := range dialect.ViewOf(c).Choices {
		if finish, ok := chat.ParseFinish(choice.Finish); ok {
			e.finish = finish
		}
		d := choice.Delta
		if d == nil {
			continue
		}
		thought := d.ReasoningText()
		held = held || thought != "" && !e.summarize
		if thought != "" && e.summarize {
			if e.reasoning == nil {
				e.reasoning = &outItem{kind: reasoningItem, id: "rs_" + rand.Text()}
				events = append(events, e.open(e.reasoning)...)
			}
			e.reasoning.text.WriteString(thought)
			events = append(events, e.event("response.reasoning_summary_text.delta", map[string]any{"item_id": e.reasoning.id, "output_index": e.reasoning.index, "summary_index": 0, "delta": thought}))
		}
		if text := d.Text(); text != "" {
			if e.message == nil {
				e.message = &outItem{kind: messageItem, id: "msg_" + rand.Text()}
				events = append(events, e.open(e.message)...)
			}
			e.message.text.WriteString(text)
			events = append(events, e.event("response.output_text.delta", map[string]any{"item_id": e.message.id, "output_index": e.message.index, "content_index": 0, "delta": text, "logprobs": []any{}}))
		}
		for _, call := range d.ToolCalls {
			it, ok := e.calls[call.Index]
			if !ok {
				it = e.callItem(call.ID, call.Function.Name)
				e.calls[call.Index] = it
				events = append(events, e.open(it)...)
			}
			if call.Function.Arguments == "" {
				continue
			}
			it.text.WriteString(call.Function.Arguments)
			held = held || it.custom
			if !it.custom {
				events = append(events, e.event("response.function_call_arguments.delta", map[string]any{"item_id": it.id, "output_index": it.index, "delta": call.Function.Arguments}))
			}
		}
	}
	if len(events) == 0 && held && e.now().Sub(e.lastSent) >= pingAfter {
		events = append(events, e.event("response.in_progress", map[string]any{"response": e.response("in_progress", e.output("in_progress"), nil, nil, nil)}))
	}
	return events
}

func (e *encoder) callItem(callID, name string) *outItem {
	custom := e.custom[name]
	prefix := "fc_"
	if custom {
		prefix = "ctc_"
	}
	if callID == "" {
		callID = "call_" + rand.Text()
	}
	it := &outItem{kind: callItem, id: prefix + rand.Text(), callID: callID, name: name, custom: custom}
	if q, ok := e.namespaced[name]; ok {
		it.name, it.namespace = q.name, q.namespace
	}
	return it
}

func (e *encoder) done(it *outItem, status string) []dialect.Event {
	at := map[string]any{"item_id": it.id, "output_index": it.index}
	with := func(fields map[string]any) map[string]any {
		for k, v := range at {
			fields[k] = v
		}
		return fields
	}
	text := it.text.String()
	var events []dialect.Event
	switch {
	case it.kind == messageItem:
		events = append(events,
			e.event("response.output_text.done", with(map[string]any{"content_index": 0, "text": text, "logprobs": []any{}})),
			e.event("response.content_part.done", with(map[string]any{"content_index": 0, "part": outputText(text)})))
	case it.kind == reasoningItem:
		events = append(events,
			e.event("response.reasoning_summary_text.done", with(map[string]any{"summary_index": 0, "text": text})),
			e.event("response.reasoning_summary_part.done", with(map[string]any{"summary_index": 0, "part": summaryText(text)})))
	case it.custom:
		input := customInput(text)
		events = append(events,
			e.event("response.custom_tool_call_input.delta", with(map[string]any{"delta": input})),
			e.event("response.custom_tool_call_input.done", with(map[string]any{"input": input})))
	default:
		events = append(events, e.event("response.function_call_arguments.done", with(map[string]any{"name": it.name, "arguments": text})))
	}
	return append(events, e.event("response.output_item.done", map[string]any{"output_index": it.index, "item": it.object(status)}))
}

func (e *encoder) output(status string) []any {
	output := make([]any, 0, len(e.items))
	for _, it := range e.items {
		output = append(output, it.object(status))
	}
	return output
}

func ending(f chat.Finish) (string, any) {
	switch f {
	case chat.FinishLength:
		return "incomplete", map[string]string{"reason": "max_output_tokens"}
	case chat.FinishContentFilter:
		return "incomplete", map[string]string{"reason": "content_filter"}
	}
	return "completed", nil
}

func (e *encoder) End(u chat.Usage) []dialect.Event {
	events := e.start()
	status, incomplete := ending(e.finish)
	for _, it := range e.items {
		events = append(events, e.done(it, status)...)
	}
	return append(events, e.event("response."+status, map[string]any{"response": e.response(status, e.output(status), usageOf(u), incomplete, nil)}))
}

// Failed nests the error in the Response: the OpenAI SDKs raise on an event with a top-level error before the client
// sees the Response.
func (e *encoder) Failed(refusal apierr.Error) []dialect.Event {
	events := e.start()
	failure := map[string]string{"code": cmp.Or(refusal.Code, "server_error"), "message": refusal.Message}
	return append(events, e.event("response.failed", map[string]any{"response": e.response("failed", e.output("incomplete"), nil, nil, failure)}))
}

func (e *encoder) Whole(c chat.Chunk, u chat.Usage) []byte {
	finish := chat.FinishNone
	for _, choice := range dialect.ViewOf(c).Choices {
		if f, ok := chat.ParseFinish(choice.Finish); ok {
			finish = f
		}
		m := choice.Message
		if m == nil {
			continue
		}
		if thought := m.ReasoningText(); thought != "" && e.summarize {
			it := &outItem{kind: reasoningItem, id: "rs_" + rand.Text()}
			it.text.WriteString(thought)
			e.items = append(e.items, it)
		}
		if text := m.Text(); text != "" {
			it := &outItem{kind: messageItem, id: "msg_" + rand.Text()}
			it.text.WriteString(text)
			e.items = append(e.items, it)
		}
		for _, call := range m.ToolCalls {
			it := e.callItem(call.ID, call.Function.Name)
			it.text.WriteString(call.Function.Arguments)
			e.items = append(e.items, it)
		}
	}
	status, incomplete := ending(finish)
	body, _ := json.Marshal(e.response(status, e.output(status), usageOf(u), incomplete, nil))
	return body
}
