package worker

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"

	"morse/backend/internal/chat"
	"morse/backend/internal/privacyveil"
)

// replyFields are the text fields of a choice's delta or message that a person reads, which the Veil restores.
var replyFields = []string{"content", "reasoning_content", "reasoning", "refusal"}

// replyVeil restores one attempt's reply: each text field of each choice through its own restorer, and each tool
// call's arguments through one that releases only what the chat's ask grants.
type replyVeil struct {
	veil     *privacyveil.Veil
	ask      privacyveil.Ask
	unveiled []string
	prose    map[string]*privacyveil.Restorer
	calls    map[string]*heldCall
	order    []string
	envelope map[string]json.RawMessage
}

type heldCall struct {
	choice, index int
	name          string
	restorer      *privacyveil.Restorer
}

func (v *openedVeil) reply() *replyVeil {
	if v == nil || v.veil == nil {
		return nil
	}
	return &replyVeil{veil: v.veil, ask: v.ask, unveiled: v.unveiled, prose: map[string]*privacyveil.Restorer{}, calls: map[string]*heldCall{}}
}

// chunk restores one streamed chunk. A chunk it cannot read goes out as it came: it carries no text a person reads.
func (rv *replyVeil) chunk(c chat.Chunk) chat.Chunk {
	if rv == nil {
		return c
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(chunkBytes(c), &object) != nil {
		return c
	}
	rv.remember(object)
	choices, ok := rv.choices(object, "delta", false)
	if !ok {
		return c
	}
	object["choices"] = choices
	out, _ := json.Marshal(object)
	return chat.NewChunk(out)
}

// complete restores a reply in one piece, whole, and adds the report.
func (rv *replyVeil) complete(c chat.Chunk) chat.Chunk {
	if rv == nil {
		return c
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(chunkBytes(c), &object) != nil {
		return c
	}
	if choices, ok := rv.choices(object, "message", true); ok {
		object["choices"] = choices
	}
	object["privacy_veil"] = rv.report().JSON()
	out, _ := json.Marshal(object)
	return chat.NewChunk(out)
}

// choices restores each choice's key ("delta" or "message"), flushing a choice's held text once it finishes, or
// at once when whole.
func (rv *replyVeil) choices(object map[string]json.RawMessage, key string, whole bool) (json.RawMessage, bool) {
	var choices []map[string]json.RawMessage
	if json.Unmarshal(object["choices"], &choices) != nil || len(choices) == 0 {
		return nil, false
	}
	for _, choice := range choices {
		var index int
		json.Unmarshal(choice["index"], &index)
		var fields map[string]json.RawMessage
		if json.Unmarshal(choice[key], &fields) != nil || fields == nil {
			continue
		}
		var finish *string
		json.Unmarshal(choice["finish_reason"], &finish)
		flush := whole || finish != nil && *finish != ""
		rv.fields(index, fields, flush)
		choice[key], _ = json.Marshal(fields)
	}
	out, _ := json.Marshal(choices)
	return out, true
}

func (rv *replyVeil) fields(choice int, fields map[string]json.RawMessage, flush bool) {
	for _, name := range replyFields {
		var text string
		_, present := fields[name]
		if present && json.Unmarshal(fields[name], &text) != nil {
			continue
		}
		r := rv.proseRestorer(choice, name)
		restored := r.Next(text)
		if flush {
			restored += r.Flush()
		}
		if present || restored != "" {
			fields[name] = marshalText(restored)
		}
	}
	if audio, ok := fields["audio"]; ok {
		var a map[string]json.RawMessage
		var transcript string
		if json.Unmarshal(audio, &a) == nil && json.Unmarshal(a["transcript"], &transcript) == nil {
			r := rv.proseRestorer(choice, "audio")
			transcript = r.Next(transcript)
			if flush {
				transcript += r.Flush()
			}
			a["transcript"] = marshalText(transcript)
			fields["audio"], _ = json.Marshal(a)
		}
	}
	var calls []map[string]json.RawMessage
	if json.Unmarshal(fields["tool_calls"], &calls) == nil && len(calls) > 0 {
		for j, call := range calls {
			index := j
			json.Unmarshal(call["index"], &index)
			call["function"] = rv.function(choice, index, call["function"], flush)
		}
		fields["tool_calls"], _ = json.Marshal(calls)
	}
	if fn, ok := fields["function_call"]; ok {
		fields["function_call"] = rv.function(choice, -1, fn, flush)
	}
}

func (rv *replyVeil) function(choice, index int, raw json.RawMessage, flush bool) json.RawMessage {
	var fn map[string]json.RawMessage
	if json.Unmarshal(raw, &fn) != nil || fn == nil {
		return raw
	}
	id := strconv.Itoa(choice) + "/" + strconv.Itoa(index)
	call, ok := rv.calls[id]
	if !ok {
		call = &heldCall{choice: choice, index: index}
		rv.calls[id], rv.order = call, append(rv.order, id)
	}
	var name string
	if json.Unmarshal(fn["name"], &name) == nil && name != "" && call.name == "" {
		call.name = name
	}
	var arguments string
	if _, present := fn["arguments"]; present && json.Unmarshal(fn["arguments"], &arguments) != nil {
		return raw
	}
	if call.restorer == nil {
		call.restorer = rv.veil.ArgumentRestorer(rv.ask.Releases(call.name))
	}
	restored := call.restorer.Next(arguments)
	if flush {
		restored += call.restorer.Flush()
	}
	if _, present := fn["arguments"]; present || restored != "" {
		fn["arguments"] = marshalText(restored)
	}
	out, _ := json.Marshal(fn)
	return out
}

func (rv *replyVeil) proseRestorer(choice int, field string) *privacyveil.Restorer {
	id := strconv.Itoa(choice) + "/" + field
	r, ok := rv.prose[id]
	if !ok {
		if rv.ask.Restore == privacyveil.RestoreNone {
			r = rv.veil.ArgumentRestorer(nil)
		} else {
			r = rv.veil.Restorer()
		}
		rv.prose[id] = r
	}
	return r
}

// remember keeps a chunk's envelope, which the chunks the Veil writes itself copy.
func (rv *replyVeil) remember(object map[string]json.RawMessage) {
	if rv.envelope != nil {
		return
	}
	rv.envelope = map[string]json.RawMessage{}
	for _, key := range []string{"id", "object", "created", "model"} {
		if v, ok := object[key]; ok {
			rv.envelope[key] = v
		}
	}
}

// closing is what the stream ends with before [DONE]: a chunk with any text still held back, then the report.
func (rv *replyVeil) closing() []chat.Chunk {
	if rv == nil {
		return nil
	}
	var out []chat.Chunk
	byChoice := map[int]map[string]json.RawMessage{}
	for id, r := range rv.prose {
		choice, field := splitID(id)
		if text := r.Flush(); text != "" {
			if byChoice[choice] == nil {
				byChoice[choice] = map[string]json.RawMessage{}
			}
			if field == "audio" {
				byChoice[choice]["audio"], _ = json.Marshal(map[string]json.RawMessage{"transcript": marshalText(text)})
				continue
			}
			byChoice[choice][field] = marshalText(text)
		}
	}
	for _, id := range rv.order {
		call := rv.calls[id]
		if call.restorer == nil {
			continue
		}
		if text := call.restorer.Flush(); text != "" {
			if byChoice[call.choice] == nil {
				byChoice[call.choice] = map[string]json.RawMessage{}
			}
			fn, _ := json.Marshal(map[string]json.RawMessage{"arguments": marshalText(text)})
			tool, _ := json.Marshal([]map[string]json.RawMessage{{"index": json.RawMessage(strconv.Itoa(call.index)), "function": fn}})
			byChoice[call.choice]["tool_calls"] = tool
		}
	}
	if len(byChoice) > 0 {
		var choices []map[string]json.RawMessage
		for _, choice := range slices.Sorted(maps.Keys(byChoice)) {
			delta, _ := json.Marshal(byChoice[choice])
			choices = append(choices, map[string]json.RawMessage{"index": json.RawMessage(strconv.Itoa(choice)), "delta": delta})
		}
		out = append(out, rv.envelopeChunk(choices, nil))
	}
	return append(out, rv.envelopeChunk([]map[string]json.RawMessage{}, rv.report().JSON()))
}

func (rv *replyVeil) envelopeChunk(choices []map[string]json.RawMessage, report []byte) chat.Chunk {
	object := map[string]json.RawMessage{}
	for k, v := range rv.envelope {
		object[k] = v
	}
	if _, ok := object["object"]; !ok {
		object["object"] = json.RawMessage(`"chat.completion.chunk"`)
	}
	object["choices"], _ = json.Marshal(choices)
	if report != nil {
		object["privacy_veil"] = report
	}
	out, _ := json.Marshal(object)
	return chat.NewChunk(out)
}

func (rv *replyVeil) report() privacyveil.Report {
	r := privacyveil.Report{Unveiled: rv.unveiled}
	for _, id := range rv.order {
		call := rv.calls[id]
		if call.restorer != nil && len(call.restorer.Held()) > 0 {
			r.Held = append(r.Held, privacyveil.Held{ToolCall: call.index, Placeholders: call.restorer.Held()})
		}
	}
	if rv.ask.Report {
		r.Entities = rv.veil.Entities()
	}
	return r
}

func splitID(id string) (int, string) {
	for i := range len(id) {
		if id[i] == '/' {
			n, _ := strconv.Atoi(id[:i])
			return n, id[i+1:]
		}
	}
	return 0, id
}

func marshalText(s string) json.RawMessage {
	out, _ := json.Marshal(s)
	return out
}

func chunkBytes(c chat.Chunk) []byte {
	var b bytesWriter
	c.WriteTo(&b)
	return b
}

type bytesWriter []byte

func (b *bytesWriter) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}
