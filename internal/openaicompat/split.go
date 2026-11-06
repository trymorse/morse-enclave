package openaicompat

import (
	"bytes"
	"encoding/json"
	"maps"
)

// DeepInfra puts reasoning, text, and tool calls in one delta, a whole tool call in one chunk, and a finish_reason on the
// chunk that carries the last of them, where Together sends each alone, a call's arguments in pieces after its opening,
// and the finish on a chunk with an empty delta, so a client could tell the hosts apart.
//
// splitChunk returns the chunks a disguised single-choice stream chunk becomes when each says one thing: one chunk for
// its reasoning, one for its text, two for each tool call (its opening with empty arguments, then the arguments), and a
// last one with an empty delta and the finish_reason. Any other chunk comes back whole.
func splitChunk(data []byte) [][]byte {
	var chunk map[string]json.RawMessage
	var choices []map[string]json.RawMessage
	if json.Unmarshal(data, &chunk) != nil || json.Unmarshal(chunk["choices"], &choices) != nil || len(choices) != 1 {
		return [][]byte{data}
	}
	choice := choices[0]
	var delta map[string]json.RawMessage
	if json.Unmarshal(choice["delta"], &delta) != nil {
		return [][]byte{data}
	}
	var deltas []json.RawMessage
	for _, name := range [...]string{"reasoning_content", "content"} {
		if !isNull(delta[name]) {
			deltas = append(deltas, one(name, delta[name]))
		}
	}
	var calls []map[string]json.RawMessage
	if json.Unmarshal(delta["tool_calls"], &calls) != nil {
		calls = nil
	}
	var openedWithArguments bool
	for _, call := range calls {
		var fn map[string]json.RawMessage
		json.Unmarshal(call["function"], &fn)
		args := fn["arguments"]
		if call["id"] == nil || args == nil || string(args) == `""` {
			deltas = append(deltas, one("tool_calls", array(object(call))))
			continue
		}
		openedWithArguments = true
		fn["arguments"] = json.RawMessage(`""`)
		opening := maps.Clone(call)
		opening["function"] = object(fn)
		deltas = append(deltas, one("tool_calls", array(object(opening))))
		deltas = append(deltas, one("tool_calls", array(object(map[string]json.RawMessage{
			"index": call["index"], "function": object(map[string]json.RawMessage{"arguments": args}),
		}))))
	}
	finish := choice["finish_reason"]
	if len(deltas) == 0 || len(deltas) == 1 && isNull(finish) && !openedWithArguments {
		return [][]byte{data}
	}
	null := json.RawMessage("null")
	var out [][]byte
	for _, d := range deltas {
		out = append(out, rebuild(chunk, choice, d, null))
	}
	if !isNull(finish) {
		out = append(out, rebuild(chunk, choice, json.RawMessage("{}"), finish))
	}
	return out
}

func one(name string, v json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	w := objectWriter{out: &b}
	w.field(name, v)
	w.close()
	return b.Bytes()
}

func array(v json.RawMessage) json.RawMessage { return json.RawMessage("[" + string(v) + "]") }

func object(m map[string]json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	w := objectWriter{out: &b}
	for _, name := range [...]string{"index", "id", "type", "function", "name", "arguments"} {
		if v, ok := m[name]; ok {
			w.field(name, v)
		}
	}
	w.close()
	return b.Bytes()
}

func rebuild(chunk, choice map[string]json.RawMessage, delta, finish json.RawMessage) []byte {
	var c bytes.Buffer
	w := objectWriter{out: &c}
	for _, name := range [...]string{"id", "object", "created", "model"} {
		if v, ok := chunk[name]; ok {
			w.field(name, v)
		}
	}
	var ch bytes.Buffer
	cw := objectWriter{out: &ch}
	cw.field("index", choice["index"])
	cw.field("delta", delta)
	cw.field("finish_reason", finish)
	cw.close()
	w.field("choices", array(ch.Bytes()))
	w.close()
	return c.Bytes()
}
