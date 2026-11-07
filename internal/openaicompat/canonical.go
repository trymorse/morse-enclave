package openaicompat

import (
	"bytes"
	"encoding/json"
	"slices"

	"morse/backend/internal/jsonx"
)

// canonical returns the chunks Together would have sent for a disguised stream chunk, so a reply reads the same
// whichever plaintext host served it. Each chunk carries one choice saying one thing: its reasoning, its text, its
// refusal, a tool call's opening with arguments "", or a run of that call's arguments, and a finish_reason comes alone
// on an empty delta. Hosts pack these together: DeepInfra puts reasoning, text, and tool calls in one delta, and Morph
// and Fireworks send a tool call whole, often on the chunk that carries finish_reason. A choice that says nothing is
// dropped, so a chunk that says nothing becomes none, as Together sends none. A chunk whose every choice says one thing
// comes back as it is.
func canonical(data []byte) [][]byte {
	var e envelope
	var choices []struct {
		Index        json.RawMessage            `json:"index"`
		Delta        map[string]json.RawMessage `json:"delta"`
		FinishReason json.RawMessage            `json:"finish_reason"`
		Logprobs     json.RawMessage            `json:"logprobs"`
	}
	if json.Unmarshal(data, &e) != nil || json.Unmarshal(e.Choices, &choices) != nil || len(choices) == 0 {
		return [][]byte{data}
	}
	type piece struct{ index, delta, finish, logprobs json.RawMessage }
	var pieces []piece
	whole := true
	for _, c := range choices {
		first := len(pieces)
		say := func(delta json.RawMessage) {
			pieces = append(pieces, piece{index: c.Index, delta: delta, finish: json.RawMessage("null")})
		}
		for _, name := range [...]string{"reasoning_content", "content", "refusal"} {
			if v, ok := c.Delta[name]; ok {
				say(one(name, v))
			}
		}
		var calls []map[string]json.RawMessage
		json.Unmarshal(c.Delta["tool_calls"], &calls)
		for _, call := range calls {
			opening, arguments := apart(call)
			say(one("tool_calls", array(opening)))
			if arguments != nil {
				say(one("tool_calls", array(arguments)))
			}
		}
		if !isNull(c.FinishReason) {
			pieces = append(pieces, piece{index: c.Index, delta: json.RawMessage("{}"), finish: c.FinishReason})
		}
		if !isNull(c.Logprobs) && len(pieces) > first {
			pieces[first].logprobs = c.Logprobs
		}
		whole = whole && len(pieces) == first+1
	}
	if whole {
		return [][]byte{data}
	}
	chunks := make([][]byte, len(pieces))
	for i, p := range pieces {
		var choice bytes.Buffer
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
		one := e
		one.Choices = array(choice.Bytes())
		if i < len(pieces)-1 {
			one.Usage = nil
		}
		chunks[i] = jsonx.Encode(one)
	}
	return chunks
}

// apart splits a streamed tool call that opens with its arguments into its opening with arguments "" and a
// continuation of index and arguments, as Together streams every call. Any other call comes back as it is.
func apart(call map[string]json.RawMessage) (opening, arguments json.RawMessage) {
	var fn map[string]json.RawMessage
	json.Unmarshal(call["function"], &fn)
	args := fn["arguments"]
	if call["id"] == nil || isNull(args) || string(args) == `""` {
		return toolCallJSON(call), nil
	}
	fn["arguments"] = json.RawMessage(`""`)
	call["function"] = toolCallJSON(fn)
	return toolCallJSON(call), toolCallJSON(map[string]json.RawMessage{"index": call["index"], "function": toolCallJSON(map[string]json.RawMessage{"arguments": args})})
}

func one(name string, v json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	w := objectWriter{out: &b}
	w.field(name, v)
	w.close()
	return b.Bytes()
}

func array(v json.RawMessage) json.RawMessage { return json.RawMessage("[" + string(v) + "]") }

// toolCallJSON writes a tool call or its function with its fields in the order uniformToolCalls writes them.
func toolCallJSON(m map[string]json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	w := objectWriter{out: &b}
	for _, name := range slices.Concat(toolCallFields, functionFields) {
		if v, ok := m[name]; ok {
			w.field(name, v)
		}
	}
	w.close()
	return b.Bytes()
}
