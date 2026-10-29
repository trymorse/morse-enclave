package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"sync"
)

var ErrOpenToolCall = errors.New("chat: the last message calls tools whose results are not in the request")

const jsonSpace = " \t\r\n"

func (r *Request) AsCompaction(prompt string) (*Request, error) {
	list := bytes.Trim(r.fields["messages"], jsonSpace)
	if len(list) < 2 || list[0] != '[' || bytes.TrimLeft(list[1:], jsonSpace)[0] == ']' {
		return nil, errMalformedMessages
	}
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	if last := msgs[len(msgs)-1]; last.Role == "assistant" && callsTools(last.ToolCalls()) {
		return nil, ErrOpenToolCall
	}
	role, _ := json.Marshal("user")
	content, _ := json.Marshal(prompt)
	instruction := encodeObject(map[string]json.RawMessage{"role": role, "content": content})
	open := bytes.TrimRight(list[:len(list)-1], jsonSpace)
	messages := make(json.RawMessage, 0, len(open)+len(instruction)+2)
	messages = append(append(append(append(messages, open...), ','), instruction...), ']')
	out := *r
	out.fields = maps.Clone(r.fields)
	out.fields["messages"] = messages
	if tools, ok := out.fields["tools"]; ok && string(tools) != "null" {
		out.fields["tool_choice"] = json.RawMessage(`"none"`)
		delete(out.fields, "parallel_tool_calls")
	}
	out.raw = encodeObject(out.fields)
	out.messages = sync.OnceValues(out.parseMessages)
	return &out, nil
}

func callsTools(raw json.RawMessage) bool {
	var calls []json.RawMessage
	return json.Unmarshal(raw, &calls) == nil && len(calls) > 0
}
