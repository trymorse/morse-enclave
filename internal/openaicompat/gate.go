package openaicompat

import (
	"encoding/json"
	"io"
	"regexp"
	"slices"

	"morse/backend/internal/chat"
	"morse/backend/internal/sse"
)

var textFields = map[string]bool{"content": true, "reasoning": true, "reasoning_content": true, "refusal": true, "tool_calls": true, "function_call": true, "audio": true}

var replyFields = map[string]bool{"id": true, "object": true, "created": true, "model": true, "choices": true, "usage": true, "system_fingerprint": true, "error": true}

var choiceFields = map[string]bool{"index": true, "finish_reason": true, "delta": true, "message": true, "logprobs": true}

// stopTokenFields name the token that ended a choice. SGLang and vLLM write its id there, a
// number that carries no text, and a matched stop string otherwise.
var stopTokenFields = map[string]bool{"matched_stop": true, "stop_reason": true}

var loggableFieldName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func unknownFieldsOf(data []byte, isCiphertext func([]byte) bool) (unknown []string, sealed bool) {
	var reply map[string]json.RawMessage
	if json.Unmarshal(data, &reply) != nil {
		return nil, false
	}
	var choices []map[string]json.RawMessage
	if raw, ok := reply["choices"]; ok && json.Unmarshal(raw, &choices) != nil {
		return nil, false
	}
	if unknown, sealed = unknownOf(reply, replyFields, nil); !sealed {
		return nil, false
	}
	for _, choice := range choices {
		if unknown, sealed = unknownOf(choice, choiceFields, unknown); !sealed {
			return nil, false
		}
		if logprobs, ok := choice["logprobs"]; ok && string(logprobs) != "null" {
			return nil, false
		}
		for _, part := range [...]string{"delta", "message"} {
			var fields map[string]json.RawMessage
			if raw, ok := choice[part]; ok && json.Unmarshal(raw, &fields) != nil {
				return nil, false
			}
			for key, value := range fields {
				switch {
				case key == "role" && string(value) == `"assistant"`, isEmpty(value), key != "role" && isCiphertext(value):
				case key == "role" || textFields[key] || !loggableFieldName.MatchString(key):
					return nil, false
				default:
					unknown = append(unknown, key)
				}
			}
		}
	}
	return unknown, true
}

func unknownOf(object map[string]json.RawMessage, known map[string]bool, unknown []string) ([]string, bool) {
	for key, value := range object {
		switch {
		case known[key] || isEmpty(value), stopTokenFields[key] && isTokenID(value):
		case !loggableFieldName.MatchString(key):
			return nil, false
		default:
			unknown = append(unknown, key)
		}
	}
	return unknown, true
}

type gate struct {
	sealed  chat.E2EE
	unknown []string
}

func (g *gate) passes(data []byte) bool {
	unknown, sealed := unknownFieldsOf(data, g.sealed.IsCiphertext)
	if !sealed || len(unknown) > 0 && !g.sealed.ConfirmsEncryption() {
		return false
	}
	for _, key := range unknown {
		if i, seen := slices.BinarySearch(g.unknown, key); !seen {
			g.unknown = slices.Insert(g.unknown, i, key)
		}
	}
	return true
}

func isTokenID(raw json.RawMessage) bool {
	var id uint32
	return json.Unmarshal(raw, &id) == nil
}

func isEmpty(raw json.RawMessage) bool {
	switch string(raw) {
	case "null", `""`, "[]":
		return true
	}
	return false
}

func relayGated(body io.Reader, g *gate, write func(frame, event []byte) error, tap *usageTap) error {
	done := false
	err := sse.Frames(body, maxEvent, sse.Refuse, func(f sse.Frame) error {
		switch {
		case f.Opaque, f.Data != nil && !isDone(f.Data) && !g.passes(f.Data):
			return chat.ErrUnsealedReply
		case f.Data == nil:
			return write(f.Raw, nil)
		}
		if err := write(f.Raw, f.Data); err != nil {
			return err
		}
		done = done || tap.event(f.Data)
		return nil
	})
	if err == nil && !done {
		return sse.ErrTruncated
	}
	return err
}
