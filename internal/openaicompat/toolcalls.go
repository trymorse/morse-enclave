package openaicompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strconv"
)

// toolCallFields and functionFields are the order a tool call's fields and its function's fields are written in.
var (
	toolCallFields = []string{"index", "id", "type", "function"}
	functionFields = []string{"name", "arguments"}
)

const idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// toolCallID is the id a client sees for call index of a choice in the reply named replyID: call_ and 24 letters or
// digits, the same for every host. A host's own scheme (Together's get_time_0, Fireworks's call_ and hex) would say
// which host served. The id derives from the reply id, which is random per reply, so every chunk of a stream names a
// call alike with no state. A host takes whatever ids a history carries, so the client sends the id back as it is
// and no reverse mapping exists to keep, on any replica.
func toolCallID(replyID string, choice, index int) string {
	sum := sha256.Sum256([]byte(replyID + "/" + strconv.Itoa(choice) + "/" + strconv.Itoa(index)))
	id := []byte("call_")
	for _, b := range sum[:24] {
		id = append(id, idAlphabet[int(b)%len(idAlphabet)])
	}
	return string(id)
}

// uniformToolCalls gives every tool call one shape whichever host sent it. In a stream the delta that opens a call
// carries index, id, type, and function.name and arguments, with an empty string for what the host left out, and a
// continuation carries only index and function.arguments, since hosts differ on repeating type. A continuation that
// carries no arguments is dropped, because it says nothing a client reads. In a whole message a call drops its index
// and always carries id, type, and function.name and arguments.
func uniformToolCalls(raw json.RawMessage, message bool, replyID string, choice int) (json.RawMessage, error) {
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('[')
	kept := 0
	for position, c := range calls {
		index := position
		if v, ok := c["index"]; ok && !message {
			json.Unmarshal(v, &index)
		}
		opens := message || !isNull(c["id"])
		fn, err := uniformFunction(c["function"], opens)
		if err != nil {
			return nil, err
		}
		if !opens && fn == nil {
			continue
		}
		if kept > 0 {
			out.WriteByte(',')
		}
		kept++
		w := objectWriter{out: &out}
		for _, name := range toolCallFields {
			v := c[name]
			switch name {
			case "index":
				if message {
					continue
				}
				v = json.RawMessage(strconv.Itoa(index))
			case "id":
				if isNull(v) && !message {
					continue
				}
				v = jsonString(toolCallID(replyID, choice, index))
			case "type":
				if !opens {
					continue
				}
				v = jsonString("function")
			case "function":
				v = fn
			}
			w.field(name, v)
		}
		w.close()
	}
	out.WriteByte(']')
	if kept == 0 {
		return nil, nil
	}
	return out.Bytes(), nil
}

// uniformFunction returns the function of a call, or nil for a continuation with no arguments to send.
func uniformFunction(raw json.RawMessage, opens bool) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if !isNull(raw) {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	w := objectWriter{out: &out}
	for _, name := range functionFields {
		v := fields[name]
		if isNull(v) || !opens && string(v) == `""` {
			if !opens {
				continue
			}
			v = jsonString("")
		}
		w.field(name, v)
	}
	if !opens && !w.more {
		return nil, nil
	}
	w.close()
	return out.Bytes(), nil
}

func jsonString(s string) json.RawMessage { return json.RawMessage(strconv.Quote(s)) }
