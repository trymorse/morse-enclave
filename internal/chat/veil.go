package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
)

// VeilText is one run of a request's text that a Privacy Veil scans, and the role of the message it is in.
type VeilText struct {
	Role string
	Text string
}

// veiledPartKeys are the keys each part type may carry with the Veil on, which can hold no personal detail but in the
// texts VeilTexts lists. A part of another type, or with another key, could carry text the Veil would not see.
var veiledPartKeys = map[string][]string{
	"text":        {"type", "text", "cache_control"},
	"input_text":  {"type", "text", "cache_control"},
	"refusal":     {"type", "refusal"},
	"image_url":   {"type", "image_url", "cache_control"},
	"input_audio": {"type", "input_audio"},
	"file":        {"type", "file"},
	"video_url":   {"type", "video_url"},
}

// UnveiledKinds names the parts a Privacy Veil sends as written, in the order a reply lists them.
var UnveiledKinds = []string{"image_url", "input_audio", "file", "video_url"}

// ErrUnveilable is a request with a part the Privacy Veil cannot carry, which Param names.
type ErrUnveilable struct{ Param string }

func (e *ErrUnveilable) Error() string {
	return "chat: " + e.Param + " is a part the Privacy Veil cannot carry"
}

// VeilTexts lists every text Veiled rewrites, in the order it rewrites them, each with the role of its message, and
// a tool definition's texts under system, as the caller writes them as it writes a system prompt. It refuses a part
// of a type, or with a key, that could carry text it would miss.
func (r *Request) VeilTexts() ([]VeilText, error) {
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	for i, m := range msgs {
		for j, p := range m.parts {
			if err := p.veilable(fmt.Sprintf("messages[%d].content[%d]", i, j)); err != nil {
				return nil, err
			}
		}
	}
	var texts []VeilText
	_, err = r.rewrite(func(role, s string) string {
		if s != "" {
			texts = append(texts, VeilText{Role: role, Text: s})
		}
		return s
	})
	return texts, err
}

func (p Part) veilable(at string) error {
	if p.fields == nil {
		return nil
	}
	keys, ok := veiledPartKeys[p.Type]
	if !ok {
		return &ErrUnveilable{Param: at + ".type"}
	}
	for key := range p.fields {
		if !slices.Contains(keys, key) {
			return &ErrUnveilable{Param: at + "." + key}
		}
	}
	return nil
}

func fileName(file json.RawMessage) string {
	var f struct {
		Filename string `json:"filename"`
	}
	json.Unmarshal(file, &f)
	return f.Filename
}

// UnveiledKinds lists the kinds of part the request carries that a Privacy Veil sends as written.
func (r *Request) UnveiledKinds() []string {
	msgs, _ := r.Messages()
	var kinds []string
	for _, kind := range UnveiledKinds {
		if slices.ContainsFunc(msgs, func(m Message) bool {
			return slices.ContainsFunc(m.parts, func(p Part) bool { _, ok := p.fields[kind]; return ok })
		}) {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func toolCallsOf(m Message) []toolCall {
	var calls []toolCall
	json.Unmarshal(m.ToolCalls(), &calls)
	return calls
}

// Forwarded is the request's messages, tools, and tool_choice, the fields a vendor reads text in, as one object, for
// a Privacy Veil to check.
func (r *Request) Forwarded() []byte {
	fields := map[string]json.RawMessage{}
	for _, name := range []string{"messages", "tools", "tool_choice"} {
		if raw, ok := r.fields[name]; ok {
			fields[name] = raw
		}
	}
	return encodeObject(fields)
}

// Without is the request without its top-level field name.
func (r *Request) Without(name string) *Request {
	if _, ok := r.fields[name]; !ok {
		return r
	}
	out := *r
	out.fields = maps.Clone(r.fields)
	delete(out.fields, name)
	out.raw = encodeObject(out.fields)
	out.messages = sync.OnceValues(out.parseMessages)
	return &out
}

// Veiled is the request with each text VeilTexts lists rewritten by veil: its messages' texts, and each description,
// title, enum, const, default and example string of its tools. Each assistant tool call is rebuilt as its id, type,
// name and arguments, so it carries nothing else, and its arguments stay JSON: a number veil changes becomes a
// string. Tool names, ids and schema keys are left alone.
func (r *Request) Veiled(veil func(string) string) (*Request, error) {
	return r.rewrite(func(_, s string) string { return veil(s) })
}

// rewrite is the one walk of a request's text that both VeilTexts and Veiled make, so the Veil scans exactly what it
// rewrites.
func (r *Request) rewrite(veil func(role, s string) string) (*Request, error) {
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	var list bytes.Buffer
	list.WriteByte('[')
	for i, m := range msgs {
		if i > 0 {
			list.WriteByte(',')
		}
		fields := maps.Clone(m.raw)
		inRole := func(s string) string { return veil(m.Role, s) }
		if content, ok := m.raw["content"]; ok {
			if fields["content"], err = veiledContent(content, inRole); err != nil {
				return nil, err
			}
		}
		if calls := toolCallsOf(m); len(calls) > 0 {
			for j := range calls {
				calls[j].Function.Arguments = veiledArguments(calls[j].Function.Arguments, inRole)
			}
			fields["tool_calls"], _ = json.Marshal(calls)
		}
		list.Write(encodeObject(fields))
	}
	list.WriteByte(']')
	out := r.withMessages(list.Bytes())
	if tools, ok := r.fields["tools"]; ok {
		veiledTools, err := rewriteTools(tools, func(s string) string { return veil("system", s) })
		if err != nil {
			return nil, err
		}
		out.fields["tools"] = veiledTools
		out.raw = encodeObject(out.fields)
	}
	return out, nil
}

func veiledContent(content json.RawMessage, veil func(string) string) (json.RawMessage, error) {
	var text string
	if json.Unmarshal(content, &text) == nil {
		return marshalString(veil(text)), nil
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(content, &parts); err != nil {
		return nil, errMalformedMessages
	}
	for i, raw := range parts {
		if json.Unmarshal(raw, &text) == nil {
			parts[i] = marshalString(veil(text))
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, errMalformedMessages
		}
		for _, key := range []string{"text", "refusal"} {
			if json.Unmarshal(fields[key], &text) == nil {
				fields[key] = marshalString(veil(text))
			}
		}
		if file, ok := fields["file"]; ok {
			var f map[string]json.RawMessage
			if json.Unmarshal(file, &f) == nil && json.Unmarshal(f["filename"], &text) == nil {
				f["filename"] = marshalString(veil(text))
				fields["file"] = encodeObject(f)
			}
		}
		parts[i] = encodeObject(fields)
	}
	return json.Marshal(parts)
}

func veiledArguments(arguments string, veil func(string) string) string {
	out, err := rewriteJSON([]byte(arguments), true, veil)
	if err != nil {
		return veil(arguments)
	}
	return string(out)
}

// toolTextKeys are the keys of a tool definition whose string values a model reads as text.
var toolTextKeys = []string{"description", "title", "enum", "const", "default", "examples"}

func rewriteTools(tools json.RawMessage, veil func(string) string) (json.RawMessage, error) {
	var list []any
	dec := json.NewDecoder(bytes.NewReader(tools))
	dec.UseNumber()
	if err := dec.Decode(&list); err != nil {
		return nil, errMalformedMessages
	}
	for i := range list {
		list[i] = rewriteToolValue(list[i], false, veil)
	}
	return json.Marshal(list)
}

func rewriteToolValue(v any, text bool, veil func(string) string) any {
	switch x := v.(type) {
	case string:
		if text {
			return veil(x)
		}
	case []any:
		for i := range x {
			x[i] = rewriteToolValue(x[i], text, veil)
		}
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(x)) {
			x[key] = rewriteToolValue(x[key], text || slices.Contains(toolTextKeys, key), veil)
		}
	}
	return v
}

var errNotJSON = errors.New("chat: not one JSON value")

// rewriteJSON rewrites each string leaf of raw, and with keysAndNumbers each object key and each number too, in
// order, keeping every other value as it was. A number whose text changes becomes a string. Strings are written with
// no HTML escaping, so text a model reads is unchanged but where f changes it.
func rewriteJSON(raw []byte, keysAndNumbers bool, f func(string) string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out bytes.Buffer
	type frame struct {
		object bool
		n      int
	}
	var stack []frame
	values := 0
	// place writes the separator a token needs where it stands, and reports whether the token is an object's key.
	place := func() bool {
		if len(stack) == 0 {
			values++
			return false
		}
		top := &stack[len(stack)-1]
		key := top.object && top.n%2 == 0
		switch {
		case top.object && !key:
			out.WriteByte(':')
		case top.n > 0:
			out.WriteByte(',')
		}
		top.n++
		return key
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				place()
				out.WriteByte(byte(d))
				stack = append(stack, frame{object: d == '{'})
			} else {
				out.WriteByte(byte(d))
				stack = stack[:len(stack)-1]
			}
			continue
		}
		key := place()
		switch t := tok.(type) {
		case string:
			if !key || keysAndNumbers {
				t = f(t)
			}
			out.Write(marshalString(t))
		case json.Number:
			if keysAndNumbers {
				if changed := f(t.String()); changed != t.String() {
					out.Write(marshalString(changed))
					continue
				}
			}
			out.WriteString(t.String())
		case bool:
			out.WriteString(strconv.FormatBool(t))
		case nil:
			out.WriteString("null")
		}
	}
	if values != 1 || len(stack) != 0 {
		return nil, errNotJSON
	}
	return out.Bytes(), nil
}

// marshalString is s as a JSON string, with no HTML escaping.
func marshalString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
