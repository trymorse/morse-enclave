package openaicompat

import (
	"bytes"
	"encoding/json"

	"morse/backend/internal/completions"
	"morse/backend/internal/jsonx"
)

type field struct {
	name                   string
	start, valueStart, end int
}

type reply struct {
	raw     []byte
	fields  []field
	edits   map[string]json.RawMessage
	dropped map[string]bool
	choices int
	usage   *completions.Usage
}

func (p *Provider) decodeReply(object []byte) (reply, error) {
	r, ok := parseReply(object)
	if !ok {
		return reply{}, errNotAnObject
	}
	if raw, ok := r.value("choices"); ok {
		var choices []struct{}
		if err := json.Unmarshal(raw, &choices); err != nil {
			return reply{}, err
		}
		r.choices = len(choices)
	}
	raw, ok := r.value("usage")
	if !ok {
		return r, nil
	}
	if len(p.ChargeFields) > 0 && string(raw) != "null" {
		kept, err := without(raw, p.ChargeFields)
		if err != nil {
			return reply{}, err
		}
		r.set("usage", kept)
		raw = kept
	}
	if p.Bill != nil && string(raw) != "null" {
		billed, err := p.Bill(raw)
		if err != nil {
			return reply{}, err
		}
		r.set("usage", billed)
		raw = billed
	}
	if err := json.Unmarshal(raw, &r.usage); err != nil {
		return reply{}, err
	}
	return r, nil
}

func parseReply(object []byte) (reply, bool) {
	if !json.Valid(object) {
		return reply{}, false
	}
	dec := json.NewDecoder(bytes.NewReader(object))
	r := reply{raw: object}
	switch open, _ := dec.Token(); open {
	case nil:
		return r, true
	case json.Delim('{'):
	default:
		return reply{}, false
	}
	for dec.More() {
		before := int(dec.InputOffset())
		key, _ := dec.Token()
		afterKey := int(dec.InputOffset())
		var value json.RawMessage
		dec.Decode(&value)
		end := int(dec.InputOffset())
		r.fields = append(r.fields, field{
			name:       key.(string),
			start:      before + bytes.IndexByte(object[before:], '"'),
			valueStart: afterKey + bytes.Index(object[afterKey:end], value),
			end:        end,
		})
	}
	return r, true
}

func (r *reply) value(name string) (json.RawMessage, bool) {
	if r.dropped[name] {
		return nil, false
	}
	if v, ok := r.edits[name]; ok {
		return v, true
	}
	var value json.RawMessage
	found := false
	for _, f := range r.fields {
		if f.name == name {
			value, found = r.raw[f.valueStart:f.end], true
		}
	}
	return value, found
}

func (r *reply) set(name string, value json.RawMessage) {
	if r.edits == nil {
		r.edits = map[string]json.RawMessage{}
	}
	r.edits[name] = value
	delete(r.dropped, name)
}

func (r *reply) drop(name string) {
	if r.dropped == nil {
		r.dropped = map[string]bool{}
	}
	r.dropped[name] = true
	delete(r.edits, name)
}

func (r *reply) kept() []byte {
	if len(r.dropped) == 0 && len(r.edits) == 0 {
		return r.raw
	}
	out := append([]byte{}, r.raw[:r.fields[0].start]...)
	separator := false
	for _, f := range r.fields {
		if r.dropped[f.name] {
			continue
		}
		if separator {
			out = append(out, ',')
		}
		if edit, ok := r.edits[f.name]; ok {
			out = append(append(out, r.raw[f.start:f.valueStart]...), edit...)
		} else {
			out = append(out, r.raw[f.start:f.end]...)
		}
		separator = true
	}
	return append(out, r.raw[r.fields[len(r.fields)-1].end:]...)
}

func (r reply) withContent(text string) reply {
	c := reply{raw: r.raw, fields: r.fields}
	c.set("choices", jsonx.Encode([]map[string]any{{"index": 0, "delta": map[string]string{"content": text}, "finish_reason": nil}}))
	c.drop("usage")
	return c
}

func (r *reply) answer(text string) error {
	raw, _ := r.value("choices")
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choices); err != nil || len(choices) == 0 {
		return errNotAnObject
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(choices[0]["message"], &message); err != nil || message == nil {
		return errNotAnObject
	}
	message["content"] = jsonx.Encode(text)
	choices[0]["message"] = jsonx.Encode(message)
	r.set("choices", jsonx.Encode(choices))
	return nil
}

func without(usage json.RawMessage, fields []string) (json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(usage, &raw); err != nil {
		return nil, err
	}
	for _, field := range fields {
		delete(raw, field)
	}
	return jsonx.Encode(raw), nil
}
