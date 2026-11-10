package privacyveil

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ErrLeak is a body that still holds a detail its veil replaced.
var ErrLeak = errors.New("privacyveil: a veiled detail is still in the body")

// identifierKeys name values that identify rather than say, which substitution leaves alone and no check reads: ids,
// roles, types, models, and the names of tools and functions (Section 4).
var identifierKeys = map[string]bool{
	"id": true, "type": true, "role": true, "model": true, "name": true, "object": true,
	"tool_call_id": true, "tool_use_id": true, "call_id": true,
	"required": true, "$ref": true, "$schema": true, "format": true,
	"media_type": true, "mime_type": true, "mimeType": true, "detail": true,
}

// mediaKeys hold the parts a veil sends as written, which no check reads: their bytes are media, not text.
var mediaKeys = map[string]bool{
	"image_url": true, "input_audio": true, "video_url": true, "audio": true, "url": true,
	"file_data": true, "file_id": true, "fileData": true, "fileUri": true, "file_uri": true,
	"inlineData": true, "inline_data": true, "source": true,
}

// dataKeys hold a tool call's arguments or result as an object, whose keys and values are all the caller's data:
// Anthropic's input, Gemini's args and response, and an object-valued arguments.
var dataKeys = map[string]bool{"input": true, "args": true, "arguments": true, "response": true}

// HoldsJSON reports whether body, decoded as JSON, still holds a detail the veil replaced: in a string or a number,
// but in an identifier or a media part, and in every key and value of a tool call's arguments, including arguments
// written as a string of JSON, whose escapes could hide a value. A body that is not JSON is read as text.
func (v *Veil) HoldsJSON(body []byte) bool {
	if v.Empty() {
		return false
	}
	root, ok := decodeJSON(body)
	if !ok {
		return v.Holds(string(body))
	}
	return v.holdsValue(root, false)
}

func decodeJSON(b []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil || dec.More() {
		return nil, false
	}
	return root, true
}

func (v *Veil) holdsValue(x any, data bool) bool {
	switch t := x.(type) {
	case string:
		if v.Holds(t) {
			return true
		}
		if s := strings.TrimSpace(t); len(s) > 1 && (s[0] == '{' || s[0] == '[') {
			if inner, ok := decodeJSON([]byte(s)); ok {
				return v.holdsValue(inner, true)
			}
		}
	case json.Number:
		return v.Holds(t.String())
	case []any:
		for _, e := range t {
			if v.holdsValue(e, data) {
				return true
			}
		}
	case map[string]any:
		for k, e := range t {
			switch {
			case data:
				if v.Holds(k) || v.holdsValue(e, true) {
					return true
				}
			case identifierKeys[k], mediaKeys[k]:
			case dataKeys[k]:
				if v.holdsValue(e, true) {
					return true
				}
			default:
				if v.holdsValue(e, false) {
					return true
				}
			}
		}
	}
	return false
}

// Egress is a check for a body about to leave: ErrLeak when it holds a detail.
func (v *Veil) Egress(body []byte) error {
	if v.HoldsJSON(body) {
		return ErrLeak
	}
	return nil
}
