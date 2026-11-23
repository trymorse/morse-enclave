package near

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

// why: NEAR's v3 labels only a tool's name, description, and parameters and a call's name and arguments
// (nearai/inference-proxy docs/e2ee.md), so a client's sealed body and a body the worker seals for a key both keep to
// these shapes, and any other field would reach NEAR in the clear.
var (
	ToolTurnKeys = map[string]bool{"role": true, "content": true, "tool_call_id": true}
	CallingKeys  = map[string]bool{"role": true, "content": true, "tool_calls": true}
	toolChoices  = []string{"auto", "none", "required"}
	callID       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	toolFields   = map[string]string{"name": LabelToolName, "description": LabelToolDescription, "parameters": LabelToolParameters}
	callFields   = map[string]string{"name": LabelCallName, "arguments": LabelCallArguments}
	errNotTools  = errors.New("near: not a list of functions with only a name, a description, and parameters")
	errNotCalls  = errors.New("near: not a list of function calls with only an id, a name, and arguments")
)

type Value func(label string, raw json.RawMessage) bool

type FieldSealer func(label string, plaintext []byte) (string, error)

func Plain(label string, raw json.RawMessage) bool {
	if label == LabelToolParameters {
		var object map[string]json.RawMessage
		return json.Unmarshal(raw, &object) == nil && object != nil
	}
	var s string
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil
}

func IsToolChoice(raw json.RawMessage) bool {
	var choice string
	return json.Unmarshal(raw, &choice) == nil && slices.Contains(toolChoices, choice)
}

func IsCallID(raw json.RawMessage) bool {
	var id string
	return json.Unmarshal(raw, &id) == nil && callID.MatchString(id)
}

func Tools(raw json.RawMessage, value Value) bool {
	tools, ok := listOf(raw)
	for _, tool := range tools {
		fn, shaped := toolFunction(tool)
		if !shaped || !hasFields(fn, toolFields, value) || fn["name"] == nil {
			return false
		}
	}
	return ok
}

func Calls(raw json.RawMessage, value Value) bool {
	calls, ok := listOf(raw)
	for _, call := range calls {
		fn, shaped := callFunction(call)
		if !shaped || !hasFields(fn, callFields, value) || fn["name"] == nil || fn["arguments"] == nil {
			return false
		}
	}
	return ok
}

func SealTools(raw json.RawMessage, seal FieldSealer) (json.RawMessage, error) {
	tools, ok := listOf(raw)
	if !ok {
		return nil, errNotTools
	}
	out := make([]map[string]any, len(tools))
	for i, tool := range tools {
		fn, shaped := toolFunction(tool)
		if !shaped {
			return nil, errNotTools
		}
		sealed, err := sealFields(fn, toolFields, seal)
		if err != nil {
			return nil, err
		}
		out[i] = map[string]any{"type": "function", "function": sealed}
	}
	return json.Marshal(out)
}

func SealCalls(raw json.RawMessage, seal FieldSealer) (json.RawMessage, error) {
	calls, ok := listOf(raw)
	if !ok {
		return nil, errNotCalls
	}
	out := make([]map[string]any, len(calls))
	for i, call := range calls {
		fn, shaped := callFunction(call)
		if !shaped {
			return nil, errNotCalls
		}
		sealed, err := sealFields(fn, callFields, seal)
		if err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		json.Unmarshal(call, &fields)
		out[i] = map[string]any{"id": fields["id"], "type": "function", "function": sealed}
	}
	return json.Marshal(out)
}

func toolFunction(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	fields, shaped := objectOf(raw, "type", "function")
	if !shaped || string(fields["type"]) != `"function"` {
		return nil, false
	}
	return objectOf(fields["function"], "name", "description", "parameters")
}

func callFunction(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	fields, shaped := objectOf(raw, "id", "type", "function")
	if !shaped || string(fields["type"]) != `"function"` || !IsCallID(fields["id"]) {
		return nil, false
	}
	return objectOf(fields["function"], "name", "arguments")
}

func hasFields(fn map[string]json.RawMessage, labels map[string]string, value Value) bool {
	for key, raw := range fn {
		if !value(labels[key], raw) {
			return false
		}
	}
	return true
}

func sealFields(fn map[string]json.RawMessage, labels map[string]string, seal FieldSealer) (map[string]string, error) {
	sealed := make(map[string]string, len(fn))
	for key, raw := range fn {
		label := labels[key]
		if !Plain(label, raw) {
			return nil, errors.New("near: " + label + " is not plaintext of its kind")
		}
		plaintext := []byte(raw)
		if label != LabelToolParameters {
			var text string
			json.Unmarshal(raw, &text)
			plaintext = []byte(text)
		}
		var err error
		if sealed[key], err = seal(label, plaintext); err != nil {
			return nil, err
		}
	}
	return sealed, nil
}

func objectOf(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return nil, false
		}
	}
	return fields, true
}

func listOf(raw json.RawMessage) ([]json.RawMessage, bool) {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return nil, false
	}
	return list, true
}
