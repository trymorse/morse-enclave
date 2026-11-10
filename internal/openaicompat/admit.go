package openaicompat

import (
	"encoding/json"
	"fmt"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

var (
	errServerTool = fmt.Errorf("%w: only function tools are supported", apierr.ErrMalformedRequest)
	errPart       = fmt.Errorf("%w: only text and inline image parts are supported", apierr.ErrMalformedRequest)
	errNameless   = fmt.Errorf("%w: a function tool and a tool_choice function need a name", apierr.ErrMalformedRequest)
	admittedParts = []string{"text", "image_url"}
)

// NamedFunctions refuses a function tool, or a tool_choice function, whose name a host would read as empty, which
// no host sends: a host that echoes the name it was told to call answers it with a nameless call, and the relay
// counts that as the host's fault, so any caller could trip a circuit every other caller shares. It reads keys by
// their exact spelling, the last of two equal keys winning, as a host does, and refuses any shape it cannot read.
func NamedFunctions(call chat.Call) error {
	var tools []json.RawMessage
	if call.Decode("tools", &tools) != nil {
		return errNameless
	}
	for _, raw := range tools {
		tool, ok := object(raw)
		if !ok {
			return errNameless
		}
		var typ string
		if raw, has := tool["type"]; has && json.Unmarshal(raw, &typ) != nil {
			return errNameless
		}
		if _, has := tool["function"]; (has || typ == "function") && !named(tool["function"]) {
			return errNameless
		}
	}
	var choice json.RawMessage
	if call.Decode("tool_choice", &choice) != nil {
		return errNameless
	}
	if c, ok := object(choice); ok {
		if fn, has := c["function"]; has && !named(fn) {
			return errNameless
		}
	} else if len(choice) > 0 && choice[0] != '"' && string(choice) != "null" {
		return errNameless
	}
	return nil
}

func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	return fields, true
}

func named(function json.RawMessage) bool {
	fields, ok := object(function)
	if !ok {
		return false
	}
	var name string
	return json.Unmarshal(fields["name"], &name) == nil && name != ""
}

// FunctionToolsTextAndImages refuses a call with a tool that is not a function, or a message part that is not text
// or an inline image: a vendor that runs its own tools and reads files on other services takes no other call.
func FunctionToolsTextAndImages(call chat.Call) error {
	var tools []struct {
		Type string `json:"type"`
	}
	if call.Decode("tools", &tools) != nil {
		return errServerTool
	}
	for _, tool := range tools {
		if tool.Type != "function" {
			return errServerTool
		}
	}
	var choice struct {
		Type *string `json:"type"`
	}
	if call.Decode("tool_choice", &choice) == nil && choice.Type != nil && *choice.Type != "function" {
		return errServerTool
	}
	msgs, err := call.Messages()
	if err != nil {
		return err
	}
	for _, m := range msgs {
		for _, part := range m.Parts() {
			if !slices.Contains(admittedParts, part.Type) && (part.Type != "" || part.Text == nil) {
				return errPart
			}
		}
	}
	return nil
}
