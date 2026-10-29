package openaicompat

import (
	"fmt"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

var (
	errServerTool = fmt.Errorf("%w: only function tools are supported", apierr.ErrMalformedRequest)
	errPart       = fmt.Errorf("%w: only text and inline image parts are supported", apierr.ErrMalformedRequest)
	admittedParts = []string{"text", "image_url"}
)

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
