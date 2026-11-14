package responses

import (
	"encoding/json"
	"fmt"
	"strings"
)

type item struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	CallID    string          `json:"call_id"`
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Arguments *string         `json:"arguments"`
	Input     *string         `json:"input"`
	Output    json.RawMessage `json:"output"`
}

type contentPart struct {
	Type     string  `json:"type"`
	Text     *string `json:"text"`
	Refusal  *string `json:"refusal"`
	ImageURL string  `json:"image_url"`
	FileID   string  `json:"file_id"`
	Detail   string  `json:"detail"`
}

// A tool call item joins the assistant message before it, since Chat Completions carries a turn's calls on its
// assistant message.
type conversation struct {
	out     []map[string]any
	calling map[string]any
}

func conversationOf(instructions, input json.RawMessage) ([]map[string]any, error) {
	var c conversation
	if !null(instructions) {
		var text string
		if json.Unmarshal(instructions, &text) != nil {
			return nil, invalid("instructions", "instructions must be a string.")
		}
		c.add(map[string]any{"role": "system", "content": text})
	}
	if null(input) {
		return nil, invalid("input", "Missing required parameter: 'input'.")
	}
	var text string
	if json.Unmarshal(input, &text) == nil {
		c.add(map[string]any{"role": "user", "content": text})
		return c.out, nil
	}
	var items []item
	if json.Unmarshal(input, &items) != nil {
		return nil, invalid("input", "input must be a string or an array of input items.")
	}
	for i, it := range items {
		if err := c.item(it, fmt.Sprintf("input[%d]", i)); err != nil {
			return nil, err
		}
	}
	return c.out, nil
}

func (c *conversation) add(m map[string]any) {
	c.out = append(c.out, m)
	c.calling = nil
	if m["role"] == "assistant" {
		c.calling = m
	}
}

func (c *conversation) item(it item, at string) error {
	switch it.Type {
	case "message", "":
		return c.message(it, at)
	case "reasoning":
		return nil
	case "function_call":
		if it.Arguments == nil {
			return invalid(at+".arguments", "Missing required parameter: 'arguments'.")
		}
		return c.call(it, at, *it.Arguments)
	case "custom_tool_call":
		if it.Input == nil {
			return invalid(at+".input", "Missing required parameter: 'input'.")
		}
		arguments, _ := json.Marshal(map[string]string{"input": *it.Input})
		return c.call(it, at, string(arguments))
	case "function_call_output", "custom_tool_call_output":
		return c.output(it, at)
	case "item_reference":
		return unsupported(at, "item_reference is not supported: Morse keeps no items to refer to. Send the item itself.")
	}
	return unsupported(at+".type", fmt.Sprintf("An input item of type %s is not supported: Morse takes message, function_call, function_call_output, custom_tool_call, custom_tool_call_output, and reasoning items.", it.Type))
}

func (c *conversation) call(it item, at, arguments string) error {
	if it.CallID == "" || it.Name == "" {
		return invalid(at, "A tool call item needs a call_id and a name.")
	}
	if c.calling == nil {
		c.add(map[string]any{"role": "assistant", "content": nil})
	}
	calls, _ := c.calling["tool_calls"].([]any)
	name := it.Name
	if it.Namespace != "" {
		name = qualified{namespace: it.Namespace, name: it.Name}.flat()
	}
	c.calling["tool_calls"] = append(calls, map[string]any{"id": it.CallID, "type": "function", "function": map[string]string{"name": name, "arguments": arguments}})
	return nil
}

func (c *conversation) output(it item, at string) error {
	if it.CallID == "" {
		return invalid(at+".call_id", "Missing required parameter: 'call_id'.")
	}
	var text string
	if json.Unmarshal(it.Output, &text) != nil {
		parts, err := partsOf(it.Output, at+".output")
		if err != nil {
			return err
		}
		texts := make([]string, 0, len(parts))
		for i, p := range parts {
			if p.Type != "input_text" && p.Type != "output_text" || p.Text == nil {
				return unsupported(fmt.Sprintf("%s.output[%d]", at, i), fmt.Sprintf("A tool output part of type %s is not supported: Morse takes text in a tool output. Send an image in a user message.", p.Type))
			}
			texts = append(texts, *p.Text)
		}
		text = strings.Join(texts, "\n\n")
	}
	c.add(map[string]any{"role": "tool", "tool_call_id": it.CallID, "content": text})
	return nil
}

func partsOf(raw json.RawMessage, at string) ([]contentPart, error) {
	var parts []contentPart
	if null(raw) || json.Unmarshal(raw, &parts) != nil {
		return nil, invalid(at, "Content must be a string or an array of content parts.")
	}
	return parts, nil
}

var roles = map[string]string{"user": "user", "assistant": "assistant", "system": "system", "developer": "system"}

func (c *conversation) message(it item, at string) error {
	role, ok := roles[it.Role]
	if !ok {
		return invalid(at+".role", "role must be one of user, assistant, system, and developer.")
	}
	var text string
	if json.Unmarshal(it.Content, &text) == nil {
		c.text(role, text)
		return nil
	}
	parts, err := partsOf(it.Content, at+".content")
	if err != nil {
		return err
	}
	if role != "user" {
		texts := make([]string, 0, len(parts))
		for i, p := range parts {
			switch {
			case p.Type == "refusal" && p.Refusal != nil:
				texts = append(texts, *p.Refusal)
			case (p.Type == "input_text" || p.Type == "output_text") && p.Text != nil:
				texts = append(texts, *p.Text)
			default:
				return unsupported(fmt.Sprintf("%s.content[%d]", at, i), fmt.Sprintf("A %s message part of type %s is not supported: Morse takes text in a %s message.", it.Role, p.Type, it.Role))
			}
		}
		c.text(role, strings.Join(texts, ""))
		return nil
	}
	out := make([]any, 0, len(parts))
	for i, p := range parts {
		where := fmt.Sprintf("%s.content[%d]", at, i)
		switch p.Type {
		case "input_text":
			if p.Text == nil {
				return invalid(where+".text", "Missing required parameter: 'text'.")
			}
			out = append(out, map[string]any{"type": "text", "text": *p.Text})
		case "input_image":
			image, err := imageOf(p, where)
			if err != nil {
				return err
			}
			out = append(out, image)
		default:
			return unsupported(where, fmt.Sprintf("A user message part of type %s is not supported: Morse takes input_text and input_image (as a base64 data URL).", p.Type))
		}
	}
	c.add(map[string]any{"role": "user", "content": out})
	return nil
}

func (c *conversation) text(role, text string) {
	if role == "assistant" && c.calling != nil && c.calling["content"] == nil {
		c.calling["content"] = text
		return
	}
	c.add(map[string]any{"role": role, "content": text})
}

func imageOf(p contentPart, at string) (any, error) {
	switch {
	case p.FileID != "":
		return nil, unsupported(at+".file_id", "An image by file_id is not supported: Morse keeps no files. Attach the image as a base64 data URL in image_url.")
	case !strings.HasPrefix(p.ImageURL, "data:"):
		return nil, unsupported(at+".image_url", "An image linked by URL is not supported: attach the image as a base64 data URL.")
	}
	image := map[string]string{"url": p.ImageURL}
	if p.Detail != "" {
		image["detail"] = p.Detail
	}
	return map[string]any{"type": "image_url", "image_url": image}, nil
}
