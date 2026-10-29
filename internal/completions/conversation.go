package completions

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dataurl"
	"morse/backend/internal/jsonx"
)

var (
	errUnsupportedMessage = fmt.Errorf("%w: only text, inline base64 image, tool call, and tool result messages with system, developer, user, assistant, or tool roles are supported", apierr.ErrMalformedRequest)
	errUnsupportedTool    = fmt.Errorf("%w: only function tools with an object schema and a known tool_choice are supported", apierr.ErrMalformedRequest)
)

const (
	EmptyArguments = "{}"
	defaultDetail  = "auto"
	openingTurn    = "(The conversation begins.)"
)

var (
	imageMediaTypes = []string{"image/jpeg", "image/png", "image/gif", "image/webp"}
	imageDetails    = []string{"auto", "low", "high"}
	choiceModes     = []string{ChoiceAuto, ChoiceNone, ChoiceRequired}
)

type Role uint8

const (
	System Role = iota
	User
	Assistant
	ToolResult
)

type Image struct {
	dataurl.URL
	Detail string
}

type Part struct {
	Text  string
	Image *Image
}

type Turn struct {
	Role   Role
	Text   string
	Parts  []Part
	Calls  []ToolCall
	CallID string
}

type Tool struct {
	Name        string
	Description string
	Parameters  json.RawMessage
}

// Schema is the tool's parameters as the object schema a vendor requires even of a tool that takes none.
func (t Tool) Schema() json.RawMessage {
	fields := map[string]json.RawMessage{}
	json.Unmarshal(t.Parameters, &fields)
	fields["type"] = json.RawMessage(`"object"`)
	return jsonx.Encode(fields)
}

const (
	ChoiceAuto     = "auto"
	ChoiceNone     = "none"
	ChoiceRequired = "required"
	ChoiceFunction = "function"
)

type Choice struct {
	Mode string
	Name string
}

type Conversation struct {
	Turns       []Turn
	Tools       []Tool
	Choice      *Choice
	Parallel    *bool
	OutputLimit int
	// Effort is the effort the call asks for, and ForwardedEffort the one the vendor accepts nearest to it, or
	// "" when it accepts none at or around it.
	Effort          string
	ForwardedEffort string
}

// Exchange is one side's consecutive turns, which a vendor whose roles must alternate takes as one message.
type Exchange struct {
	FromModel bool
	Turns     []Turn
}

// Alternating lifts the system text out and groups the rest into exchanges that alternate. The user's is always
// first: a conversation the user did not open, or one with no turn but system text, opens on a stand-in user turn.
func (c Conversation) Alternating() (system []string, exchanges []Exchange) {
	for _, t := range c.Turns {
		if t.Role == System {
			system = append(system, t.Text)
			continue
		}
		fromModel := t.Role == Assistant
		if last := len(exchanges) - 1; last >= 0 && exchanges[last].FromModel == fromModel {
			exchanges[last].Turns = append(exchanges[last].Turns, t)
			continue
		}
		exchanges = append(exchanges, Exchange{FromModel: fromModel, Turns: []Turn{t}})
	}
	if len(exchanges) == 0 || exchanges[0].FromModel {
		opening := Exchange{Turns: []Turn{{Role: User, Parts: []Part{{Text: openingTurn}}}}}
		exchanges = slices.Insert(exchanges, 0, opening)
	}
	return system, exchanges
}

func parseConversation(c chat.Call) (Conversation, error) {
	var (
		defs       []functionTool
		toolChoice json.RawMessage
		parallel   *bool
	)
	if c.Decode("tools", &defs) != nil || c.Decode("tool_choice", &toolChoice) != nil || c.Decode("parallel_tool_calls", &parallel) != nil {
		return Conversation{}, apierr.ErrMalformedRequest
	}
	msgs, err := c.Messages()
	if err != nil {
		return Conversation{}, err
	}
	conv := Conversation{Parallel: parallel, OutputLimit: c.OutputLimit, Effort: c.Effort()}
	conv.ForwardedEffort, _ = c.ForwardedEffort()
	if conv.Tools, err = tools(defs); err != nil {
		return Conversation{}, err
	}
	if conv.Choice, err = choice(toolChoice); err != nil {
		return Conversation{}, err
	}
	for _, m := range msgs {
		turn, err := parseTurn(m)
		if err != nil {
			return Conversation{}, err
		}
		if turn.Role == ToolResult || turn.Text != "" || len(turn.Parts) > 0 || len(turn.Calls) > 0 {
			conv.Turns = append(conv.Turns, turn)
		}
	}
	return conv, nil
}

func parseTurn(m chat.Message) (Turn, error) {
	if m.Role == "user" {
		parts, err := userParts(m)
		return Turn{Role: User, Parts: parts}, err
	}
	text, ok := m.Text()
	if !ok {
		return Turn{}, errUnsupportedMessage
	}
	switch m.Role {
	case "system", "developer":
		return Turn{Role: System, Text: text}, nil
	case "assistant":
		calls, err := toolCalls(m.ToolCalls())
		return Turn{Role: Assistant, Text: text, Calls: calls}, err
	case "tool":
		var id string
		if json.Unmarshal(m.ToolCallID(), &id) != nil || id == "" {
			return Turn{}, errUnsupportedMessage
		}
		return Turn{Role: ToolResult, Text: text, CallID: id}, nil
	}
	return Turn{}, errUnsupportedMessage
}

func tools(defs []functionTool) ([]Tool, error) {
	var out []Tool
	for _, def := range defs {
		parameters, ok := objectSchema(def.Function.Parameters)
		if def.Type != "function" || def.Function.Name == "" || !ok {
			return nil, errUnsupportedTool
		}
		out = append(out, Tool{Name: def.Function.Name, Description: def.Function.Description, Parameters: parameters})
	}
	return out, nil
}

func objectSchema(parameters json.RawMessage) (json.RawMessage, bool) {
	if len(parameters) == 0 || string(parameters) == "null" {
		return nil, true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(parameters, &fields) != nil || fields == nil {
		return nil, false
	}
	typ, ok := fields["type"]
	return parameters, !ok || string(typ) == `"object"`
}

func choice(raw json.RawMessage) (*Choice, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var mode string
	if json.Unmarshal(raw, &mode) == nil {
		if !slices.Contains(choiceModes, mode) {
			return nil, errUnsupportedTool
		}
		return &Choice{Mode: mode}, nil
	}
	var typ, name string
	var function json.RawMessage
	if decodeKnown(raw, map[string]any{"type": &typ, "function": &function}) != nil ||
		decodeKnown(function, map[string]any{"name": &name}) != nil || typ != ChoiceFunction || name == "" {
		return nil, errUnsupportedTool
	}
	return &Choice{Mode: ChoiceFunction, Name: name}, nil
}

func toolCalls(raw json.RawMessage) ([]ToolCall, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var objects []json.RawMessage
	if json.Unmarshal(raw, &objects) != nil {
		return nil, errUnsupportedMessage
	}
	calls := make([]ToolCall, 0, len(objects))
	for _, object := range objects {
		var call ToolCall
		var function json.RawMessage
		if decodeKnown(object, map[string]any{"id": &call.ID, "type": &call.Type, "function": &function}) != nil ||
			decodeKnown(function, map[string]any{"name": &call.Function.Name, "arguments": &call.Function.Arguments}) != nil {
			return nil, errUnsupportedMessage
		}
		if strings.TrimSpace(call.Function.Arguments) == "" {
			call.Function.Arguments = EmptyArguments
		}
		if call.Type != "function" || call.ID == "" || call.Function.Name == "" || !json.Valid([]byte(call.Function.Arguments)) {
			return nil, errUnsupportedMessage
		}
		calls = append(calls, call)
	}
	return calls, nil
}

func userParts(m chat.Message) ([]Part, error) {
	if text, ok := m.Text(); ok {
		return textParts(text), nil
	}
	var out []Part
	for _, part := range m.Parts() {
		switch {
		case part.Type == "text" && part.Text != nil:
			out = append(out, textParts(*part.Text)...)
		case part.Type == "image_url":
			image, ok := inlineImage(part.ImageURL())
			if !ok {
				return nil, errUnsupportedMessage
			}
			out = append(out, Part{Image: &image})
		default:
			return nil, errUnsupportedMessage
		}
	}
	return out, nil
}

func textParts(text string) []Part {
	if text == "" {
		return nil
	}
	return []Part{{Text: text}}
}

func inlineImage(ref json.RawMessage) (Image, bool) {
	detail := defaultDetail
	if json.Unmarshal(ref, new(string)) != nil && decodeKnown(ref, map[string]any{"detail": &detail}) != nil {
		return Image{}, false
	}
	image, err := dataurl.Parse(chat.PartURL(ref))
	if err != nil || !slices.Contains(imageMediaTypes, image.MediaType) || !slices.Contains(imageDetails, detail) {
		return Image{}, false
	}
	return Image{URL: image, Detail: detail}, true
}

func decodeKnown(raw json.RawMessage, into map[string]any) error {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for name, target := range into {
		if value, ok := fields[name]; ok {
			if err := json.Unmarshal(value, target); err != nil {
				return err
			}
		}
	}
	return nil
}
