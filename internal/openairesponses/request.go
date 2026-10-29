package openairesponses

import (
	"encoding/json"

	"morse/backend/internal/completions"
)

const (
	minOutputTokens  = 16
	phaseCommentary  = "commentary"
	phaseFinalAnswer = "final_answer"
)

type request struct {
	Model             string     `json:"model"`
	Input             []any      `json:"input"`
	Tools             []tool     `json:"tools,omitempty"`
	ToolChoice        any        `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool      `json:"parallel_tool_calls,omitempty"`
	Reasoning         *reasoning `json:"reasoning,omitempty"`
	MaxOutputTokens   int        `json:"max_output_tokens"`
	Store             bool       `json:"store"`
	Stream            bool       `json:"stream"`
}

type reasoning struct {
	Effort string `json:"effort"`
}

type tool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      bool            `json:"strict"`
}

type namedFunction struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type messageItem struct {
	Type    string `json:"type"`
	Role    string `json:"role"`
	Phase   string `json:"phase,omitempty"`
	Content any    `json:"content"`
}

type inputPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type functionCallItem struct {
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type functionCallOutputItem struct {
	Type   string `json:"type"`
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

func newRequest(conv completions.Conversation, model string) request {
	out := request{
		Model:             model,
		Input:             inputItems(conv.Turns),
		Tools:             tools(conv.Tools),
		ToolChoice:        toolChoice(conv.Choice),
		ParallelToolCalls: conv.Parallel,
		MaxOutputTokens:   max(conv.OutputLimit, minOutputTokens),
		Stream:            true,
	}
	if conv.ForwardedEffort != "" {
		out.Reasoning = &reasoning{Effort: conv.ForwardedEffort}
	}
	return out
}

func tools(defs []completions.Tool) []tool {
	var out []tool
	for _, def := range defs {
		out = append(out, tool{Type: "function", Name: def.Name, Description: def.Description, Parameters: def.Parameters})
	}
	return out
}

func toolChoice(c *completions.Choice) any {
	switch {
	case c == nil:
		return nil
	case c.Mode == completions.ChoiceFunction:
		return namedFunction{Type: "function", Name: c.Name}
	}
	return c.Mode
}

func inputItems(turns []completions.Turn) []any {
	items := []any{}
	for _, t := range turns {
		switch t.Role {
		case completions.System:
			items = append(items, messageItem{Type: "message", Role: "developer", Content: t.Text})
		case completions.User:
			items = append(items, messageItem{Type: "message", Role: "user", Content: inputParts(t.Parts)})
		case completions.Assistant:
			if t.Text != "" {
				phase := phaseFinalAnswer
				if len(t.Calls) > 0 {
					phase = phaseCommentary
				}
				items = append(items, messageItem{Type: "message", Role: "assistant", Phase: phase, Content: t.Text})
			}
			for _, call := range t.Calls {
				items = append(items, functionCallItem{Type: "function_call", CallID: call.ID, Name: call.Function.Name, Arguments: call.Function.Arguments})
			}
		case completions.ToolResult:
			items = append(items, functionCallOutputItem{Type: "function_call_output", CallID: t.CallID, Output: t.Text})
		}
	}
	return items
}

func inputParts(parts []completions.Part) []inputPart {
	out := make([]inputPart, 0, len(parts))
	for _, part := range parts {
		if part.Image == nil {
			out = append(out, inputPart{Type: "input_text", Text: part.Text})
			continue
		}
		out = append(out, inputPart{Type: "input_image", ImageURL: part.Image.URL.String(), Detail: part.Image.Detail})
	}
	return out
}
