package openairesponses

import (
	"encoding/json"

	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
)

const (
	minOutputTokens  = 16
	phaseCommentary  = "commentary"
	phaseFinalAnswer = "final_answer"
	summaryAuto      = "auto"
	itemReasoning    = "reasoning"
	itemMessage      = "message"
	layoutReasoning  = 'r'
	layoutMessage    = 'm'
	layoutCall       = 'f'
)

type request struct {
	Model             string     `json:"model"`
	Input             []any      `json:"input"`
	Tools             []tool     `json:"tools,omitempty"`
	ToolChoice        any        `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool      `json:"parallel_tool_calls,omitempty"`
	Reasoning         *reasoning `json:"reasoning,omitempty"`
	MaxOutputTokens   int        `json:"max_output_tokens"`
	Store             unstored   `json:"store"`
	Stream            bool       `json:"stream"`
}

type unstored struct{}

func (unstored) MarshalJSON() ([]byte, error) { return []byte("false"), nil }

type reasoning struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
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
		Input:             inputItems(conv, model),
		Tools:             tools(conv.Tools),
		ToolChoice:        toolChoice(conv.Choice),
		ParallelToolCalls: conv.Parallel,
		MaxOutputTokens:   max(conv.OutputLimit, minOutputTokens),
		Stream:            true,
	}
	if conv.ForwardedEffort != "" {
		out.Reasoning = &reasoning{Effort: conv.ForwardedEffort}
	}
	if conv.ReasoningView.Summarizes() && conv.ForwardedEffort != chat.NoEffort {
		out.Reasoning = &reasoning{Effort: conv.ForwardedEffort, Summary: summaryAuto}
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

func inputItems(conv completions.Conversation, model string) []any {
	items := []any{}
	for _, t := range conv.Turns {
		switch t.Role {
		case completions.System:
			items = append(items, messageItem{Type: "message", Role: "developer", Content: t.Text})
		case completions.User:
			items = append(items, messageItem{Type: "message", Role: "user", Content: inputParts(t.Parts)})
		case completions.Assistant:
			items = append(items, assistantItems(conv, t, model)...)
		case completions.ToolResult:
			items = append(items, functionCallOutputItem{Type: "function_call_output", CallID: t.CallID, Output: t.Text})
		}
	}
	return items
}

func assistantItems(conv completions.Conversation, t completions.Turn, model string) []any {
	var said []any
	if t.Text != "" {
		phase := phaseFinalAnswer
		if len(t.Calls) > 0 {
			phase = phaseCommentary
		}
		said = append(said, messageItem{Type: "message", Role: "assistant", Phase: phase, Content: t.Text})
	}
	for _, call := range t.Calls {
		said = append(said, functionCallItem{Type: "function_call", CallID: call.ID, Name: call.Function.Name, Arguments: call.Function.Arguments})
	}
	state, ok := conv.StateOf(t, model)
	if !ok {
		return said
	}
	return withReasoning(said, state)
}

// why: OpenAI takes a response's output items back in their original order
// (https://developers.openai.com/api/docs/guides/reasoning), so a reasoning item goes ahead of the item it preceded.
func withReasoning(said []any, state completions.ReasoningState) []any {
	reasoned := state.Items
	out := make([]any, 0, len(said)+len(reasoned))
	var ahead []json.RawMessage
	for _, kind := range state.Layout {
		if kind == layoutReasoning {
			if len(reasoned) > 0 {
				ahead, reasoned = append(ahead, reasoned[0]), reasoned[1:]
			}
			continue
		}
		if len(said) == 0 {
			break
		}
		for _, item := range ahead {
			if replayable(item) {
				out = append(out, item)
			}
		}
		ahead = nil
		out, said = append(out, said[0]), said[1:]
	}
	return append(out, said...)
}

func replayable(item json.RawMessage) bool {
	var read struct {
		Type             string          `json:"type"`
		EncryptedContent string          `json:"encrypted_content"`
		Content          json.RawMessage `json:"content"`
	}
	if json.Unmarshal(item, &read) != nil || read.Type != itemReasoning || read.EncryptedContent == "" {
		return false
	}
	var content []json.RawMessage
	return len(read.Content) == 0 || json.Unmarshal(read.Content, &content) == nil && len(content) == 0
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
