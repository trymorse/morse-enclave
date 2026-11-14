package dialect

import (
	"encoding/json"

	"morse/backend/internal/chat"
)

// View is what an encoder reads of a Chat Completions chunk or whole reply: each choice's delta or message, and its
// finish reason.
type View struct {
	Choices []struct {
		Delta   *Part  `json:"delta"`
		Message *Part  `json:"message"`
		Finish  string `json:"finish_reason"`
	} `json:"choices"`
}

type Part struct {
	Content          *string    `json:"content"`
	Refusal          *string    `json:"refusal"`
	ReasoningContent *string    `json:"reasoning_content"`
	Reasoning        *string    `json:"reasoning"`
	ToolCalls        []ToolCall `json:"tool_calls"`
}

type ToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ReasoningText is the part's reasoning, under either name a host streams it as.
func (p *Part) ReasoningText() string {
	switch {
	case p.ReasoningContent != nil:
		return *p.ReasoningContent
	case p.Reasoning != nil:
		return *p.Reasoning
	}
	return ""
}

// Text is the part's answer, a refusal included.
func (p *Part) Text() string {
	text := ""
	if p.Content != nil {
		text = *p.Content
	}
	if p.Refusal != nil {
		text += *p.Refusal
	}
	return text
}

func ViewOf(c chat.Chunk) View {
	var v View
	json.Unmarshal(chunkBytes(c), &v)
	return v
}
