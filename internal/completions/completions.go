package completions

import (
	"cmp"
	"encoding/json"
	"strings"
	"time"

	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
)

type Finish string

const (
	FinishStop          Finish = "stop"
	FinishToolCalls     Finish = "tool_calls"
	FinishLength        Finish = "length"
	FinishContentFilter Finish = "content_filter"
)

type functionTool struct {
	Type     string
	Function struct {
		Name        string
		Description string
		Parameters  json.RawMessage
	}
}

func (t *functionTool) UnmarshalJSON(raw []byte) error {
	var function json.RawMessage
	if err := decodeKnown(raw, map[string]any{"type": &t.Type, "function": &function}); err != nil {
		return err
	}
	return decodeKnown(function, map[string]any{"name": &t.Function.Name, "description": &t.Function.Description, "parameters": &t.Function.Parameters})
}

type FunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

type ToolCall struct {
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function FunctionCall `json:"function"`
}

type toolCallDelta struct {
	Index int `json:"index"`
	ToolCall
}

type delta struct {
	Role      string          `json:"role,omitempty"`
	Content   *string         `json:"content,omitempty"`
	Refusal   *string         `json:"refusal,omitempty"`
	ToolCalls []toolCallDelta `json:"tool_calls,omitempty"`
}

func toolDelta(index int, call ToolCall) delta {
	return delta{ToolCalls: []toolCallDelta{{Index: index, ToolCall: call}}}
}

type reply struct {
	text    strings.Builder
	refusal strings.Builder
	calls   []ToolCall
	finish  Finish
}

func (r *reply) add(d delta, finish *Finish) error {
	if d.Content != nil {
		r.text.WriteString(*d.Content)
	}
	if d.Refusal != nil {
		r.refusal.WriteString(*d.Refusal)
	}
	for _, c := range d.ToolCalls {
		if c.Index == len(r.calls) {
			r.calls = append(r.calls, ToolCall{ID: c.ID, Type: c.Type, Function: FunctionCall{Name: c.Function.Name}})
		}
		r.calls[c.Index].Function.Arguments += c.Function.Arguments
	}
	if finish != nil {
		r.finish = *finish
	}
	return nil
}

type chunkChoice struct {
	Index        int     `json:"index"`
	Delta        delta   `json:"delta"`
	FinishReason *Finish `json:"finish_reason"`
}

type message struct {
	Role      string     `json:"role"`
	Content   *string    `json:"content"`
	Refusal   *string    `json:"refusal,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

type completionChoice struct {
	Index        int     `json:"index"`
	Message      message `json:"message"`
	FinishReason Finish  `json:"finish_reason"`
}

type promptDetails struct {
	CachedTokens     int `json:"cached_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens,omitempty"`
}

type completionDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

type Usage struct {
	PromptTokens            int                `json:"prompt_tokens"`
	CompletionTokens        int                `json:"completion_tokens"`
	TotalTokens             int                `json:"total_tokens"`
	PromptTokensDetails     *promptDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *completionDetails `json:"completion_tokens_details,omitempty"`
	// OutputTokensDetails is where Fireworks reports reasoning tokens, in place of completion_tokens_details. It is
	// read, never written.
	OutputTokensDetails *completionDetails `json:"output_tokens_details,omitempty"`
}

func (u Usage) Domain() chat.Usage {
	out := chat.Usage{PromptTokens: u.PromptTokens, CompletionTokens: u.CompletionTokens}
	if d := u.PromptTokensDetails; d != nil {
		out.CachedPromptTokens, out.CacheWritePromptTokens = d.CachedTokens, d.CacheWriteTokens
	}
	if d := cmp.Or(u.CompletionTokensDetails, u.OutputTokensDetails); d != nil {
		out.ReasoningTokens = max(d.ReasoningTokens, 0)
	}
	return out
}

func wireUsage(u chat.Usage, detailed bool) *Usage {
	out := &Usage{PromptTokens: u.PromptTokens, CompletionTokens: u.CompletionTokens, TotalTokens: u.PromptTokens + u.CompletionTokens}
	if detailed {
		out.PromptTokensDetails = &promptDetails{CachedTokens: u.CachedPromptTokens}
		out.CompletionTokensDetails = &completionDetails{u.ReasoningTokens}
	}
	return out
}

type envelope struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
}

func newEnvelope(model string) envelope {
	return envelope{ID: chat.NewReplyID(), Created: time.Now().Unix(), Model: model}
}

func (e envelope) Chunk(d delta, finish *Finish) []byte {
	e.Object = "chat.completion.chunk"
	return jsonx.Encode(struct {
		envelope
		Choices []chunkChoice `json:"choices"`
	}{e, []chunkChoice{{Delta: d, FinishReason: finish}}})
}

func (e envelope) Usage(u chat.Usage, detailed bool) []byte {
	e.Object = "chat.completion.chunk"
	return jsonx.Encode(struct {
		envelope
		Choices []chunkChoice `json:"choices"`
		Usage   *Usage        `json:"usage"`
	}{e, []chunkChoice{}, wireUsage(u, detailed)})
}

func (e envelope) Completion(r *reply, u chat.Usage, detailed bool) []byte {
	e.Object = "chat.completion"
	msg := message{Role: "assistant", ToolCalls: r.calls}
	if text := r.text.String(); text != "" || (len(r.calls) == 0 && r.refusal.Len() == 0) {
		msg.Content = &text
	}
	if refusal := r.refusal.String(); refusal != "" {
		msg.Refusal = &refusal
	}
	finish := r.finish
	if finish == "" {
		finish = FinishStop
	}
	return jsonx.Encode(struct {
		envelope
		Choices []completionChoice `json:"choices"`
		Usage   *Usage             `json:"usage"`
	}{e, []completionChoice{{Message: msg, FinishReason: finish}}, wireUsage(u, detailed)})
}
