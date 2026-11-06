package anthropic

import (
	"encoding/json"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/upstream"
)

const (
	messagesPath  = "/v1/messages?beta=true"
	apiVersion    = "2023-06-01"
	roleUser      = "user"
	roleAssistant = "assistant"
	blockText     = "text"
	blockToolUse  = "tool_use"
)

var roles = map[bool]string{false: roleUser, true: roleAssistant}

var finishReasons = map[string]completions.Finish{
	"end_turn":                      completions.FinishStop,
	"stop_sequence":                 completions.FinishStop,
	"tool_use":                      completions.FinishToolCalls,
	"max_tokens":                    completions.FinishLength,
	"model_context_window_exceeded": completions.FinishLength,
	"refusal":                       completions.FinishContentFilter,
}

var toolChoices = map[string]toolChoice{
	completions.ChoiceAuto:     {Type: "auto"},
	completions.ChoiceNone:     {Type: "none"},
	completions.ChoiceRequired: {Type: "any"},
	completions.ChoiceFunction: {Type: "tool"},
}

type request struct {
	Model        string        `json:"model"`
	MaxTokens    int           `json:"max_tokens"`
	System       []textBlock   `json:"system,omitempty"`
	Messages     []turn        `json:"messages"`
	Tools        []tool        `json:"tools,omitempty"`
	ToolChoice   *toolChoice   `json:"tool_choice,omitempty"`
	OutputConfig *outputConfig `json:"output_config,omitempty"`
	Stream       bool          `json:"stream"`
}

type outputConfig struct {
	Effort string `json:"effort"`
}

type tool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"input_schema"`
	CacheControl *cacheControl   `json:"cache_control,omitempty"`
}

type cacheControl struct {
	Type string `json:"type"`
}

type toolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name,omitempty"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use,omitempty"`
}

type turn struct {
	Role    string  `json:"role"`
	Content []block `json:"content"`
}

type block interface{ block() }

func (textBlock) block()       {}
func (imageBlock) block()      {}
func (toolUseBlock) block()    {}
func (toolResultBlock) block() {}

type textBlock struct {
	Type         string        `json:"type"`
	Text         string        `json:"text"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type imageBlock struct {
	Type         string        `json:"type"`
	Source       imageSource   `json:"source"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type imageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

type toolUseBlock struct {
	Type         string          `json:"type"`
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Input        json.RawMessage `json:"input"`
	CacheControl *cacheControl   `json:"cache_control,omitempty"`
}

type toolResultBlock struct {
	Type         string        `json:"type"`
	ToolUseID    string        `json:"tool_use_id"`
	Content      []textBlock   `json:"content,omitempty"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type usageWire struct {
	InputTokens              int64 `json:"input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	OutputTokensDetails      *struct {
		ThinkingTokens int `json:"thinking_tokens"`
	} `json:"output_tokens_details"`
}

type messageStart struct {
	Message struct {
		Usage usageWire `json:"usage"`
	} `json:"message"`
}

type blockStart struct {
	Index        int `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
}

type blockDelta struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

type blockStop struct {
	Index int `json:"index"`
}

type messageDelta struct {
	Delta struct {
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Usage usageWire `json:"usage"`
}

type errorEvent struct {
	Error struct {
		Type string `json:"type"`
	} `json:"error"`
}

func New(baseURL, apiKey, model string, client *http.Client) *completions.Provider {
	return &completions.Provider{
		Endpoint:   upstream.Endpoint{BaseURL: baseURL, Auth: http.Header{"X-Api-Key": {apiKey}, "Anthropic-Version": {apiVersion}}, HTTP: client},
		Translator: translator{model: model},
	}
}

type translator struct {
	model string
}

func (t translator) Request(conv completions.Conversation) (string, string, any) {
	return messagesPath, "application/json", t.request(conv)
}

func (translator) Events(w *completions.Writer) func([]byte) (bool, error) {
	return (&translation{w: w}).events().ByType
}

type translation struct {
	w        *completions.Writer
	tokens   chat.Usage
	detailed bool
}

func (s *translation) events() completions.Events {
	return completions.Events{
		"message_start": completions.On(func(e messageStart) (bool, error) {
			s.countPrompt(e.Message.Usage)
			return false, s.w.Start()
		}),
		"content_block_start": completions.On(func(e blockStart) (bool, error) {
			if e.ContentBlock.Type != blockToolUse {
				return false, nil
			}
			return false, s.w.ToolStart(e.Index, e.ContentBlock.ID, e.ContentBlock.Name)
		}),
		"content_block_delta": completions.On(func(e blockDelta) (bool, error) {
			switch e.Delta.Type {
			case "text_delta":
				return false, s.w.Text(e.Delta.Text)
			case "input_json_delta":
				return false, s.w.ToolArguments(e.Index, e.Delta.PartialJSON)
			}
			return false, nil
		}),
		"content_block_stop": completions.On(func(e blockStop) (bool, error) { return false, s.w.ToolEnd(e.Index, "") }),
		"message_delta":      completions.On(s.messageDelta),
		"message_stop":       func([]byte) (bool, error) { return true, nil },
		"error": completions.On(func(e errorEvent) (bool, error) {
			return false, s.w.Fail(e.Error.Type, apierr.ErrUpstream)
		}),
	}
}

func (s *translation) messageDelta(e messageDelta) (bool, error) {
	if e.Usage.InputTokens > 0 {
		s.countPrompt(e.Usage)
	}
	s.tokens.CompletionTokens = int(e.Usage.OutputTokens)
	if d := e.Usage.OutputTokensDetails; d != nil {
		s.tokens.ReasoningTokens, s.detailed = d.ThinkingTokens, true
	}
	s.w.Count(s.tokens, s.detailed)
	finish := finishReasons[e.Delta.StopReason]
	if finish == "" {
		finish = completions.FinishStop
	}
	return false, s.w.Finish(finish)
}

func (s *translation) countPrompt(u usageWire) {
	s.tokens.PromptTokens = int(u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens)
	s.tokens.CachedPromptTokens = int(u.CacheReadInputTokens)
	s.tokens.CacheWritePromptTokens = int(u.CacheCreationInputTokens)
	s.w.Count(s.tokens, s.detailed)
}

func (t translator) request(conv completions.Conversation) request {
	out := request{Model: t.model, MaxTokens: conv.OutputLimit, Stream: true, Tools: tools(conv.Tools), ToolChoice: choice(conv.Choice, conv.Parallel)}
	if conv.ForwardedEffort != "" && conv.Effort != chat.NoEffort {
		out.OutputConfig = &outputConfig{Effort: conv.ForwardedEffort}
	}
	system, exchanges := conv.Alternating()
	for _, text := range system {
		out.System = append(out.System, textBlock{Type: blockText, Text: text})
	}
	for _, x := range exchanges {
		message := turn{Role: roles[x.FromModel]}
		for _, t := range x.Turns {
			message.Content = append(message.Content, blocks(t)...)
		}
		out.Messages = append(out.Messages, message)
	}
	out.cacheRepeatedPrefix(conv.RequestBytes)
	return out
}

func blocks(t completions.Turn) []block {
	switch t.Role {
	case completions.Assistant:
		return append(textBlocks(t.Text), toolUseBlocks(t.Calls)...)
	case completions.ToolResult:
		result := toolResultBlock{Type: "tool_result", ToolUseID: t.CallID}
		if t.Text != "" {
			result.Content = []textBlock{{Type: blockText, Text: t.Text}}
		}
		return []block{result}
	}
	return userBlocks(t.Parts)
}

func textBlocks(text string) []block {
	if text == "" {
		return nil
	}
	return []block{textBlock{Type: blockText, Text: text}}
}

func tools(defs []completions.Tool) []tool {
	var out []tool
	for _, def := range defs {
		out = append(out, tool{Name: def.Name, Description: def.Description, InputSchema: def.Schema()})
	}
	return out
}

func choice(c *completions.Choice, parallel *bool) *toolChoice {
	oneCall := parallel != nil && !*parallel
	if c == nil {
		if oneCall {
			return &toolChoice{Type: "auto", DisableParallelToolUse: true}
		}
		return nil
	}
	chosen := toolChoices[c.Mode]
	chosen.Name = c.Name
	chosen.DisableParallelToolUse = oneCall && c.Mode != completions.ChoiceNone
	return &chosen
}

func toolUseBlocks(calls []completions.ToolCall) []block {
	var blocks []block
	for _, call := range calls {
		blocks = append(blocks, toolUseBlock{Type: blockToolUse, ID: call.ID, Name: call.Function.Name, Input: json.RawMessage(call.Function.Arguments)})
	}
	return blocks
}

func userBlocks(parts []completions.Part) []block {
	var blocks []block
	for _, part := range parts {
		if part.Image == nil {
			blocks = append(blocks, textBlock{Type: blockText, Text: part.Text})
			continue
		}
		blocks = append(blocks, imageBlock{Type: "image", Source: imageSource{Type: "base64", MediaType: part.Image.MediaType, Data: part.Image.Base64}})
	}
	return blocks
}
