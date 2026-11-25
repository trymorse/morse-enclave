package anthropic

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/upstream"
)

const (
	messagesPath  = "/v1/messages?beta=true"
	apiVersion    = "2023-06-01"
	roleUser      = "user"
	roleAssistant = "assistant"
	blockText     = "text"
	blockToolUse  = "tool_use"
	blockThinking = "thinking"
	blockRedacted = "redacted_thinking"

	bindingBeta   = "thinking-binding-controls-2026-08-01"
	dropMismatch  = "drop_block"
	adaptive      = "adaptive"
	summarized    = "summarized"
	layoutThought = 't'
	layoutText    = 'x'
	layoutCall    = 'u'
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
	Thinking     *thinking     `json:"thinking,omitempty"`
	OutputConfig *outputConfig `json:"output_config,omitempty"`
	Stream       bool          `json:"stream"`
}

type thinking struct {
	Type         string        `json:"type"`
	Display      string        `json:"display,omitempty"`
	BlockBinding *blockBinding `json:"block_binding,omitempty"`
}

type blockBinding struct {
	PrefixMismatchBehavior string `json:"prefix_mismatch_behavior"`
}

// why: block_binding is accepted only under this beta header, and with it a replayed thinking block whose prefix
// changed is dropped, not refused (https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting).
func (r request) Header() http.Header {
	if r.Thinking == nil || r.Thinking.BlockBinding == nil {
		return nil
	}
	return http.Header{"Anthropic-Beta": {bindingBeta}}
}

type outputConfig struct {
	Effort string `json:"effort"`
}

type tool struct {
	Name                string          `json:"name"`
	Description         string          `json:"description,omitempty"`
	InputSchema         json.RawMessage `json:"input_schema"`
	EagerInputStreaming bool            `json:"eager_input_streaming,omitempty"`
	CacheControl        *cacheControl   `json:"cache_control,omitempty"`
}

// why: Anthropic otherwise holds each input value until it is whole, so a widget's markup reached the client only as
// its call ended. Eager input is not checked as JSON, so a reply cut at its limit can end a call mid-value.
var eagerTools = map[string]bool{"show_widget": true}

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
func (thoughtBlock) block()    {}

type thoughtBlock struct {
	Type      string  `json:"type"`
	Thinking  *string `json:"thinking,omitempty"`
	Signature string  `json:"signature,omitempty"`
	Data      string  `json:"data,omitempty"`
}

func (b thoughtBlock) replayable() bool {
	switch b.Type {
	case blockThinking:
		return b.Thinking != nil && b.Signature != "" && b.Data == ""
	case blockRedacted:
		return b.Data != "" && b.Thinking == nil && b.Signature == ""
	}
	return false
}

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
		Data string `json:"data"`
	} `json:"content_block"`
}

type blockDelta struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		Signature   string `json:"signature"`
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

func (t translator) Events(w *completions.Writer) func([]byte) (bool, error) {
	return (&translation{w: w, model: t.model, heard: map[int]*heardBlock{}}).events().ByType
}

type translation struct {
	w        *completions.Writer
	model    string
	tokens   chat.Usage
	detailed bool
	heard    map[int]*heardBlock
}

type heardBlock struct {
	kind    rune
	thought thoughtBlock
	text    int
}

func (s *translation) hear(e blockStart) {
	if !s.w.CarriesReasoning() {
		return
	}
	switch e.ContentBlock.Type {
	case blockThinking:
		s.heard[e.Index] = &heardBlock{kind: layoutThought, thought: thoughtBlock{Type: blockThinking, Thinking: new(string)}}
	case blockRedacted:
		s.heard[e.Index] = &heardBlock{kind: layoutThought, thought: thoughtBlock{Type: blockRedacted, Data: e.ContentBlock.Data}}
	case blockText:
		s.heard[e.Index] = &heardBlock{kind: layoutText}
	case blockToolUse:
		s.heard[e.Index] = &heardBlock{kind: layoutCall}
	}
}

func (s *translation) hearDelta(e blockDelta) {
	b := s.heard[e.Index]
	if b == nil {
		return
	}
	switch {
	case b.kind == layoutText:
		b.text += len(e.Delta.Text)
	case b.thought.Type == blockThinking:
		*b.thought.Thinking += e.Delta.Thinking
		b.thought.Signature += e.Delta.Signature
	}
}

func (s *translation) reasoningState() completions.ReasoningState {
	var state completions.ReasoningState
	var layout []rune
	for _, index := range slices.Sorted(maps.Keys(s.heard)) {
		b := s.heard[index]
		switch {
		case b.kind == layoutText && b.text == 0:
			continue
		case b.kind == layoutText:
			state.Texts = append(state.Texts, b.text)
		case b.kind == layoutThought && !b.thought.replayable():
			return completions.ReasoningState{}
		case b.kind == layoutThought:
			state.Items = append(state.Items, jsonx.Encode(b.thought))
		}
		layout = append(layout, b.kind)
	}
	state.Layout = string(layout)
	return state
}

func (s *translation) events() completions.Events {
	return completions.Events{
		"message_start": completions.On(func(e messageStart) (bool, error) {
			s.countPrompt(e.Message.Usage)
			return false, s.w.Start()
		}),
		"content_block_start": completions.On(func(e blockStart) (bool, error) {
			s.hear(e)
			switch e.ContentBlock.Type {
			case blockToolUse:
				return false, s.w.ToolStart(e.Index, e.ContentBlock.ID, e.ContentBlock.Name)
			case blockThinking:
				s.w.ReasoningBlock()
			}
			return false, nil
		}),
		"content_block_delta": completions.On(func(e blockDelta) (bool, error) {
			s.hearDelta(e)
			switch e.Delta.Type {
			case "text_delta":
				return false, s.w.Text(e.Delta.Text)
			case "thinking_delta":
				return false, s.w.Reasoning(e.Delta.Thinking)
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
	if finish == completions.FinishToolCalls {
		if err := s.w.ReasoningState(s.model, s.reasoningState()); err != nil {
			return false, err
		}
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
	if conv.ReasoningView.Summarizes() {
		out.Thinking = &thinking{Type: adaptive, Display: summarized}
	}
	system, exchanges := conv.Alternating()
	for _, text := range system {
		out.System = append(out.System, textBlock{Type: blockText, Text: text})
	}
	replays := false
	for _, x := range exchanges {
		message := turn{Role: roles[x.FromModel]}
		for _, said := range x.Turns {
			if replayed, ok := t.replayed(conv, said); ok {
				replays = true
				message.Content = append(message.Content, replayed...)
				continue
			}
			message.Content = append(message.Content, blocks(said)...)
		}
		out.Messages = append(out.Messages, message)
	}
	if replays {
		if out.Thinking == nil {
			out.Thinking = &thinking{Type: adaptive}
		}
		out.Thinking.BlockBinding = &blockBinding{PrefixMismatchBehavior: dropMismatch}
	}
	out.cacheRepeatedPrefix(conv.RequestBytes)
	return out
}

// why: Anthropic refuses a turn whose thinking blocks are reordered, edited, or partly dropped, so a turn goes back
// with its thinking only when every block of it can be put where it was
// (https://platform.claude.com/docs/en/build-with-claude/thinking#preserving-thinking-blocks).
func (t translator) replayed(conv completions.Conversation, said completions.Turn) ([]block, bool) {
	state, ok := conv.StateOf(said, t.model)
	if !ok {
		return nil, false
	}
	texts, ok := splitText(said.Text, state.Texts)
	if !ok {
		return nil, false
	}
	thoughts, calls := state.Items, toolUseBlocks(said.Calls)
	var out []block
	for _, kind := range state.Layout {
		switch {
		case kind == layoutThought && len(thoughts) > 0:
			var thought thoughtBlock
			if json.Unmarshal(thoughts[0], &thought) != nil || !thought.replayable() {
				return nil, false
			}
			out, thoughts = append(out, thought), thoughts[1:]
		case kind == layoutText && len(texts) > 0:
			out, texts = append(out, textBlock{Type: blockText, Text: texts[0]}), texts[1:]
		case kind == layoutCall && len(calls) > 0:
			out, calls = append(out, calls[0]), calls[1:]
		default:
			return nil, false
		}
	}
	return out, len(thoughts)+len(texts)+len(calls) == 0
}

func splitText(text string, lengths []int) ([]string, bool) {
	var parts []string
	at := 0
	for _, n := range lengths {
		end := at + n
		if n <= 0 || end > len(text) || end < len(text) && !utf8.RuneStart(text[end]) {
			return nil, false
		}
		parts = append(parts, text[at:end])
		at = end
	}
	return parts, at == len(text)
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
		out = append(out, tool{Name: def.Name, Description: def.Description, InputSchema: def.Schema(), EagerInputStreaming: eagerTools[def.Name]})
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
