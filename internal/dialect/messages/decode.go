// Package messages is the Anthropic Messages dialect (POST /v1/messages): it reads a Messages request as a Chat
// Completions body, and writes the reply as a Message, or as Anthropic's stream of named events, without state.
package messages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
	"morse/backend/internal/strictjson"
)

var Dialect = dialect.Dialect{Decode: Decode, Envelope: Envelope}

type request struct {
	Model         string          `json:"model"`
	MaxTokens     json.RawMessage `json:"max_tokens"`
	Messages      json.RawMessage `json:"messages"`
	System        json.RawMessage `json:"system"`
	Tools         json.RawMessage `json:"tools"`
	ToolChoice    json.RawMessage `json:"tool_choice"`
	Stream        bool            `json:"stream"`
	Thinking      json.RawMessage `json:"thinking"`
	OutputConfig  json.RawMessage `json:"output_config"`
	StopSequences []string        `json:"stop_sequences"`
	Temperature   *float64        `json:"temperature"`
	TopP          *float64        `json:"top_p"`
	TopK          json.RawMessage `json:"top_k"`
}

var privacyPassthroughFields = []string{"provider", "privacy_veil"}

// extraInputs are the fields Morse refuses in the words Anthropic refuses a field it does not take. Claude Code reads
// "context_management: Extra inputs are not permitted" to retry without context_management.
var extraInputs = []string{"context_management", "container", "mcp_servers"}

func Decode(body []byte, known func(string) bool) (dialect.Decoded, error) {
	if err := strictjson.UniqueKeys(body); err != nil {
		return dialect.Decoded{}, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return dialect.Decoded{}, invalid("The request body must be a JSON object.")
	}
	for _, name := range extraInputs {
		if raw, ok := fields[name]; ok && !null(raw) {
			return dialect.Decoded{}, invalid(name + ": Extra inputs are not permitted")
		}
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		return dialect.Decoded{}, invalid("The request body does not match the Messages API: " + err.Error())
	}
	out := map[string]any{"stream": req.Stream}
	for _, name := range privacyPassthroughFields {
		if raw, ok := fields[name]; ok {
			out[name] = raw
		}
	}
	if req.Model == "" {
		return dialect.Decoded{}, invalid("model: Field required")
	}
	out["model"] = modelOf(req.Model, known)
	limit, err := maxTokens(req.MaxTokens)
	if err != nil {
		return dialect.Decoded{}, err
	}
	out["max_completion_tokens"] = limit
	messages, err := conversation(req.System, req.Messages)
	if err != nil {
		return dialect.Decoded{}, err
	}
	out["messages"] = messages
	if err := toolsOf(req.Tools, req.ToolChoice, out); err != nil {
		return dialect.Decoded{}, err
	}
	showThinking, err := reasoningOf(req.Thinking, req.OutputConfig, out)
	if err != nil {
		return dialect.Decoded{}, err
	}
	if err := samplingOf(req, out); err != nil {
		return dialect.Decoded{}, err
	}
	chatBody, err := json.Marshal(out)
	if err != nil {
		return dialect.Decoded{}, err
	}
	model := req.Model
	return dialect.Decoded{Body: chatBody, Reply: func() dialect.Encoder { return newEncoder(model, showThinking) }}, nil
}

func invalid(message string) apierr.Error {
	return apierr.Invalid(400, "invalid_request_error", message)
}

func null(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || string(raw) == "null"
}

var (
	anthropicDateSuffix    = regexp.MustCompile(`-\d{8}$`)
	anthropicVersionDashed = regexp.MustCompile(`-(\d+)-(\d+)$`)
)

func modelOf(name string, known func(string) bool) string {
	if known(name) || !strings.HasPrefix(name, "claude-") {
		return name
	}
	for _, id := range morseIDsOfAnthropicID(name) {
		if known(id) {
			return id
		}
	}
	return name
}

// morseIDsOfAnthropicID are the Morse ids Anthropic's id for a Claude model may name, most likely first:
// claude-opus-5-5-20261001 and claude-opus-5-5 both name anthropic/claude-opus-5.5.
func morseIDsOfAnthropicID(id string) []string {
	undated := anthropicDateSuffix.ReplaceAllString(id, "")
	return []string{"anthropic/" + anthropicVersionDashed.ReplaceAllString(undated, "-$1.$2"), "anthropic/" + undated}
}

func maxTokens(raw json.RawMessage) (int, error) {
	if null(raw) {
		return 0, invalid("max_tokens: Field required")
	}
	var n int
	if json.Unmarshal(raw, &n) != nil || n <= 0 {
		return 0, invalid("max_tokens: Input should be a positive integer")
	}
	return n, nil
}

type block struct {
	Type      string          `json:"type"`
	Text      *string         `json:"text"`
	Source    json.RawMessage `json:"source"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

type imageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

type message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// dropped are the blocks that carry nothing Morse can send on: thinking that only Anthropic's signature vouches for.
var dropped = []string{"thinking", "redacted_thinking"}

func blocksOf(raw json.RawMessage, at string) ([]block, error) {
	if null(raw) {
		return nil, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []block{{Type: "text", Text: &text}}, nil
	}
	var blocks []block
	if json.Unmarshal(raw, &blocks) != nil {
		return nil, invalid(at + ": Input should be a string or a list of content blocks")
	}
	return slices.DeleteFunc(blocks, func(b block) bool { return slices.Contains(dropped, b.Type) }), nil
}

func refusedBlock(at, typ string) apierr.Error {
	switch typ {
	case "document":
		return invalid(at + ": Morse does not take document blocks. Send the document's text as a text block.")
	case "":
		return invalid(at + ".type: Field required")
	}
	return invalid(fmt.Sprintf("%s: Morse does not take %s blocks. It takes text, image (base64), tool_use, and tool_result blocks.", at, typ))
}

func textOf(raw json.RawMessage, at string) (string, error) {
	blocks, err := blocksOf(raw, at)
	if err != nil {
		return "", err
	}
	texts := make([]string, 0, len(blocks))
	for i, b := range blocks {
		if b.Type != "text" || b.Text == nil {
			return "", refusedBlock(fmt.Sprintf("%s.%d", at, i), b.Type)
		}
		texts = append(texts, *b.Text)
	}
	return strings.Join(texts, "\n\n"), nil
}

// conversation is the Chat Completions messages of a Messages request: its system prompt first, then each turn. A
// user turn's tool results become tool messages ahead of the rest of the turn, so they follow the assistant's calls.
func conversation(system, raw json.RawMessage) ([]any, error) {
	var out []any
	if !null(system) {
		text, err := textOf(system, "system")
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"role": "system", "content": text})
	}
	if null(raw) {
		return nil, invalid("messages: Field required")
	}
	var turns []message
	if json.Unmarshal(raw, &turns) != nil {
		return nil, invalid("messages: Input should be a valid list of messages")
	}
	for i, m := range turns {
		at := fmt.Sprintf("messages.%d.content", i)
		var turn []any
		var err error
		switch m.Role {
		case "user":
			turn, err = userTurn(m.Content, at)
		case "assistant":
			turn, err = assistantTurn(m.Content, at)
		case "system":
			var text string
			text, err = textOf(m.Content, at)
			turn = []any{map[string]any{"role": "system", "content": text}}
		default:
			err = invalid(fmt.Sprintf("messages.%d.role: Input should be 'user' or 'assistant'", i))
		}
		if err != nil {
			return nil, err
		}
		out = append(out, turn...)
	}
	return out, nil
}

func userTurn(raw json.RawMessage, at string) ([]any, error) {
	blocks, err := blocksOf(raw, at)
	if err != nil {
		return nil, err
	}
	var results []any
	var parts []any
	for i, b := range blocks {
		where := fmt.Sprintf("%s.%d", at, i)
		switch {
		case b.Type == "text" && b.Text != nil:
			parts = append(parts, map[string]any{"type": "text", "text": *b.Text})
		case b.Type == "image":
			part, err := imagePart(b.Source, where)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case b.Type == "tool_result":
			result, err := toolResult(b, where)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		default:
			return nil, refusedBlock(where, b.Type)
		}
	}
	if len(parts) > 0 {
		results = append(results, map[string]any{"role": "user", "content": parts})
	}
	return results, nil
}

func imagePart(raw json.RawMessage, at string) (any, error) {
	var source imageSource
	switch {
	case null(raw):
		return nil, invalid(at + ".source: Field required")
	case json.Unmarshal(raw, &source) != nil:
		return nil, invalid(at + ".source: Input should be an object")
	case source.Type == "url":
		return nil, invalid(at + ".source: Morse does not take an image linked by URL. Attach the image as a base64 source.")
	case source.Type != "base64":
		return nil, invalid(fmt.Sprintf("%s.source: Morse does not take %s image sources. Attach the image as a base64 source.", at, source.Type))
	}
	return map[string]any{"type": "image_url", "image_url": map[string]string{"url": "data:" + source.MediaType + ";base64," + source.Data}}, nil
}

func toolResult(b block, at string) (any, error) {
	if b.ToolUseID == "" {
		return nil, invalid(at + ".tool_use_id: Field required")
	}
	blocks, err := blocksOf(b.Content, at+".content")
	if err != nil {
		return nil, err
	}
	texts := make([]string, 0, len(blocks))
	for i, c := range blocks {
		if c.Type != "text" || c.Text == nil {
			if c.Type == "image" {
				return nil, invalid(fmt.Sprintf("%s.content.%d: Morse does not take an image in a tool result. Send the image in a user text turn's image block.", at, i))
			}
			return nil, refusedBlock(fmt.Sprintf("%s.content.%d", at, i), c.Type)
		}
		texts = append(texts, *c.Text)
	}
	content := strings.Join(texts, "\n\n")
	if b.IsError {
		content = "Error: " + content
	}
	return map[string]any{"role": "tool", "tool_call_id": b.ToolUseID, "content": content}, nil
}

func assistantTurn(raw json.RawMessage, at string) ([]any, error) {
	blocks, err := blocksOf(raw, at)
	if err != nil {
		return nil, err
	}
	var text strings.Builder
	var calls []any
	for i, b := range blocks {
		where := fmt.Sprintf("%s.%d", at, i)
		switch {
		case b.Type == "text" && b.Text != nil:
			text.WriteString(*b.Text)
		case b.Type == "tool_use":
			if b.ID == "" || b.Name == "" {
				return nil, invalid(where + ": a tool_use block needs an id and a name")
			}
			arguments := "{}"
			if !null(b.Input) {
				arguments = string(b.Input)
			}
			calls = append(calls, map[string]any{"id": b.ID, "type": "function", "function": map[string]string{"name": b.Name, "arguments": arguments}})
		default:
			return nil, refusedBlock(where, b.Type)
		}
	}
	if text.Len() == 0 && len(calls) == 0 {
		return nil, nil
	}
	turn := map[string]any{"role": "assistant", "content": text.String()}
	if len(calls) > 0 {
		turn["tool_calls"] = calls
		if text.Len() == 0 {
			turn["content"] = nil
		}
	}
	return []any{turn}, nil
}

type tool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type toolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use"`
}

// toolsOf maps custom tools onto functions and refuses Anthropic's server tools, which run on Anthropic's side, in
// the words Anthropic refuses a tool type it does not know: Claude Code reads them to retry without the tool.
func toolsOf(rawTools, rawChoice json.RawMessage, out map[string]any) error {
	if !null(rawTools) {
		var tools []tool
		if json.Unmarshal(rawTools, &tools) != nil {
			return invalid("tools: Input should be a valid list of tools")
		}
		functions := make([]any, 0, len(tools))
		for i, t := range tools {
			if t.Type != "" && t.Type != "custom" {
				return invalid(fmt.Sprintf("tools.%d: Input tag '%s' found using 'type' does not match any of the expected tags: 'custom'. Morse serves custom tools only, not Anthropic's server tools.", i, t.Type))
			}
			if t.Name == "" {
				return invalid(fmt.Sprintf("tools.%d.name: Field required", i))
			}
			function := map[string]any{"name": t.Name}
			if t.Description != "" {
				function["description"] = t.Description
			}
			if !null(t.InputSchema) {
				function["parameters"] = t.InputSchema
			}
			functions = append(functions, map[string]any{"type": "function", "function": function})
		}
		if len(functions) > 0 {
			out["tools"] = functions
		}
	}
	if null(rawChoice) {
		return nil
	}
	var choice toolChoice
	if json.Unmarshal(rawChoice, &choice) != nil {
		return invalid("tool_choice: Input should be an object")
	}
	switch choice.Type {
	case "auto":
		out["tool_choice"] = "auto"
	case "any":
		out["tool_choice"] = "required"
	case "none":
		out["tool_choice"] = "none"
	case "tool":
		if choice.Name == "" {
			return invalid("tool_choice.name: Field required")
		}
		out["tool_choice"] = map[string]any{"type": "function", "function": map[string]string{"name": choice.Name}}
	default:
		return invalid(fmt.Sprintf("tool_choice: Input tag '%s' found using 'type' does not match any of the expected tags: 'auto', 'any', 'tool', 'none'", choice.Type))
	}
	if choice.DisableParallelToolUse && choice.Type != "none" {
		out["parallel_tool_calls"] = false
	}
	return nil
}

type thinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

type outputConfig struct {
	Effort string          `json:"effort"`
	Format json.RawMessage `json:"format"`
}

var budgetEfforts = []struct {
	upTo   int
	effort string
}{{2048, "low"}, {8192, "medium"}, {24576, "high"}, {49152, "xhigh"}}

func reasoningOf(rawThinking, rawConfig json.RawMessage, out map[string]any) (showThinking bool, err error) {
	var config outputConfig
	if !null(rawConfig) && json.Unmarshal(rawConfig, &config) != nil {
		return false, invalid("output_config: Input should be an object")
	}
	if !null(config.Format) {
		return false, invalid("output_config.format: Morse does not serve structured outputs on any model. Send the request without output_config.format.")
	}
	var t thinking
	if !null(rawThinking) && json.Unmarshal(rawThinking, &t) != nil {
		return false, invalid("thinking: Input should be an object")
	}
	if config.Effort != "" {
		if !slices.Contains(chat.EffortLadder, config.Effort) {
			return false, invalid(fmt.Sprintf("output_config.effort: Input should be one of %s", strings.Join(chat.ReasoningEfforts, ", ")))
		}
		out["reasoning_effort"] = config.Effort
	}
	switch t.Type {
	case "", "disabled":
		return false, nil
	case "adaptive":
		return true, nil
	case "enabled":
		if config.Effort == "" {
			out["reasoning_effort"] = budgetEffort(t.BudgetTokens)
		}
		return true, nil
	}
	return false, invalid(fmt.Sprintf("thinking: Input tag '%s' found using 'type' does not match any of the expected tags: 'enabled', 'disabled', 'adaptive'", t.Type))
}

func budgetEffort(budget int) string {
	for _, b := range budgetEfforts {
		if budget <= b.upTo {
			return b.effort
		}
	}
	return "max"
}

// anthropicDefaultSampling is Anthropic's default temperature and top_p. Sending it would change nothing, yet an API key
// without forward_settings is refused any temperature or top_p it sends (openaicompat.SettingsOf).
const anthropicDefaultSampling = 1.0

func samplingOf(req request, out map[string]any) error {
	if !null(req.TopK) {
		return invalid("top_k: Morse sends top_k to no model host. Send the request without it.")
	}
	if len(req.StopSequences) > 0 {
		out["stop"] = req.StopSequences
	}
	if req.Temperature != nil && *req.Temperature != anthropicDefaultSampling {
		out["temperature"] = *req.Temperature
	}
	if req.TopP != nil && *req.TopP != anthropicDefaultSampling {
		out["top_p"] = *req.TopP
	}
	return nil
}
