// Package responses is the OpenAI Responses dialect (POST /v1/responses): it reads a Responses request as a Chat
// Completions body, and writes the reply as a Response, or as OpenAI's stream of response events, without state.
// Morse keeps no response, so a request that leans on a stored one is refused.
package responses

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
	"morse/backend/internal/strictjson"
)

// Dialect leaves Envelope nil: a Responses client reads refusals in the OpenAI envelope the relay and the worker
// already write.
var Dialect = dialect.Dialect{Decode: Decode}

type request struct {
	Model             string          `json:"model"`
	Input             json.RawMessage `json:"input"`
	Instructions      json.RawMessage `json:"instructions"`
	Stream            bool            `json:"stream"`
	MaxOutputTokens   json.RawMessage `json:"max_output_tokens"`
	Tools             json.RawMessage `json:"tools"`
	ToolChoice        json.RawMessage `json:"tool_choice"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls"`
	Reasoning         json.RawMessage `json:"reasoning"`
	Text              json.RawMessage `json:"text"`
	Temperature       *float64        `json:"temperature"`
	TopP              *float64        `json:"top_p"`
	Metadata          json.RawMessage `json:"metadata"`
}

var privacyPassthroughFields = []string{"provider", "privacy_veil"}

var stateful = []string{"previous_response_id", "conversation", "prompt", "context_management"}

func Decode(body []byte, _ func(string) bool) (dialect.Decoded, error) {
	if err := strictjson.UniqueKeys(body); err != nil {
		return dialect.Decoded{}, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return dialect.Decoded{}, invalid("", "The request body must be a JSON object.")
	}
	if err := refuseState(fields); err != nil {
		return dialect.Decoded{}, err
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		return dialect.Decoded{}, invalid("", "The request body does not match the Responses API: "+err.Error())
	}
	if req.Model == "" {
		return dialect.Decoded{}, invalid("model", "Missing required parameter: 'model'.")
	}
	out := map[string]any{"stream": req.Stream, "model": req.Model}
	for _, name := range privacyPassthroughFields {
		if raw, ok := fields[name]; ok {
			out[name] = raw
		}
	}
	if !null(req.MaxOutputTokens) {
		var n int
		if json.Unmarshal(req.MaxOutputTokens, &n) != nil || n <= 0 {
			return dialect.Decoded{}, invalid("max_output_tokens", "max_output_tokens must be a positive integer.")
		}
		out["max_completion_tokens"] = n
	}
	messages, err := conversationOf(req.Instructions, req.Input)
	if err != nil {
		return dialect.Decoded{}, err
	}
	out["messages"] = messages
	t, err := toolsOf(req.Tools, req.ToolChoice, out)
	if err != nil {
		return dialect.Decoded{}, err
	}
	if req.ParallelToolCalls != nil {
		out["parallel_tool_calls"] = *req.ParallelToolCalls
	}
	r, err := reasoningOf(req.Reasoning, out)
	if err != nil {
		return dialect.Decoded{}, err
	}
	if err := textOf(req.Text); err != nil {
		return dialect.Decoded{}, err
	}
	samplingOf(req, out)
	chatBody, err := json.Marshal(out)
	if err != nil {
		return dialect.Decoded{}, err
	}
	echo := echoOf(req, t, r)
	return dialect.Decoded{Body: chatBody, Reply: func() dialect.Encoder { return newEncoder(echo) }}, nil
}

func invalid(param, message string) apierr.Error {
	return apierr.InvalidParameter(message).Naming(param)
}

func unsupported(param, message string) apierr.Error {
	return apierr.Invalid(400, "unsupported_parameter", message).Naming(param)
}

func null(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || string(raw) == "null"
}

func refuseState(fields map[string]json.RawMessage) error {
	for _, name := range stateful {
		if raw, ok := fields[name]; ok && !null(raw) {
			return unsupported(name, fmt.Sprintf("%s is not supported: Morse keeps no responses or conversations. Send the whole conversation in input, with store false or absent.", name))
		}
	}
	var on bool
	if raw, ok := fields["store"]; ok && !null(raw) {
		if json.Unmarshal(raw, &on) != nil {
			return invalid("store", "store must be a boolean.")
		}
		if on {
			return unsupported("store", "store: true is not supported: Morse keeps no responses. Send store: false, or leave it out.")
		}
	}
	if raw, ok := fields["background"]; ok && !null(raw) {
		if json.Unmarshal(raw, &on) != nil {
			return invalid("background", "background must be a boolean.")
		}
		if on {
			return unsupported("background", "background: true is not supported: Morse keeps no responses to poll. Send the request without background, and stream it if it runs long.")
		}
	}
	var truncation string
	if raw, ok := fields["truncation"]; ok && !null(raw) && (json.Unmarshal(raw, &truncation) != nil || truncation != "disabled") {
		return unsupported("truncation", `truncation is supported only as "disabled": Morse does not cut a conversation to fit.`)
	}
	return nil
}

type tools struct {
	echo       []json.RawMessage
	choice     json.RawMessage
	custom     map[string]bool
	namespaced map[string]qualified
}

type qualified struct{ namespace, name string }

// Chat Completions takes a function name of a-z, A-Z, 0-9, _ and - only, so the separator is two underscores.
func (q qualified) flat() string { return q.namespace + "__" + q.name }

type tool struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Parameters  json.RawMessage   `json:"parameters"`
	Strict      json.RawMessage   `json:"strict"`
	Tools       []json.RawMessage `json:"tools"`
	Format      struct {
		Type       string `json:"type"`
		Syntax     string `json:"syntax"`
		Definition string `json:"definition"`
	} `json:"format"`
}

// description tells the model a custom tool's grammar in words, since Morse sends no host a grammar to decode by.
func (def tool) description() string {
	if def.Type != "custom" || def.Format.Type != "grammar" || def.Format.Definition == "" {
		return def.Description
	}
	grammar := fmt.Sprintf("The input must follow this %s grammar:\n%s", def.Format.Syntax, def.Format.Definition)
	if def.Description == "" {
		return grammar
	}
	return def.Description + "\n\n" + grammar
}

var customParameters = json.RawMessage(`{"type":"object","properties":{"input":{"type":"string","description":"The tool's whole input, as freeform text."}},"required":["input"],"additionalProperties":false}`)

func (t *tools) functions(raw json.RawMessage, at, namespace string) ([]any, error) {
	var def tool
	if json.Unmarshal(raw, &def) != nil {
		return nil, invalid(at, "Each tool must be an object with a type.")
	}
	switch {
	case def.Type == "namespace" && namespace == "":
		return t.namespace(def, at)
	case def.Type == "function", def.Type == "custom" && namespace == "":
	case def.Type == "":
		return nil, invalid(at+".type", "Missing required parameter: 'tools[].type'.")
	case namespace != "":
		return nil, unsupported(at+".type", fmt.Sprintf("A %s tool in a namespace is not supported: Morse takes function tools in a namespace.", def.Type))
	default:
		return nil, unsupported(at+".type", fmt.Sprintf("The %s tool is not supported: Morse serves function, custom, and namespace tools only, not OpenAI's built-in tools. Send the request without it.", def.Type))
	}
	if def.Name == "" {
		return nil, invalid(at+".name", "Missing required parameter: 'tools[].name'.")
	}
	name := def.Name
	if namespace != "" {
		q := qualified{namespace: namespace, name: def.Name}
		name = q.flat()
		t.namespaced[name] = q
	}
	function := map[string]any{"name": name}
	if description := def.description(); description != "" {
		function["description"] = description
	}
	switch {
	case def.Type == "custom":
		t.custom[name] = true
		function["parameters"] = customParameters
	case !null(def.Parameters):
		function["parameters"] = def.Parameters
	}
	if def.Type == "function" && !null(def.Strict) {
		function["strict"] = def.Strict
	}
	return []any{map[string]any{"type": "function", "function": function}}, nil
}

func (t *tools) namespace(def tool, at string) ([]any, error) {
	if def.Name == "" {
		return nil, invalid(at+".name", "Missing required parameter: 'tools[].name'.")
	}
	var functions []any
	for i, raw := range def.Tools {
		fs, err := t.functions(raw, fmt.Sprintf("%s.tools[%d]", at, i), def.Name)
		if err != nil {
			return nil, err
		}
		functions = append(functions, fs...)
	}
	return functions, nil
}

func toolsOf(rawTools, rawChoice json.RawMessage, out map[string]any) (tools, error) {
	t := tools{custom: map[string]bool{}, namespaced: map[string]qualified{}, choice: rawChoice}
	if !null(rawTools) {
		var list []json.RawMessage
		if json.Unmarshal(rawTools, &list) != nil {
			return t, invalid("tools", "tools must be an array of tools.")
		}
		var functions []any
		for i, raw := range list {
			fs, err := t.functions(raw, fmt.Sprintf("tools[%d]", i), "")
			if err != nil {
				return t, err
			}
			functions = append(functions, fs...)
			t.echo = append(t.echo, raw)
		}
		if len(functions) > 0 {
			out["tools"] = functions
		}
	}
	if null(rawChoice) {
		return t, nil
	}
	var mode string
	if json.Unmarshal(rawChoice, &mode) == nil {
		if !slices.Contains([]string{"auto", "none", "required"}, mode) {
			return t, invalid("tool_choice", `tool_choice must be "auto", "none", "required", or a function or custom tool by name.`)
		}
		out["tool_choice"] = mode
		return t, nil
	}
	var named struct{ Type, Name, Namespace string }
	if json.Unmarshal(rawChoice, &named) != nil {
		return t, invalid("tool_choice", "tool_choice must be a string or an object with a type.")
	}
	switch named.Type {
	case "function", "custom":
		if named.Name == "" {
			return t, invalid("tool_choice.name", "Missing required parameter: 'tool_choice.name'.")
		}
		name := named.Name
		if named.Namespace != "" {
			name = qualified{namespace: named.Namespace, name: named.Name}.flat()
		}
		out["tool_choice"] = map[string]any{"type": "function", "function": map[string]string{"name": name}}
	default:
		return t, unsupported("tool_choice", fmt.Sprintf("A tool_choice of type %s is not supported: Morse takes \"auto\", \"none\", \"required\", or a function or custom tool by name.", named.Type))
	}
	return t, nil
}

type reasoning struct {
	Effort          *string `json:"effort"`
	Summary         *string `json:"summary"`
	GenerateSummary *string `json:"generate_summary"`
}

func (r reasoning) summarized() bool {
	return r.Summary != nil && *r.Summary != "none" || r.GenerateSummary != nil && *r.GenerateSummary != "none"
}

func reasoningOf(raw json.RawMessage, out map[string]any) (reasoning, error) {
	var r reasoning
	if null(raw) {
		return r, nil
	}
	if json.Unmarshal(raw, &r) != nil {
		return r, invalid("reasoning", "reasoning must be an object.")
	}
	if r.Effort != nil {
		if !slices.Contains(chat.EffortLadder, *r.Effort) {
			return r, invalid("reasoning.effort", fmt.Sprintf("reasoning.effort must be one of %s.", strings.Join(chat.EffortLadder, ", ")))
		}
		out["reasoning_effort"] = *r.Effort
	}
	return r, nil
}

func textOf(raw json.RawMessage) error {
	if null(raw) {
		return nil
	}
	var text struct {
		Format *struct {
			Type string `json:"type"`
		} `json:"format"`
	}
	if json.Unmarshal(raw, &text) != nil {
		return invalid("text", "text must be an object.")
	}
	if text.Format != nil && text.Format.Type != "text" {
		return unsupported("text.format", "text.format is supported only as {\"type\":\"text\"}: Morse serves structured outputs on no model. Send the request without text.format.")
	}
	return nil
}

const openAIDefaultSampling = 1.0

func samplingOf(req request, out map[string]any) {
	if req.Temperature != nil && *req.Temperature != openAIDefaultSampling {
		out["temperature"] = *req.Temperature
	}
	if req.TopP != nil && *req.TopP != openAIDefaultSampling {
		out["top_p"] = *req.TopP
	}
}
