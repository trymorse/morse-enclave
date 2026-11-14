package messages

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
)

func knows(models ...string) func(string) bool {
	return func(m string) bool { return slices.Contains(models, m) }
}

func decoded(t *testing.T, body string) map[string]any {
	t.Helper()
	d, err := Decode([]byte(body), knows("glm-5.3", "anthropic/claude-opus-5.5"))
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if _, err := chat.ParseRequest(strings.NewReader(string(d.Body))); err != nil {
		t.Fatalf("the chat body %s does not parse: %v", d.Body, err)
	}
	var out map[string]any
	json.Unmarshal(d.Body, &out)
	return out
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const claudeCodeTurn = `{
	"model": "claude-opus-5-5",
	"max_tokens": 32000,
	"stream": true,
	"system": [{"type":"text","text":"x-anthropic-billing-header: cc"},{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
	"messages": [
		{"role":"user","content":[{"type":"text","text":"list files"}]},
		{"role":"assistant","content":[{"type":"thinking","thinking":"hmm","signature":"sig"},{"type":"text","text":"Listing."},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"a.go"}]},{"type":"text","text":"and now?","cache_control":{"type":"ephemeral"}}]},
		{"role":"system","content":"a reminder"}
	],
	"tools": [{"name":"Bash","description":"runs","input_schema":{"type":"object","properties":{"command":{"type":"string"}}}}],
	"thinking": {"type":"adaptive"},
	"output_config": {"effort":"high"},
	"temperature": 1,
	"metadata": {"user_id":"u"}
}`

func TestAClaudeCodeTurnDecodesToTheChatItMeans(t *testing.T) {
	out := decoded(t, claudeCodeTurn)
	want := map[string]string{
		"model":                 `"anthropic/claude-opus-5.5"`,
		"max_completion_tokens": `32000`,
		"stream":                `true`,
		"reasoning_effort":      `"high"`,
		"tools":                 `[{"function":{"description":"runs","name":"Bash","parameters":{"properties":{"command":{"type":"string"}},"type":"object"}},"type":"function"}]`,
		"messages": `[{"content":"x-anthropic-billing-header: cc\n\nYou are Claude Code.","role":"system"},` +
			`{"content":[{"text":"list files","type":"text"}],"role":"user"},` +
			`{"content":"Listing.","role":"assistant","tool_calls":[{"function":{"arguments":"{\"command\":\"ls\"}","name":"Bash"},"id":"toolu_1","type":"function"}]},` +
			`{"content":"a.go","role":"tool","tool_call_id":"toolu_1"},` +
			`{"content":[{"text":"and now?","type":"text"}],"role":"user"},` +
			`{"content":"a reminder","role":"system"}]`,
	}
	for field, value := range want {
		if got := asJSON(out[field]); got != value {
			t.Errorf("%s is %s, want %s", field, got, value)
		}
	}
	for _, dropped := range []string{"temperature", "metadata", "thinking", "output_config", "system"} {
		if _, ok := out[dropped]; ok {
			t.Errorf("%s reached the chat body: %v", dropped, out[dropped])
		}
	}
}

func TestToolChoicesAndSettingsMapOntoTheirChatFields(t *testing.T) {
	for _, c := range []struct{ extra, field, want string }{
		{`"tool_choice":{"type":"auto"}`, "tool_choice", `"auto"`},
		{`"tool_choice":{"type":"any"}`, "tool_choice", `"required"`},
		{`"tool_choice":{"type":"none"}`, "tool_choice", `"none"`},
		{`"tool_choice":{"type":"tool","name":"f"}`, "tool_choice", `{"function":{"name":"f"},"type":"function"}`},
		{`"tool_choice":{"type":"auto","disable_parallel_tool_use":true}`, "parallel_tool_calls", `false`},
		{`"thinking":{"type":"enabled","budget_tokens":1024}`, "reasoning_effort", `"low"`},
		{`"thinking":{"type":"enabled","budget_tokens":16000}`, "reasoning_effort", `"high"`},
		{`"thinking":{"type":"enabled","budget_tokens":64000}`, "reasoning_effort", `"max"`},
		{`"thinking":{"type":"enabled","budget_tokens":64000},"output_config":{"effort":"low"}`, "reasoning_effort", `"low"`},
		{`"stop_sequences":["END"]`, "stop", `["END"]`},
		{`"temperature":0.2`, "temperature", `0.2`},
		{`"top_p":0.9`, "top_p", `0.9`},
		{`"provider":{"min_privacy":"tee"}`, "provider", `{"min_privacy":"tee"}`},
	} {
		out := decoded(t, `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"}}],`+c.extra+`}`)
		if got := asJSON(out[c.field]); got != c.want {
			t.Errorf("%s: %s is %s, want %s", c.extra, c.field, got, c.want)
		}
	}
}

func TestOnlyAnthropicsOwnIDsForAClaudeModelAreTakenAsItsMorseName(t *testing.T) {
	for name, want := range map[string]string{
		"claude-opus-5-5":           "anthropic/claude-opus-5.5",
		"claude-opus-5-5-20261001":  "anthropic/claude-opus-5.5",
		"anthropic/claude-opus-5.5": "anthropic/claude-opus-5.5",
		"claude-sonnet-5-5":         "claude-sonnet-5-5",
		"glm-5.3":                   "glm-5.3",
	} {
		if got := modelOf(name, knows("glm-5.3", "anthropic/claude-opus-5.5")); got != want {
			t.Errorf("%s names %s, want %s", name, got, want)
		}
	}
}

func TestWhatMorseCannotServeIsRefusedNamingIt(t *testing.T) {
	user := func(blocks string) string {
		return `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":[` + blocks + `]}]}`
	}
	for _, c := range []struct{ body, says string }{
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`, "tools.0: Input tag 'code_execution_20250825'"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[]}}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"mcp_servers":[{"type":"url"}]}`, "mcp_servers: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"output_config":{"format":{"type":"json_schema","schema":{}}}}`, "output_config.format"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"top_k":5}`, "top_k"},
		{user(`{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"x"}}`), "messages.0.content.0: Morse does not take document blocks"},
		{user(`{"type":"image","source":{"type":"url","url":"https://e.com/a.png"}}`), "messages.0.content.0.source: Morse does not take an image linked by URL"},
		{user(`{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"x"}}]}`), "an image in a tool result"},
		{user(`{"type":"search_result","source":"s","title":"t","content":[]}`), "search_result blocks"},
		{`{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}`, "max_tokens: Field required"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"sometimes"}}`, "Input tag 'sometimes'"},
	} {
		_, err := Decode([]byte(c.body), knows("glm-5.3"))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal.Status != 400 || !strings.Contains(refusal.Message, c.says) {
			t.Errorf("%s: refused with %v, want a 400 saying %q", c.body, err, c.says)
		}
	}
}

func TestAnImageAttachedInlineIsADataURL(t *testing.T) {
	out := decoded(t, `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},{"type":"text","text":"what is it?"}]}]}`)
	want := `[{"content":[{"image_url":{"url":"data:image/png;base64,iVBORw0KGgo="},"type":"image_url"},{"text":"what is it?","type":"text"}],"role":"user"}]`
	if got := asJSON(out["messages"]); got != want {
		t.Errorf("messages %s, want %s", got, want)
	}
}

func chunk(s string) chat.Chunk { return chat.NewChunk([]byte(s)) }

func streamed(e dialect.Encoder, chunks []string, u chat.Usage) []map[string]any {
	var events []dialect.Event
	for _, c := range chunks {
		events = append(events, e.Chunk(chunk(c))...)
	}
	events = append(events, e.End(u)...)
	var out []map[string]any
	for _, ev := range events {
		var data map[string]any
		json.Unmarshal(ev.Data, &data)
		if data["type"] != ev.Name {
			panic("an event's name is not its type")
		}
		out = append(out, data)
	}
	return out
}

func types(events []map[string]any) string {
	var out []string
	for _, e := range events {
		typ := e["type"].(string)
		if block, ok := e["content_block"].(map[string]any); ok {
			typ += ":" + block["type"].(string)
		}
		if delta, ok := e["delta"].(map[string]any); ok && delta["type"] != nil {
			typ += ":" + delta["type"].(string)
		}
		out = append(out, typ)
	}
	return strings.Join(out, " ")
}

const (
	reasoningChunk = `{"choices":[{"index":0,"delta":{"reasoning_content":"thinking it over"}}]}`
	textChunk      = `{"choices":[{"index":0,"delta":{"content":"hello"}}]}`
	lengthChunk    = `{"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}`
)

func TestThinkingIsShownOnlyToAClientThatAskedForIt(t *testing.T) {
	asked := types(streamed(newEncoder("m", true), []string{reasoningChunk, textChunk}, chat.Usage{}))
	if want := "message_start content_block_start:thinking content_block_delta:thinking_delta content_block_stop content_block_start:text content_block_delta:text_delta content_block_stop message_delta message_stop"; asked != want {
		t.Errorf("asked: %s\nwant:  %s", asked, want)
	}
	unasked := types(streamed(newEncoder("m", false), []string{reasoningChunk, textChunk}, chat.Usage{}))
	if want := "message_start content_block_start:text content_block_delta:text_delta content_block_stop message_delta message_stop"; unasked != want {
		t.Errorf("unasked: %s\nwant:    %s", unasked, want)
	}
}

func TestTheFinishAndUsageEndTheMessage(t *testing.T) {
	events := streamed(newEncoder("m", false), []string{textChunk, lengthChunk}, chat.Usage{PromptTokens: 1000, CachedPromptTokens: 600, CacheWritePromptTokens: 300, CompletionTokens: 50})
	ending := events[len(events)-2]
	if stop := ending["delta"].(map[string]any)["stop_reason"]; stop != "max_tokens" {
		t.Errorf("stop_reason %v, want max_tokens", stop)
	}
	if got, want := asJSON(ending["usage"]), `{"cache_creation_input_tokens":300,"cache_read_input_tokens":600,"input_tokens":100,"output_tokens":50}`; got != want {
		t.Errorf("usage %s, want %s", got, want)
	}
}

func TestParallelToolCallsAreABlockEach(t *testing.T) {
	calls := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"f","arguments":"{}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"g","arguments":""}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"x\":1}"}}]},"finish_reason":"tool_calls"}]}`,
	}
	events := streamed(newEncoder("m", false), calls, chat.Usage{})
	if got, want := types(events), "message_start content_block_start:tool_use content_block_delta:input_json_delta content_block_stop content_block_start:tool_use content_block_delta:input_json_delta content_block_stop message_delta message_stop"; got != want {
		t.Errorf("%s\nwant %s", got, want)
	}
	if second := events[4]; second["index"] != 1.0 || second["content_block"].(map[string]any)["id"] != "b" {
		t.Errorf("the second call opened as %v", second)
	}
}

func TestAMidStreamFailureIsAnErrorEvent(t *testing.T) {
	events := newEncoder("m", false).Failed(apierr.ErrUpstream)
	if len(events) != 1 || events[0].Name != "error" || string(events[0].Data) != `{"error":{"message":"The upstream model server failed.","type":"api_error"},"type":"error"}` {
		t.Errorf("failed as %+v", events)
	}
}

func TestEachStatusIsAnthropicsErrorType(t *testing.T) {
	for status, want := range map[int]string{400: "invalid_request_error", 401: "authentication_error", 402: "billing_error", 403: "permission_error", 404: "not_found_error", 408: "invalid_request_error", 413: "request_too_large", 429: "rate_limit_error", 500: "api_error", 502: "api_error", 503: "overloaded_error"} {
		var envelope struct{ Error struct{ Type string } }
		json.Unmarshal(Envelope(apierr.Error{Status: status, Message: "m"}), &envelope)
		if envelope.Error.Type != want {
			t.Errorf("%d is %s, want %s", status, envelope.Error.Type, want)
		}
	}
}

func TestReasoningTheClientDoesNotSeeIsFilledWithPings(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	e := newEncoder("m", false)
	e.now = func() time.Time { return at }
	var got []string
	for _, step := range []time.Duration{0, 5 * time.Second, 11 * time.Second, 5 * time.Second, 15 * time.Second} {
		at = at.Add(step)
		for _, ev := range e.Chunk(chunk(reasoningChunk)) {
			got = append(got, ev.Name)
		}
	}
	if want := []string{"message_start", "ping", "ping"}; !slices.Equal(got, want) {
		t.Errorf("hidden reasoning over 36 seconds sent %v, want %v", got, want)
	}
}

func TestAFailedToolResultReachesTheModelAsAnError(t *testing.T) {
	turn := func(flag string) string {
		return `{"model":"glm-5.3","max_tokens":10,"messages":[` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Bash","input":{}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t"` + flag + `,"content":[{"type":"text","text":"no such file"}]}]}]}`
	}
	for flag, want := range map[string]string{
		`,"is_error":true`:  "Error: no such file",
		`,"is_error":false`: "no such file",
		``:                  "no such file",
	} {
		msgs := decoded(t, turn(flag))["messages"].([]any)
		if got := msgs[len(msgs)-1].(map[string]any)["content"]; got != want {
			t.Errorf("tool_result%s reached the model as %q, want %q", flag, got, want)
		}
	}
}
