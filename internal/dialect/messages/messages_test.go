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
		{`"thinking":{"type":"disabled"}`, "reasoning_effort", `"none"`},
		{`"thinking":{"type":"disabled"},"output_config":{"effort":"high"}`, "reasoning_effort", `"high"`},
		{`"thinking":{"type":"adaptive"}`, "reasoning_effort", `null`},
		{`"output_config":{"format":{"type":"json_schema","schema":{"type":"object","properties":{"city":{"type":"string"}}}}}`, "response_format", `{"json_schema":{"name":"output","schema":{"properties":{"city":{"type":"string"}},"type":"object"},"strict":true},"type":"json_schema"}`},
		{`"stop_sequences":["END"]`, "stop", `["END"]`},
		{`"top_k":5`, "top_k", `5`},
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

func TestWhatMorseCannotServeIsRefusedNamingIt(t *testing.T) {
	user := func(blocks string) string {
		return `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":[` + blocks + `]}]}`
	}
	for _, c := range []struct{ body, says string }{
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`, "tools.0: Input tag 'code_execution_20250825'"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"clear_tool_uses_20250919"}]}}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}}]}}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"},{"type":"clear_tool_uses_20250919"}]}}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all","trigger":{"type":"input_tokens","value":1}}]}}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"context_management":"all"}`, "context_management: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"mcp_servers":[{"type":"url"}]}`, "mcp_servers: Extra inputs are not permitted"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"output_config":{"format":{"type":"json_object"}}}`, "output_config.format: Input tag 'json_object'"},
		{`{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"output_config":{"format":{"type":"json_schema"}}}`, "output_config.format.schema: Field required"},
		{user(`{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"x"}}`), "messages.0.content.0: Morse does not take document blocks"},
		{user(`{"type":"image","source":{"type":"url","url":"https://e.com/a.png"}}`), "messages.0.content.0.source: Morse does not take an image linked by URL"},
		{user(`{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://e.com/a.png"}}]}`), "messages.0.content.0.content.0.source: Morse does not take an image linked by URL"},
		{user(`{"type":"tool_result","tool_use_id":"t","content":[{"type":"tool_reference","tool_name":"x"}]}`), "messages.0.content.0.content.0: Morse does not take tool_reference blocks"},
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

// why: Claude Code's Read returns a picture as an image block inside the tool result, and a Chat Completions tool
// message holds text alone.
func TestAnImageAToolReturnedFollowsTheTurnsToolMessages(t *testing.T) {
	image := func(data string) string {
		return `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + data + `"}}`
	}
	out := decoded(t, `{"model":"glm-5.3","max_tokens":10,"messages":[`+
		`{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"a.png"}},{"type":"tool_use","id":"t2","name":"Bash","input":{}},{"type":"tool_use","id":"t3","name":"Shot","input":{}}]},`+
		`{"role":"user","content":[`+
		`{"type":"tool_result","tool_use_id":"t1","content":[`+image("QQ==")+`]},`+
		`{"type":"tool_result","tool_use_id":"t2","content":"ok"},`+
		`{"type":"tool_result","tool_use_id":"t3","is_error":true,"content":[{"type":"text","text":"two views"},`+image("Qg==")+`,`+image("Qw==")+`]},`+
		`{"type":"text","text":"what colour is it?"}]}]}`)
	msgs := out["messages"].([]any)
	want := `[{"content":"[This tool returned image output. It is attached in the next message.]","role":"tool","tool_call_id":"t1"},` +
		`{"content":"ok","role":"tool","tool_call_id":"t2"},` +
		`{"content":"Error: two views\n\n[This tool returned image output. It is attached in the next message.]","role":"tool","tool_call_id":"t3"},` +
		`{"content":[{"text":"The image output of tool call t1:","type":"text"},{"image_url":{"url":"data:image/png;base64,QQ=="},"type":"image_url"},` +
		`{"text":"The image output of tool call t3:","type":"text"},{"image_url":{"url":"data:image/png;base64,Qg=="},"type":"image_url"},{"image_url":{"url":"data:image/png;base64,Qw=="},"type":"image_url"},` +
		`{"text":"what colour is it?","type":"text"}],"role":"user"}]`
	if got := asJSON(msgs[1:]); got != want {
		t.Errorf("after the assistant's calls the model got\n%s\nwant\n%s", got, want)
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

func TestATokenCountRequestNeedsNoMaxTokensAndAMessagesRequestDoes(t *testing.T) {
	for name, tc := range map[string]struct {
		decode func([]byte, func(string) bool) (dialect.Decoded, error)
		body   string
		limit  any
		err    string
	}{
		"a count with none":      {DecodeCount, `{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}`, nil, ""},
		"a count with one":       {DecodeCount, `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`, float64(10), ""},
		"a count with a bad one": {DecodeCount, `{"model":"glm-5.3","max_tokens":0,"messages":[{"role":"user","content":"hi"}]}`, nil, "max_tokens: Input should be a positive integer"},
		"a count with no model":  {DecodeCount, `{"messages":[{"role":"user","content":"hi"}]}`, nil, "model: Field required"},
		"a message with none":    {Decode, `{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}`, nil, "max_tokens: Field required"},
		"a message with one":     {Decode, `{"model":"glm-5.3","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`, float64(10), ""},
	} {
		d, err := tc.decode([]byte(tc.body), knows("glm-5.3"))
		var refusal apierr.Error
		if tc.err != "" {
			if !errors.As(err, &refusal) || refusal.Message != tc.err {
				t.Errorf("%s: %v, want %q", name, err, tc.err)
			}
			continue
		}
		var out map[string]any
		if err != nil || json.Unmarshal(d.Body, &out) != nil || out["max_completion_tokens"] != tc.limit {
			t.Errorf("%s: %s (%v), want max_completion_tokens %v", name, d.Body, err, tc.limit)
		}
	}
}
