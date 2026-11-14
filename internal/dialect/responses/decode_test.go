package responses

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

func knows(models ...string) func(string) bool {
	return func(m string) bool { return slices.Contains(models, m) }
}

func decoded(t *testing.T, body string) map[string]any {
	t.Helper()
	d, err := Decode([]byte(body), knows("glm-5.3", "openai/gpt-oss-120b"))
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

const codexTurn = `{
	"model": "gpt-oss-120b",
	"instructions": "You are Codex.",
	"input": [
		{"type":"message","role":"developer","content":[{"type":"input_text","text":"permissions"}]},
		{"type":"message","role":"user","content":[{"type":"input_text","text":"environment_context"}]},
		{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]},
		{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"hmm"}],"encrypted_content":"opaque"},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Listing."}]},
		{"type":"function_call","name":"shell","arguments":"{\"command\":[\"ls\"]}","call_id":"call_1"},
		{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch","call_id":"call_2"},
		{"type":"function_call_output","call_id":"call_1","output":"a.go"},
		{"type":"custom_tool_call_output","call_id":"call_2","output":[{"type":"input_text","text":"Done"}]}
	],
	"tools": [
		{"type":"function","name":"shell","description":"runs","strict":false,"parameters":{"type":"object","properties":{"command":{"type":"array"}}}},
		{"type":"custom","name":"apply_patch","description":"patches","format":{"type":"grammar","syntax":"lark","definition":"start: x"}},
		{"type":"custom","name":"note"}
	],
	"tool_choice": "auto",
	"parallel_tool_calls": false,
	"reasoning": {"effort":"high","summary":"auto"},
	"store": false,
	"stream": true,
	"include": ["reasoning.encrypted_content"],
	"prompt_cache_key": "k",
	"text": {"verbosity":"low"},
	"client_metadata": {"x":"y"}
}`

func TestACodexTurnDecodesToTheChatItMeans(t *testing.T) {
	out := decoded(t, codexTurn)
	var schema any
	json.Unmarshal(customParameters, &schema)
	wrapped := asJSON(schema)
	want := map[string]string{
		"model":               `"gpt-oss-120b"`,
		"stream":              `true`,
		"reasoning_effort":    `"high"`,
		"tool_choice":         `"auto"`,
		"parallel_tool_calls": `false`,
		"tools": `[{"function":{"description":"runs","name":"shell","parameters":{"properties":{"command":{"type":"array"}},"type":"object"},"strict":false},"type":"function"},` +
			`{"function":{"description":"patches\n\nThe input must follow this lark grammar:\nstart: x","name":"apply_patch","parameters":` + wrapped + `},"type":"function"},` +
			`{"function":{"name":"note","parameters":` + wrapped + `},"type":"function"}]`,
		"messages": `[{"content":"You are Codex.","role":"system"},` +
			`{"content":"permissions","role":"system"},` +
			`{"content":[{"text":"environment_context","type":"text"}],"role":"user"},` +
			`{"content":[{"text":"list files","type":"text"}],"role":"user"},` +
			`{"content":"Listing.","role":"assistant","tool_calls":[` +
			`{"function":{"arguments":"{\"command\":[\"ls\"]}","name":"shell"},"id":"call_1","type":"function"},` +
			`{"function":{"arguments":"{\"input\":\"*** Begin Patch\"}","name":"apply_patch"},"id":"call_2","type":"function"}]},` +
			`{"content":"a.go","role":"tool","tool_call_id":"call_1"},` +
			`{"content":"Done","role":"tool","tool_call_id":"call_2"}]`,
	}
	for field, value := range want {
		if got := asJSON(out[field]); got != value {
			t.Errorf("%s is %s, want %s", field, got, value)
		}
	}
	for _, dropped := range []string{"input", "instructions", "store", "include", "prompt_cache_key", "text", "client_metadata", "reasoning"} {
		if _, ok := out[dropped]; ok {
			t.Errorf("%s reached the chat body: %v", dropped, out[dropped])
		}
	}
}

func TestFieldsMapOntoTheirChatFields(t *testing.T) {
	for _, c := range []struct{ extra, field, want string }{
		{`"input":"hi"`, "messages", `[{"content":"hi","role":"user"}]`},
		{`"input":[{"role":"user","content":"hi"}]`, "messages", `[{"content":"hi","role":"user"}]`},
		{`"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AAAA","detail":"low"}]}]`, "messages", `[{"content":[{"image_url":{"detail":"low","url":"data:image/png;base64,AAAA"},"type":"image_url"}],"role":"user"}]`},
		{`"input":[{"type":"function_call","name":"f","arguments":"{}","call_id":"c"},{"type":"function_call_output","call_id":"c","output":"ok"}]`, "messages", `[{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{}","name":"f"},"id":"c","type":"function"}]},{"content":"ok","role":"tool","tool_call_id":"c"}]`},
		{`"input":[{"type":"function_call","name":"f","arguments":"{}","call_id":"a"},{"type":"function_call_output","call_id":"a","output":"1"},{"type":"function_call","name":"f","arguments":"{}","call_id":"b"},{"type":"function_call_output","call_id":"b","output":"2"}]`, "messages",
			`[{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{}","name":"f"},"id":"a","type":"function"}]},{"content":"1","role":"tool","tool_call_id":"a"},` +
				`{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{}","name":"f"},"id":"b","type":"function"}]},{"content":"2","role":"tool","tool_call_id":"b"}]`},
		{`"input":"hi","max_output_tokens":50`, "max_completion_tokens", `50`},
		{`"input":"hi","tool_choice":"required"`, "tool_choice", `"required"`},
		{`"input":"hi","tool_choice":{"type":"function","name":"f"}`, "tool_choice", `{"function":{"name":"f"},"type":"function"}`},
		{`"input":"hi","tool_choice":{"type":"function","namespace":"agents","name":"close"}`, "tool_choice", `{"function":{"name":"agents__close"},"type":"function"}`},
		{`"input":"hi","reasoning":{"effort":"minimal"}`, "reasoning_effort", `"minimal"`},
		{`"input":"hi","reasoning":{"effort":"none"}`, "reasoning_effort", `"none"`},
		{`"input":"hi","temperature":0.2`, "temperature", `0.2`},
		{`"input":"hi","top_p":0.9`, "top_p", `0.9`},
		{`"input":"hi","temperature":1,"top_p":1`, "temperature", `null`},
		{`"input":"hi","provider":{"min_privacy":"tee"}`, "provider", `{"min_privacy":"tee"}`},
		{`"input":"hi","tools":[{"type":"namespace","name":"agents","description":"subagents","tools":[{"type":"function","name":"close","parameters":{"type":"object"}}]}]`, "tools", `[{"function":{"name":"agents__close","parameters":{"type":"object"}},"type":"function"}]`},
		{`"input":[{"type":"function_call","namespace":"agents","name":"close","arguments":"{}","call_id":"c"},{"type":"function_call_output","call_id":"c","output":"ok"}]`, "messages", `[{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{}","name":"agents__close"},"id":"c","type":"function"}]},{"content":"ok","role":"tool","tool_call_id":"c"}]`},
		{`"input":"hi","store":false,"background":false,"previous_response_id":null,"truncation":"disabled","text":{"format":{"type":"text"}}`, "stream", `false`},
	} {
		out := decoded(t, `{"model":"glm-5.3",`+c.extra+`}`)
		if got := asJSON(out[c.field]); got != c.want {
			t.Errorf("%s: %s is %s, want %s", c.extra, c.field, got, c.want)
		}
	}
}

func TestWhatMorseCannotServeIsRefusedNamingIt(t *testing.T) {
	for _, c := range []struct{ extra, code, param, says string }{
		{`"previous_response_id":"resp_1"`, "unsupported_parameter", "previous_response_id", "keeps no responses"},
		{`"conversation":"conv_1"`, "unsupported_parameter", "conversation", "keeps no responses"},
		{`"store":true`, "unsupported_parameter", "store", "store: true"},
		{`"background":true`, "unsupported_parameter", "background", "background: true"},
		{`"truncation":"auto"`, "unsupported_parameter", "truncation", "disabled"},
		{`"prompt":{"id":"pmpt_1"}`, "unsupported_parameter", "prompt", "keeps no"},
		{`"tools":[{"type":"web_search"}]`, "unsupported_parameter", "tools[0].type", "web_search tool"},
		{`"tools":[{"type":"function","name":"f"},{"type":"file_search","vector_store_ids":[]}]`, "unsupported_parameter", "tools[1].type", "file_search tool"},
		{`"tools":[{"type":"code_interpreter"}]`, "unsupported_parameter", "tools[0].type", "code_interpreter"},
		{`"tools":[{"type":"computer_use_preview"}]`, "unsupported_parameter", "tools[0].type", "computer_use_preview"},
		{`"tools":[{"type":"mcp","server_label":"x"}]`, "unsupported_parameter", "tools[0].type", "mcp tool"},
		{`"tools":[{"type":"image_generation"}]`, "unsupported_parameter", "tools[0].type", "image_generation"},
		{`"tools":[{"type":"namespace","name":"n","tools":[{"type":"web_search"}]}]`, "unsupported_parameter", "tools[0].tools[0].type", "in a namespace"},
		{`"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[]}`, "unsupported_parameter", "tool_choice", "allowed_tools"},
		{`"text":{"format":{"type":"json_schema","name":"x","schema":{}}}`, "unsupported_parameter", "text.format", "structured outputs"},
		{`"reasoning":{"effort":"huge"}`, "invalid_parameter", "reasoning.effort", "must be one of"},
		{`"max_output_tokens":0`, "invalid_parameter", "max_output_tokens", "positive"},
	} {
		_, err := Decode([]byte(`{"model":"glm-5.3","input":"hi",`+c.extra+`}`), knows("glm-5.3"))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal.Status != 400 || refusal.Code != c.code || refusal.Param != c.param || !strings.Contains(refusal.Message, c.says) {
			t.Errorf("%s: %+v, want 400 %s naming %s and saying %q", c.extra, err, c.code, c.param, c.says)
		}
	}
	for _, c := range []struct{ input, param, says string }{
		{`[{"type":"item_reference","id":"msg_1"}]`, "input[0]", "item_reference"},
		{`[{"type":"web_search_call","id":"ws_1"}]`, "input[0].type", "web_search_call"},
		{`[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/a.png"}]}]`, "input[0].content[0].image_url", "linked by URL"},
		{`[{"role":"user","content":[{"type":"input_image","file_id":"file_1"}]}]`, "input[0].content[0].file_id", "file_id"},
		{`[{"role":"user","content":[{"type":"input_file","file_data":"x"}]}]`, "input[0].content[0]", "input_file"},
		{`[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":"data:x"}]}]`, "input[0].output[0]", "input_image"},
	} {
		_, err := Decode([]byte(`{"model":"glm-5.3","input":`+c.input+`}`), knows("glm-5.3"))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal.Status != 400 || refusal.Param != c.param || !strings.Contains(refusal.Message, c.says) {
			t.Errorf("%s: %+v, want 400 naming %s and saying %q", c.input, err, c.param, c.says)
		}
	}
}
