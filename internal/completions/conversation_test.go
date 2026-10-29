package completions

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

func parse(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 1024, RouteEffort: "low"}
}

func TestOptionsAreReadByExactKeySoACaseVariantIsAnUnknownField(t *testing.T) {
	const user = `"messages":[{"role":"user","content":"hi"}]`
	conv, err := parseConversation(parse(t, `{"model":"m","reasoning_effort":"high",`+user+`}`))
	if err != nil || conv.Effort != "high" {
		t.Fatalf("exact key: effort %q err %v, want the client's effort", conv.Effort, err)
	}
	for name, body := range map[string]string{
		"effort":    `{"model":"m","Reasoning_Effort":"high",` + user + `}`,
		"functions": `{"model":"m","FUNCTIONS":[{"name":"f"}],"Function_Call":"auto",` + user + `}`,
		"tools":     `{"model":"m","TOOLS":[{"type":"custom"}],"Tool_Choice":"sometimes","PARALLEL_TOOL_CALLS":"yes",` + user + `}`,
	} {
		conv, err := parseConversation(parse(t, body))
		if err != nil || conv.Effort != "low" || conv.Tools != nil || conv.Choice != nil || conv.Parallel != nil {
			t.Errorf("%s: %+v err %v, want the case variant ignored like any unknown field and the route default effort kept", name, conv, err)
		}
	}
}

func TestNestedToolKeysAreExactSoACaseVariantIsAnUnknownField(t *testing.T) {
	const user = `,"messages":[{"role":"user","content":"hi"}]}`
	conv, err := parseConversation(parse(t, `{"model":"m","tools":[{"type":"function","function":{"name":"f","Parameters":{"type":"string"}}}],"tool_choice":{"type":"function","function":{"name":"f"}}`+user))
	if err != nil || len(conv.Tools) != 1 || conv.Tools[0].Name != "f" || conv.Tools[0].Parameters != nil || conv.Choice == nil || conv.Choice.Name != "f" {
		t.Fatalf("exact keys: %+v err %v, want tool f with its case-variant Parameters ignored and choice f", conv, err)
	}
	for name, fields := range map[string]string{
		"tool Type":            `"tools":[{"Type":"function","function":{"name":"f"}}]`,
		"tool Function":        `"tools":[{"type":"function","Function":{"name":"f"}}]`,
		"tool Name":            `"tools":[{"type":"function","function":{"Name":"f"}}]`,
		"tool_choice Type":     `"tool_choice":{"Type":"function","function":{"name":"f"}}`,
		"tool_choice Function": `"tool_choice":{"type":"function","Function":{"name":"f"}}`,
		"tool_choice Name":     `"tool_choice":{"type":"function","function":{"NAME":"f"}}`,
	} {
		if _, err := parseConversation(parse(t, `{"model":"m",`+fields+user)); !errors.Is(err, errUnsupportedTool) {
			t.Errorf("%s: err %v, want the case variant read as a missing key and the tool refused", name, err)
		}
	}
}

func TestToolCallAndImageDetailKeysAreExactSoACaseVariantIsAnUnknownField(t *testing.T) {
	const user = `{"role":"user","content":"hi"}`
	call := func(fields string) string {
		return `{"model":"m","messages":[` + user + `,{"role":"assistant","content":null,"tool_calls":[{` + fields + `}]},{"role":"tool","tool_call_id":"c1","content":"ok"}]}`
	}
	image := func(fields string) string {
		return `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo=",` + fields + `}}]}]}`
	}
	conv, err := parseConversation(parse(t, call(`"id":"c1","type":"function","function":{"name":"f","ARGUMENTS":"{\"x\":1}"}`)))
	if err != nil || len(conv.Turns) != 3 || len(conv.Turns[1].Calls) != 1 || conv.Turns[1].Calls[0].Function.Arguments != EmptyArguments {
		t.Fatalf("exact keys: %+v err %v, want the call with its case-variant ARGUMENTS ignored", conv.Turns, err)
	}
	for name, fields := range map[string]string{
		"ID":       `"ID":"c1","type":"function","function":{"name":"f","arguments":"{}"}`,
		"Type":     `"id":"c1","Type":"function","function":{"name":"f","arguments":"{}"}`,
		"FUNCTION": `"id":"c1","type":"function","FUNCTION":{"name":"f","arguments":"{}"}`,
		"Name":     `"id":"c1","type":"function","function":{"Name":"f","arguments":"{}"}`,
	} {
		if _, err := parseConversation(parse(t, call(fields))); !errors.Is(err, errUnsupportedMessage) {
			t.Errorf("tool call %s: err %v, want the case variant read as a missing key and the call refused", name, err)
		}
	}
	conv, err = parseConversation(parse(t, image(`"DETAIL":"bogus"`)))
	if err != nil || len(conv.Turns) != 1 || len(conv.Turns[0].Parts) != 1 || conv.Turns[0].Parts[0].Image == nil || conv.Turns[0].Parts[0].Image.Detail != defaultDetail {
		t.Errorf("image DETAIL: %+v err %v, want the case variant ignored and the default detail", conv.Turns, err)
	}
	if _, err := parseConversation(parse(t, image(`"detail":"bogus"`))); !errors.Is(err, errUnsupportedMessage) {
		t.Errorf("image detail bogus: err %v, want the exact key read and refused", err)
	}
}

func TestUnsupportedShapesAreRefusedWithTheirCode(t *testing.T) {
	const user = `{"role":"user","content":"weather in Paris?"}`
	call := func(fields string) string {
		return `"messages":[` + user + `,{"role":"assistant","content":null,"tool_calls":[{` + fields + `}]}]`
	}
	part := func(p string) string {
		return `"messages":[{"role":"user","content":[` + p + `]}]`
	}
	for name, tc := range map[string]struct{ body, code string }{
		"custom tool":        {`"tools":[{"type":"custom","custom":{"name":"grep"}}],"messages":[` + user + `]`, "invalid_request"},
		"built-in tool":      {`"tools":[{"type":"web_search"}],"messages":[` + user + `]`, "invalid_request"},
		"nameless tool":      {`"tools":[{"type":"function","function":{"parameters":{"type":"object"}}}],"messages":[` + user + `]`, "invalid_request"},
		"array schema":       {`"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"array"}}}],"messages":[` + user + `]`, "invalid_request"},
		"string schema":      {`"tools":[{"type":"function","function":{"name":"f","parameters":"object"}}],"messages":[` + user + `]`, "invalid_request"},
		"unknown choice":     {`"tool_choice":"sometimes","messages":[` + user + `]`, "invalid_request"},
		"allowed_tools":      {`"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[]}},"messages":[` + user + `]`, "invalid_request"},
		"nameless choice":    {`"tool_choice":{"type":"function","function":{}},"messages":[` + user + `]`, "invalid_request"},
		"bad arguments":      {call(`"id":"call_1","type":"function","function":{"name":"f","arguments":"{nope"}`), "invalid_request"},
		"call without id":    {call(`"type":"function","function":{"name":"f","arguments":"{}"}`), "invalid_request"},
		"custom call":        {call(`"id":"call_1","type":"custom","custom":{"name":"f","input":"x"}`), "invalid_request"},
		"tool without id":    {`"messages":[` + user + `,{"role":"tool","content":"sunny"}]`, "invalid_request"},
		"tool image result":  {`"messages":[` + user + `,{"role":"tool","tool_call_id":"call_1","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]`, "invalid_request"},
		"system image":       {`"messages":[{"role":"system","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]`, "invalid_request"},
		"function role":      {`"messages":[{"role":"function","name":"f","content":"x"}]`, "invalid_request"},
		"mistyped parallel":  {`"parallel_tool_calls":"yes","messages":[` + user + `]`, "invalid_request"},
		"audio part":         {part(`{"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}}`), "invalid_request"},
		"file part":          {part(`{"type":"file","file":{"file_data":"data:application/pdf;base64,JVBERi0=","filename":"a.pdf"}}`), "invalid_request"},
		"svg image":          {part(`{"type":"image_url","image_url":{"url":"data:image/svg+xml;base64,PHN2Zz4="}}`), "invalid_request"},
		"unencoded image":    {part(`{"type":"image_url","image_url":{"url":"data:image/png,not-base64"}}`), "invalid_request"},
		"empty image":        {part(`{"type":"image_url","image_url":{"url":"data:image/png;base64,"}}`), "invalid_request"},
		"original detail":    {part(`{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo=","detail":"original"}}`), "invalid_request"},
		"remote image":       {part(`{"type":"image_url","image_url":{"url":"https://cdn.example/cat.png?user=u-1"}}`), "remote_media"},
		"remote file":        {part(`{"type":"file","file":{"file_id":"file-123"}}`), "remote_media"},
		"messages not array": {`"messages":"hi"`, "invalid_request"},
		"unknown role":       {`"messages":[{"role":"narrator","content":"x"}]`, "invalid_request"},
	} {
		_, err := parseConversation(parse(t, `{"model":"m",`+tc.body+`}`))
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal.Status != http.StatusBadRequest {
			t.Errorf("%s: err %v, want a 400 refusal", name, err)
			continue
		}
		if body := string(refusal.Envelope()); !strings.Contains(body, `"code":"`+tc.code+`"`) || strings.Contains(body, "example") {
			t.Errorf("%s: body %s, want code %s", name, body, tc.code)
		}
	}
}

func TestAlternatingMergesEachSidesTurnsAndOpensOnTheUser(t *testing.T) {
	const call = `{"id":"call_1","type":"function","function":{"name":"time","arguments":"{}"}}`
	sides := func(body string) (system []string, got []string) {
		conv, err := parseConversation(parse(t, body))
		if err != nil {
			t.Fatal(err)
		}
		system, exchanges := conv.Alternating()
		for _, x := range exchanges {
			side := "user"
			if x.FromModel {
				side = "model"
			}
			for _, turn := range x.Turns {
				side += " " + turn.Text
				for _, part := range turn.Parts {
					side += part.Text
				}
			}
			got = append(got, side)
		}
		return system, got
	}
	for name, tc := range map[string]struct {
		messages string
		system   []string
		want     []string
	}{
		"merged": {
			`{"role":"system","content":"S1"},{"role":"user","content":"a"},{"role":"developer","content":"S2"},{"role":"user","content":"b"},` +
				`{"role":"assistant","content":"c","tool_calls":[` + call + `]},{"role":"assistant","content":"d"},` +
				`{"role":"tool","tool_call_id":"call_1","content":"noon"},{"role":"user","content":"e"}`,
			[]string{"S1", "S2"}, []string{"user a b", "model c d", "user noon e"},
		},
		"opened by the model": {`{"role":"assistant","content":"hello"},{"role":"user","content":"hi"}`, nil, []string{"user (The conversation begins.)", "model hello", "user hi"}},
		"system text alone":   {`{"role":"system","content":"S"}`, []string{"S"}, []string{"user (The conversation begins.)"}},
		"an empty user turn":  {`{"role":"user","content":""}`, nil, []string{"user (The conversation begins.)"}},
		"no messages":         {``, nil, []string{"user (The conversation begins.)"}},
	} {
		system, got := sides(`{"model":"m","messages":[` + tc.messages + `]}`)
		if !slices.Equal(system, tc.system) || !slices.Equal(got, tc.want) {
			t.Errorf("%s: system %q exchanges %q, want %q and %q", name, system, got, tc.system, tc.want)
		}
	}
}

func TestAToolsSchemaIsAlwaysAnObjectSchema(t *testing.T) {
	for parameters, want := range map[string]string{
		``: `{"type":"object"}`,
		`{"properties":{"city":{"type":"string"}}}`: `{"properties":{"city":{"type":"string"}},"type":"object"}`,
	} {
		if got := string(Tool{Parameters: json.RawMessage(parameters)}.Schema()); got != want {
			t.Errorf("schema of %q is %s, want %s", parameters, got, want)
		}
	}
}
