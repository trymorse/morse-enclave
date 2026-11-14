package responses

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
)

func chunk(s string) chat.Chunk { return chat.NewChunk([]byte(s)) }

func encoderFor(t *testing.T, body string) dialect.Encoder {
	t.Helper()
	d, err := Decode([]byte(body), knows("m"))
	if err != nil {
		t.Fatal(err)
	}
	return d.Reply()
}

func events(t *testing.T, evs []dialect.Event) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ev := range evs {
		var data map[string]any
		json.Unmarshal(ev.Data, &data)
		if data["type"] != ev.Name {
			t.Fatalf("event %s has type %v", ev.Name, data["type"])
		}
		if ev.Unpadded {
			t.Errorf("event %s goes unpadded", ev.Name)
		}
		out = append(out, data)
	}
	return out
}

func streamed(t *testing.T, e dialect.Encoder, chunks []string, u chat.Usage) []map[string]any {
	t.Helper()
	var evs []dialect.Event
	for _, c := range chunks {
		evs = append(evs, e.Chunk(chunk(c))...)
	}
	return events(t, append(evs, e.End(u)...))
}

func types(events []map[string]any) string {
	var out []string
	for _, e := range events {
		out = append(out, strings.TrimPrefix(e["type"].(string), "response."))
	}
	return strings.Join(out, " ")
}

const (
	plain          = `{"model":"m","input":"hi","stream":true}`
	summarized     = `{"model":"m","input":"hi","stream":true,"reasoning":{"effort":"low","summary":"auto"}}`
	reasoningChunk = `{"choices":[{"index":0,"delta":{"reasoning_content":"thinking it over"}}]}`
	textChunk      = `{"choices":[{"index":0,"delta":{"content":"hello"}}]}`
	stopChunk      = `{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	lengthChunk    = `{"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}`
)

func TestATextReplyIsOpenAIsEventsNumberedInOrder(t *testing.T) {
	got := streamed(t, encoderFor(t, plain), []string{textChunk, textChunk, stopChunk}, chat.Usage{PromptTokens: 1000, CachedPromptTokens: 600, CacheWritePromptTokens: 300, CompletionTokens: 50, ReasoningTokens: 20})
	if want := "created in_progress output_item.added content_part.added output_text.delta output_text.delta output_text.done content_part.done output_item.done completed"; types(got) != want {
		t.Fatalf("%s\nwant %s", types(got), want)
	}
	for i, e := range got {
		if e["sequence_number"] != float64(i) {
			t.Errorf("event %d (%s) is numbered %v", i, e["type"], e["sequence_number"])
		}
	}
	if done := got[6]; done["text"] != "hellohello" {
		t.Errorf("output_text.done carries %v", done["text"])
	}
	response := got[len(got)-1]["response"].(map[string]any)
	if response["status"] != "completed" || response["model"] != "m" || response["store"] != false || !strings.HasPrefix(response["id"].(string), "resp_") {
		t.Errorf("the completed response is %v", response)
	}
	if got, want := asJSON(response["usage"]), `{"input_tokens":1000,"input_tokens_details":{"cached_tokens":600},"output_tokens":50,"output_tokens_details":{"reasoning_tokens":20},"total_tokens":1050}`; got != want {
		t.Errorf("usage %s, want %s", got, want)
	}
	if got, want := asJSON(response["output"]), `[{"content":[{"annotations":[],"logprobs":[],"text":"hellohello","type":"output_text"}],"id":"`+got[2]["item"].(map[string]any)["id"].(string)+`","role":"assistant","status":"completed","type":"message"}]`; got != want {
		t.Errorf("output %s, want %s", got, want)
	}
}

func TestAReplyCutAtItsLimitIsIncomplete(t *testing.T) {
	got := streamed(t, encoderFor(t, plain), []string{textChunk, lengthChunk}, chat.Usage{})
	last := got[len(got)-1]
	response := last["response"].(map[string]any)
	if last["type"] != "response.incomplete" || response["status"] != "incomplete" || asJSON(response["incomplete_details"]) != `{"reason":"max_output_tokens"}` {
		t.Errorf("ended as %v", last)
	}
}

func TestReasoningIsSummarizedOnlyForAClientThatAskedForIt(t *testing.T) {
	asked := streamed(t, encoderFor(t, summarized), []string{reasoningChunk, textChunk}, chat.Usage{})
	if want := "created in_progress output_item.added reasoning_summary_part.added reasoning_summary_text.delta output_item.added content_part.added output_text.delta " +
		"reasoning_summary_text.done reasoning_summary_part.done output_item.done output_text.done content_part.done output_item.done completed"; types(asked) != want {
		t.Errorf("asked: %s\nwant:  %s", types(asked), want)
	}
	if item := asked[len(asked)-1]["response"].(map[string]any)["output"].([]any)[0]; asJSON(item.(map[string]any)["summary"]) != `[{"text":"thinking it over","type":"summary_text"}]` {
		t.Errorf("the reasoning item is %v", item)
	}
	unasked := streamed(t, encoderFor(t, plain), []string{reasoningChunk, textChunk}, chat.Usage{})
	if want := "created in_progress output_item.added content_part.added output_text.delta output_text.done content_part.done output_item.done completed"; types(unasked) != want {
		t.Errorf("unasked: %s\nwant:    %s", types(unasked), want)
	}
}

func TestParallelToolCallsAreAnItemEach(t *testing.T) {
	calls := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"f","arguments":"{\"x\":"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"g","arguments":""}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`,
	}
	got := streamed(t, encoderFor(t, `{"model":"m","input":"hi","stream":true,"tools":[{"type":"function","name":"f"},{"type":"function","name":"g"}]}`), calls, chat.Usage{})
	if want := "created in_progress output_item.added function_call_arguments.delta output_item.added function_call_arguments.delta function_call_arguments.delta " +
		"function_call_arguments.done output_item.done function_call_arguments.done output_item.done completed"; types(got) != want {
		t.Fatalf("%s\nwant %s", types(got), want)
	}
	if third := got[5]; third["output_index"] != 0.0 || third["delta"] != "1}" {
		t.Errorf("the first call's second delta is %v", third)
	}
	output := asJSON(got[len(got)-1]["response"].(map[string]any)["output"])
	for _, want := range []string{`"arguments":"{\"x\":1}","call_id":"a"`, `"arguments":"{}","call_id":"b"`, `"name":"g"`} {
		if !strings.Contains(output, want) {
			t.Errorf("output %s lacks %s", output, want)
		}
	}
}

func TestACustomToolCallIsItsFreeformInput(t *testing.T) {
	calls := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"apply_patch","arguments":"{\"input\":\"*** Begin"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":" Patch\"}"}}]},"finish_reason":"tool_calls"}]}`,
	}
	got := streamed(t, encoderFor(t, `{"model":"m","input":"hi","stream":true,"tools":[{"type":"custom","name":"apply_patch"}]}`), calls, chat.Usage{})
	if want := "created in_progress output_item.added custom_tool_call_input.delta custom_tool_call_input.done output_item.done completed"; types(got) != want {
		t.Fatalf("%s\nwant %s", types(got), want)
	}
	item := got[5]["item"].(map[string]any)
	if item["type"] != "custom_tool_call" || item["input"] != "*** Begin Patch" || item["call_id"] != "a" || !strings.HasPrefix(item["id"].(string), "ctc_") {
		t.Errorf("the custom call is %v", item)
	}
}

func TestContentTheClientDoesNotSeeYetIsFilledWithInProgress(t *testing.T) {
	customArgs := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"more patch"}}]}}]}`
	// output is the filler's Response output as OpenAI's Responses API types an in-progress item, with $id standing for
	// the id its output_item.added announced.
	for _, c := range []struct{ name, body, first, rest, want, output string }{
		{"hidden reasoning", plain, reasoningChunk, reasoningChunk, "created in_progress in_progress in_progress", `[]`},
		{"hidden reasoning after text", plain, textChunk, reasoningChunk,
			"created in_progress output_item.added content_part.added output_text.delta in_progress in_progress",
			`[{"content":[{"annotations":[],"logprobs":[],"text":"hello","type":"output_text"}],"id":"$id","role":"assistant","status":"in_progress","type":"message"}]`},
		{"a buffered custom tool call", `{"model":"m","input":"hi","stream":true,"tools":[{"type":"custom","name":"apply_patch"}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"apply_patch","arguments":""}}]}}]}`, customArgs,
			"created in_progress output_item.added in_progress in_progress",
			`[{"call_id":"a","id":"$id","input":"","name":"apply_patch","status":"in_progress","type":"custom_tool_call"}]`},
	} {
		at := time.Unix(1_800_000_000, 0)
		e := encoderFor(t, c.body).(*encoder)
		e.now = func() time.Time { return at }
		evs := e.Chunk(chunk(c.first))
		for _, step := range []time.Duration{5 * time.Second, 11 * time.Second, 5 * time.Second, 15 * time.Second} {
			at = at.Add(step)
			evs = append(evs, e.Chunk(chunk(c.rest))...)
		}
		got := events(t, evs)
		if types(got) != c.want {
			t.Errorf("%s over 36 seconds sent %s, want %s", c.name, types(got), c.want)
		}
		for i, ev := range got {
			if ev["sequence_number"] != float64(i) {
				t.Errorf("%s: event %d is numbered %v", c.name, i, ev["sequence_number"])
			}
		}
		filler := got[len(got)-1]["response"].(map[string]any)
		if filler["status"] != "in_progress" {
			t.Errorf("%s: the filler carries a response %v", c.name, filler["status"])
		}
		want := c.output
		for _, ev := range got {
			if ev["type"] == "response.output_item.added" {
				want = strings.ReplaceAll(want, "$id", ev["item"].(map[string]any)["id"].(string))
			}
		}
		if output := asJSON(filler["output"]); output != want {
			t.Errorf("%s: the filler's output is %s, want %s", c.name, output, want)
		}
	}
}

func TestAMidStreamFailureIsResponseFailed(t *testing.T) {
	e := encoderFor(t, plain)
	e.Chunk(chunk(textChunk))
	got := events(t, e.Failed(apierr.ErrUpstream))
	if len(got) != 1 || got[0]["type"] != "response.failed" {
		t.Fatalf("failed as %v", got)
	}
	response := got[0]["response"].(map[string]any)
	if response["status"] != "failed" || asJSON(response["error"]) != `{"code":"upstream_error","message":"The upstream model server failed."}` {
		t.Errorf("the failed response is %v", response)
	}
	if _, raised := got[0]["error"]; raised {
		t.Errorf("response.failed carries a top-level error, which the OpenAI SDKs raise before the client reads it")
	}
}

func TestAWholeReplyIsAResponse(t *testing.T) {
	whole := `{"choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"hmm","content":"hello","tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
	var response struct {
		Object, Status string
		Output         []map[string]any
		Usage          map[string]any
		Reasoning      map[string]any
		Tools          []map[string]any
		ToolChoice     any `json:"tool_choice"`
	}
	body := encoderFor(t, `{"model":"m","input":"hi","reasoning":{"effort":"low","summary":"auto"},"tools":[{"type":"function","name":"f"}],"tool_choice":"required"}`).Whole(chunk(whole), chat.Usage{PromptTokens: 10, CompletionTokens: 5})
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Object != "response" || response.Status != "completed" || len(response.Output) != 3 {
		t.Fatalf("the response is %s", body)
	}
	for i, want := range []string{"reasoning", "message", "function_call"} {
		if response.Output[i]["type"] != want {
			t.Errorf("output %d is %v, want %s", i, response.Output[i]["type"], want)
		}
	}
	if response.Usage["total_tokens"] != 15.0 || response.Reasoning["effort"] != "low" || response.ToolChoice != "required" || len(response.Tools) != 1 {
		t.Errorf("the response is %s", body)
	}
}

func TestANamespacesFunctionIsCalledWithinItsNamespace(t *testing.T) {
	calls := []string{`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"agents__close","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`}
	got := streamed(t, encoderFor(t, `{"model":"m","input":"hi","stream":true,"tools":[{"type":"namespace","name":"agents","tools":[{"type":"function","name":"close"}]}]}`), calls, chat.Usage{})
	item := got[len(got)-2]["item"].(map[string]any)
	if item["type"] != "function_call" || item["name"] != "close" || item["namespace"] != "agents" || item["arguments"] != "{}" {
		t.Errorf("the call is %v", item)
	}
}
