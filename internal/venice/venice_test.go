package venice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

const reply = `{"id":"chatcmpl-v","object":"chat.completion","created":1,"model":"deepseek-v4-1-flash-uncensored","choices":[{"index":0,"message":{"role":"assistant","content":"hi","reasoning_content":"think"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"cost":{"usd":0.0004,"diem":0.0004},"prompt_tokens_details":{"cached_tokens":1},"completion_tokens_details":{"reasoning_tokens":1}}}`

type recorder struct {
	srv  *httptest.Server
	sent []map[string]json.RawMessage
}

func record(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]json.RawMessage
		json.NewDecoder(req.Body).Decode(&body)
		r.sent = append(r.sent, body)
		if req.URL.Path != "/api/v1/chat/completions" || req.Header.Get("Authorization") != "Bearer vk" {
			http.NotFound(w, req)
			return
		}
		if string(body["stream"]) == "true" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, `data: {"id":"chatcmpl-v","choices":[{"index":0,"delta":{"reasoning_content":"think"}}]}`+"\n\n")
			io.WriteString(w, `data: {"id":"chatcmpl-v","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}`+"\n\n")
			io.WriteString(w, `data: {"id":"chatcmpl-v","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"cost":{"usd":0.0004,"diem":0.0004}}}`+"\n\n")
			io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		io.WriteString(w, reply)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) chat() *Chat {
	return NewChat(r.srv.URL+"/api", "vk", "deepseek-v4-1-flash-uncensored", r.srv.Client())
}

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func TestEveryRequestTurnsOffVenicesPromptAndSearchWhateverTheClientSends(t *testing.T) {
	r := record(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` +
		`"venice_parameters":{"include_venice_system_prompt":true,"enable_web_search":"on","enable_web_scraping":true,"enable_x_search":true,"character_slug":"x"}}`
	if _, _, err := r.chat().Complete(context.Background(), call(t, body)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.chat().Stream(context.Background(), call(t, body), func(chat.Chunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(r.sent) != 2 {
		t.Fatalf("sent %d requests, want 2", len(r.sent))
	}
	for i, sent := range r.sent {
		if string(sent["venice_parameters"]) != string(Parameters) {
			t.Errorf("request %d sent venice_parameters %s, want %s", i, sent["venice_parameters"], Parameters)
		}
		if string(sent["model"]) != `"deepseek-v4-1-flash-uncensored"` || string(sent["max_completion_tokens"]) != "64" {
			t.Errorf("request %d sent model %s max_completion_tokens %s", i, sent["model"], sent["max_completion_tokens"])
		}
		if _, ok := sent["max_tokens"]; ok {
			t.Errorf("request %d sent max_tokens, which Venice deprecates", i)
		}
	}
}

func TestASearchVeniceWouldRunItselfIsRefusedBeforeItIsSent(t *testing.T) {
	r := record(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search"}]}`
	if _, _, err := r.chat().Complete(context.Background(), call(t, body)); !errors.Is(err, apierr.ErrMalformedRequest) {
		t.Errorf("Complete gave %v, want it refused as malformed", err)
	}
	if _, err := r.chat().Stream(context.Background(), call(t, body), func(chat.Chunk) error { return nil }); !errors.Is(err, apierr.ErrMalformedRequest) {
		t.Errorf("Stream gave %v, want it refused as malformed", err)
	}
	if len(r.sent) != 0 {
		t.Errorf("sent %d refused requests upstream", len(r.sent))
	}
}

func TestTheClientIsNotShownWhatVeniceChargedUs(t *testing.T) {
	r := record(t)
	chunk, usage, err := r.chat().Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := (chat.Usage{PromptTokens: 3, CompletionTokens: 2, CachedPromptTokens: 1, ReasoningTokens: 1}); usage != want {
		t.Errorf("usage %+v, want %+v", usage, want)
	}
	var out strings.Builder
	chunk.WriteTo(&out)
	for _, leak := range []string{"cost", "diem", "chatcmpl-v"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("the reply names %q: %s", leak, out.String())
		}
	}
	if !strings.Contains(out.String(), `"reasoning_content":"think"`) {
		t.Errorf("the reply dropped the reasoning: %s", out.String())
	}
	var streamed strings.Builder
	usage, err = r.chat().Stream(context.Background(), call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`), func(c chat.Chunk) error {
		c.WriteTo(&streamed)
		return nil
	})
	if err != nil || usage.PromptTokens != 3 || usage.CompletionTokens != 2 {
		t.Fatalf("stream usage %+v err %v", usage, err)
	}
	for _, leak := range []string{"cost", "diem"} {
		if strings.Contains(streamed.String(), leak) {
			t.Errorf("the stream names %q: %s", leak, streamed.String())
		}
	}
	if !strings.Contains(streamed.String(), `"reasoning_content":"think"`) || !strings.Contains(streamed.String(), `"prompt_tokens":3`) {
		t.Errorf("the stream lost the reasoning or the usage the client asked for: %s", streamed.String())
	}
}

func TestOnlyTheCallsCacheKeyReachesVeniceAsPromptCacheKey(t *testing.T) {
	r := record(t)
	for _, key := range []string{"0123456789abcdef0123456789abcdef", ""} {
		c := call(t, `{"model":"m","prompt_cache_key":"pk-client","session_id":"end-user-42","messages":[{"role":"user","content":"hi"}]}`)
		c.CacheKey = key
		if _, _, err := r.chat().Complete(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := r.chat().Stream(context.Background(), c, func(chat.Chunk) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.sent) != 4 {
		t.Fatalf("sent %d requests, want 4", len(r.sent))
	}
	for i, sent := range r.sent {
		got, ok := sent["prompt_cache_key"]
		if want := i < 2; ok != want || want && string(got) != `"0123456789abcdef0123456789abcdef"` {
			t.Errorf("request %d sent prompt_cache_key %s, want the call's cache key %t", i, got, want)
		}
		if _, ok := sent["session_id"]; ok {
			t.Errorf("request %d sent the client's session_id", i)
		}
	}
}
