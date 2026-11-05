package fireworks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
)

type seen struct {
	header http.Header
	body   string
}

const (
	usageOnEveryChunk = `data: {"id":"x","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"prompt_tokens_details":{"cached_tokens":2}}}` + "\n\n" + `data: {"id":"x","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"prompt_tokens_details":{"cached_tokens":2}}}` + "\n\ndata: [DONE]\n\n"
	usageChunkLast    = `data: {"id":"x","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}` + "\n\n" + `data: {"id":"x","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"prompt_tokens_details":{"cached_tokens":2}}}` + "\n\ndata: [DONE]\n\n"
)

func record(t *testing.T) (*openaicompat.Provider, func() []seen) {
	t.Helper()
	return recordStreaming(t, usageOnEveryChunk)
}

func recordStreaming(t *testing.T, stream string) (*openaicompat.Provider, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{r.Header.Clone(), string(raw)})
		mu.Unlock()
		if r.URL.Path != "/inference/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer fk" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, stream)
			return
		}
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"prompt_tokens_details":{"cached_tokens":2}}}`)
	}))
	t.Cleanup(srv.Close)
	return NewChat(srv.URL+"/inference", "fk", "accounts/fireworks/models/glm-5p3", srv.Client()), func() []seen {
		mu.Lock()
		defer mu.Unlock()
		return append([]seen(nil), got...)
	}
}

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func affinityOfCall(t *testing.T, body string) (string, bool) {
	t.Helper()
	return Affinity(call(t, body))
}

const system = `{"role":"system","content":"be brief"}`

func TestAConversationKeepsOneAffinityAsItGrowsAndAnotherGetsAnother(t *testing.T) {
	first, ok := affinityOfCall(t, `{"model":"m","messages":[`+system+`,{"role":"user","content":"hello"}]}`)
	if !ok || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("affinity = %q, %t", first, ok)
	}
	later, _ := affinityOfCall(t, `{"model":"m","user":"alice","messages":[`+system+`,{"role":"user","content":"hello"},{"role":"assistant","content":"hi"},{"role":"user","content":"more"}]}`)
	if later != first {
		t.Errorf("a later turn got %q, want %q", later, first)
	}
	other, _ := affinityOfCall(t, `{"model":"m","messages":[`+system+`,{"role":"user","content":"different"}]}`)
	if other == first {
		t.Error("two conversations share an affinity")
	}
}

func TestAnAffinityComesFromTheRequestsContentAlone(t *testing.T) {
	body := `{"model":"m","messages":[` + system + `,{"role":"user","content":"hello"}]}`
	base, _ := affinityOfCall(t, body)
	for name, extra := range map[string]string{
		"user":              `"user":"acct-1"`,
		"metadata":          `"metadata":{"account":"acct-1"}`,
		"safety_identifier": `"safety_identifier":"acct-1"`,
		"session_id":        `"session_id":"chat-7"`,
		"prompt_cache_key":  `"prompt_cache_key":"user-42"`,
	} {
		got, _ := affinityOfCall(t, `{`+extra+`,`+body[1:])
		if got != base {
			t.Errorf("%s changed the affinity", name)
		}
	}
}

func TestARequestWithNoStableOpeningGetsNoAffinity(t *testing.T) {
	for name, body := range map[string]string{
		"no messages": `{"model":"m"}`,
		"image":       `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}]}]}`,
		"no user":     `{"model":"m","messages":[` + system + `]}`,
		"huge":        `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", maxMaterial+1) + `"}]}`,
	} {
		if got, ok := affinityOfCall(t, body); ok {
			t.Errorf("%s got affinity %q", name, got)
		}
	}
}

func TestEveryCallCarriesTheAffinityAndNothingTheCallerIsKnownBy(t *testing.T) {
	p, sent := record(t)
	body := `{"model":"m","user":"alice","metadata":{"k":"v"},"store":true,"messages":[` + system + `,{"role":"user","content":"hello"}]}`
	if _, _, err := p.Complete(context.Background(), call(t, body)); err != nil {
		t.Fatal(err)
	}
	usage, err := p.Stream(context.Background(), call(t, body), func(chat.Chunk) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if usage.CachedPromptTokens != 2 {
		t.Errorf("stream usage = %+v, want 2 cached prompt tokens", usage)
	}
	want, _ := affinityOfCall(t, body)
	got := sent()
	if len(got) != 2 {
		t.Fatalf("sent %d requests", len(got))
	}
	for i, s := range got {
		if s.header.Get(AffinityHeader) != want {
			t.Errorf("request %d affinity = %q, want %q", i, s.header.Get(AffinityHeader), want)
		}
		for _, banned := range []string{`"user":`, `"metadata"`, `"store"`, "alice"} {
			if strings.Contains(s.body, banned) {
				t.Errorf("request %d body carries %s: %s", i, banned, s.body)
			}
		}
		if !strings.Contains(s.body, `"max_tokens":64`) || strings.Contains(s.body, "max_completion_tokens") {
			t.Errorf("request %d limit: %s", i, s.body)
		}
	}
}

func TestACallWithNoOpeningSendsNoAffinityHeader(t *testing.T) {
	p, sent := record(t)
	if _, _, err := p.Complete(context.Background(), call(t, `{"model":"m","messages":[`+system+`]}`)); err != nil {
		t.Fatal(err)
	}
	if got := sent()[0].header.Values(AffinityHeader); len(got) != 0 {
		t.Errorf("sent affinity %v", got)
	}
}

func TestConversationsThatShareAClientKeyStillGetTheirOwnAffinity(t *testing.T) {
	for _, field := range []string{"session_id", "prompt_cache_key"} {
		p, sent := record(t)
		for _, opening := range []string{"hello", "different"} {
			body := `{"model":"m","` + field + `":"user-42","messages":[` + system + `,{"role":"user","content":"` + opening + `"}]}`
			if _, _, err := p.Complete(context.Background(), call(t, body)); err != nil {
				t.Fatal(err)
			}
		}
		got := sent()
		first, second := got[0].header.Get(AffinityHeader), got[1].header.Get(AffinityHeader)
		if first == "" || first == second {
			t.Errorf("two conversations with %s user-42 sent affinities %q and %q", field, first, second)
		}
	}
}

func TestAStreamThatAskedForUsageEndsWithAUsageChunk(t *testing.T) {
	for name, stream := range map[string]string{"usage on every chunk": usageOnEveryChunk, "usage on its own chunk": usageChunkLast} {
		p, _ := recordStreaming(t, stream)
		c := call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[`+system+`,{"role":"user","content":"hello"}]}`)
		var chunks [][]byte
		if _, err := p.Stream(context.Background(), c, func(ch chat.Chunk) error {
			var b bytes.Buffer
			ch.WriteTo(&b)
			chunks = append(chunks, b.Bytes())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(chunks) != 2 {
			t.Fatalf("%s: client got %d chunks, want the reply and then the usage", name, len(chunks))
		}
		var reply, last struct {
			Choices []json.RawMessage `json:"choices"`
			Usage   *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(chunks[0], &reply); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(chunks[1], &last); err != nil {
			t.Fatal(err)
		}
		if len(reply.Choices) != 1 || reply.Usage != nil {
			t.Errorf("%s: reply chunk %s", name, chunks[0])
		}
		if len(last.Choices) != 0 || last.Usage == nil || last.Usage.PromptTokens != 3 || last.Usage.CompletionTokens != 1 {
			t.Errorf("%s: last chunk %s, want choices [] and usage 3/1", name, chunks[1])
		}
	}
}
