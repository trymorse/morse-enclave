package morph

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"morse/backend/internal/chat"
)

func TestAChatGoesToMorphsChatPathWithTheKeyAndTheUpstreamModelAndMaxTokens(t *testing.T) {
	var path, auth, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		path, auth, body = r.URL.Path, r.Header.Get("Authorization"), string(raw)
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":1,"model":"morph-dsv41flash-1017","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
	}))
	t.Cleanup(srv.Close)
	req, err := chat.ParseRequest(strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := NewChat(srv.URL, "mk", "morph-dsv41flash-1017", srv.Client()).Complete(context.Background(), chat.Call{Request: req, OutputLimit: 64})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reply.WriteTo(&out)
	if path != "/v1/chat/completions" || auth != "Bearer mk" {
		t.Errorf("Morph saw %s with %q, want /v1/chat/completions with the bearer key", path, auth)
	}
	if !strings.Contains(body, `"model":"morph-dsv41flash-1017"`) || !strings.Contains(body, `"max_tokens":64`) {
		t.Errorf("Morph was sent %s, want its own model id and max_tokens", body)
	}
	if !strings.Contains(out.String(), `"hi"`) {
		t.Errorf("reply %s lost the content", out.String())
	}
}
