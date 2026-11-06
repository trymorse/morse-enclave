package novita

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"morse/backend/internal/chat"
)

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func TestAReplyNovitaStreamedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"*She smiles.* "}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"","reasoning":"\"Follow me.\""}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`+"\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	var content string
	var finished bool
	_, err := NewChat(srv.URL, "sk-nv", "inclusionai/ling-3.0-flash", true, srv.Client()).Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(ch chat.Chunk) error {
		d := ch.Delta()
		if finished && d.Content != "" {
			t.Errorf("content %q arrived after the finishing chunk", d.Content)
		}
		content += d.Content
		finished = finished || d.Finish == chat.FinishStop
		return nil
	})
	if err != nil || content != `*She smiles.* "Follow me."` || !finished {
		t.Fatalf("content %q finished %t err %v, want the reasoning as content before the finish", content, finished, err)
	}
}

func TestAReplyNovitaCompletedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `{"id":"gen-1","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning":"*She smiles.* \"Follow me.\""},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`)
	}))
	t.Cleanup(srv.Close)
	chunk, _, err := NewChat(srv.URL, "sk-nv", "inclusionai/ling-3.0-flash", true, srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if d := chunk.Delta(); err != nil || d.Content != `*She smiles.* "Follow me."` || d.Finish != chat.FinishStop {
		t.Fatalf("content %q finish %s err %v, want the reasoning as content", d.Content, d.Finish, err)
	}
}
