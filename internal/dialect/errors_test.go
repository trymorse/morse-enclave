package dialect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/dialect"
)

var marked = dialect.Dialect{
	Decode: func([]byte, func(string) bool) (dialect.Decoded, error) { return dialect.Decoded{}, nil },
	Envelope: func(e apierr.Error) []byte {
		return []byte(`{"type":"error","code":"` + e.Code + `","param":"` + e.Param + `"}`)
	},
}

func TestARefusalLeavesInTheDialectsEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	w := marked.Errors(rec)
	refusal := apierr.Invalid(http.StatusBadRequest, "some_code", "nope").Naming("messages")
	envelope := refusal.Envelope()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(refusal.Status)
	w.Write(envelope[:5])
	if rec.Body.Len() != 0 {
		t.Fatalf("half a refusal reached the client: %q", rec.Body)
	}
	w.Write(envelope[5:])
	if got, want := rec.Body.String(), `{"type":"error","code":"some_code","param":"messages"}`; got != want || rec.Code != http.StatusBadRequest {
		t.Errorf("got %d %s, want 400 %s", rec.Code, got, want)
	}
}

func TestEveryOtherReplyPassesAsWritten(t *testing.T) {
	for _, c := range []struct {
		name, contentType, body string
		status                  int
	}{
		{"a reply", "application/json", `{"id":"x"}`, http.StatusOK},
		{"a stream", "text/event-stream", "data: {}\n\n", http.StatusOK},
		{"a refusal already in the dialect", "application/json", `{"type":"error","error":{"type":"invalid_request_error","message":"m"}}`, http.StatusBadRequest},
		{"a refusal that is not JSON", "text/plain", "nope", http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		w := marked.Errors(rec)
		w.Header().Set("Content-Type", c.contentType)
		w.WriteHeader(c.status)
		w.Write([]byte(c.body))
		if rec.Code != c.status || rec.Body.String() != c.body {
			t.Errorf("%s: got %d %q, want %d %q", c.name, rec.Code, rec.Body, c.status, c.body)
		}
	}
}

func TestChatCompletionsWritesTheWriterItself(t *testing.T) {
	rec := httptest.NewRecorder()
	if w := (dialect.Dialect{}).Errors(rec); w != http.ResponseWriter(rec) {
		t.Errorf("Chat Completions wrapped the writer in %T", w)
	}
}
