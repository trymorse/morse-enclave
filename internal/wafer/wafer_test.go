package wafer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/upstream"
)

const whole = `{"id":"x","object":"chat.completion","created":1,"model":"GLM-5.3-Flash","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`

type waferStub struct {
	srv   *httptest.Server
	mu    sync.Mutex
	seen  []http.Header
	reply func(w http.ResponseWriter)
}

func stub(t *testing.T) *waferStub {
	t.Helper()
	s := &waferStub{reply: func(w http.ResponseWriter) { io.WriteString(w, whole) }}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Header.Clone())
		s.mu.Unlock()
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer wk" {
			http.NotFound(w, r)
			return
		}
		s.reply(w)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func TestNoHeaderOfARequestOrAKeyOverridesTheZDRHeader(t *testing.T) {
	s := stub(t)
	e := Endpoint(s.srv.URL, "wk", s.srv.Client())
	for name, header := range map[string]http.Header{
		"another value": {ZDRHeader: {"optional"}},
		"empty":         {ZDRHeader: {""}},
		"lower case":    {"wafer-zdr": {"optional"}},
		"none":          nil,
	} {
		resp, err := e.Open(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1/chat/completions", Header: header, Body: []byte(`{}`)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
	}
	if len(s.seen) != 4 {
		t.Fatalf("Wafer saw %d requests, want 4", len(s.seen))
	}
	for i, h := range s.seen {
		if values := h.Values(ZDRHeader); len(values) != 1 || values[0] != ZDRValue {
			t.Errorf("request %d carried %s %q, want exactly %q", i+1, ZDRHeader, values, ZDRValue)
		}
	}
}

func TestAnEndpointWithoutAKeyStillSendsTheZDRHeader(t *testing.T) {
	if got := Endpoint("https://example.test", "", nil).Auth.Get(ZDRHeader); got != ZDRValue {
		t.Errorf("a keyless endpoint sends %s %q, want %q", ZDRHeader, got, ZDRValue)
	}
}

func TestAModelWaferCannotServeUnderZDRIsAHostRefusalAndAnInvalidZDRHeaderIsNot(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   apierr.Error
	}{
		"422 model_zdr_not_supported": {http.StatusUnprocessableEntity, `{"error":{"code":"model_zdr_not_supported","message":"vendor text"}}`, apierr.ErrUpstreamUnavailable},
		"400 invalid_zdr_header":      {http.StatusBadRequest, `{"error":{"code":"invalid_zdr_header","message":"vendor text"}}`, apierr.ErrInvalidRequest},
	} {
		s := stub(t)
		s.reply = func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}
		req, err := chat.ParseRequest(strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = NewChat(s.srv.URL, "wk", "GLM-5.3-Flash", s.srv.Client()).Complete(context.Background(), chat.Call{Request: req, OutputLimit: 64})
		var got apierr.Error
		if !errors.As(err, &got) || got.Code != tc.want.Code || strings.Contains(got.Message, "vendor text") {
			t.Errorf("%s: %v, want %s with no vendor text", name, err, tc.want.Code)
		}
	}
}
