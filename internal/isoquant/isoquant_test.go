package isoquant

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

const (
	whole  = `{"id":"x","object":"chat.completion","created":1,"model":"glm-5.3-flash","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"created_cache_tokens":0}}`
	stream = `data: {"id":"x","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}` + "\n\n" + `data: {"id":"x","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}` + "\n\ndata: [DONE]\n\n"
)

type isoquantStub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []http.Header
	fail func(w http.ResponseWriter) bool
}

func stub(t *testing.T) *isoquantStub {
	t.Helper()
	s := &isoquantStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, r.Header.Clone())
		fail := s.fail
		s.mu.Unlock()
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer ik" {
			http.NotFound(w, r)
			return
		}
		if fail != nil && fail(w) {
			return
		}
		if strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, stream)
			return
		}
		io.WriteString(w, whole)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *isoquantStub) requests() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.seen...)
}

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func TestEveryRequestToIsoquantCarriesTheZDRHeaderWhateverTheCall(t *testing.T) {
	s := stub(t)
	p := NewChat(s.srv.URL, "ik", "glm-5.3-flash", s.srv.Client())
	ctx := context.Background()
	msgs := `"messages":[{"role":"user","content":"hello"}]`
	if _, err := p.Stream(ctx, call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},`+msgs+`}`), func(chat.Chunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err != nil {
		t.Fatal(err)
	}
	s.fail = func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusServiceUnavailable); return true }
	for range 3 {
		if _, _, err := p.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err == nil {
			t.Fatal("a 503 reply was no error")
		}
	}
	s.fail = nil
	if _, _, err := p.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err != nil {
		t.Fatal(err)
	}
	got := s.requests()
	if len(got) != 6 {
		t.Fatalf("Isoquant saw %d requests, want 6", len(got))
	}
	for i, h := range got {
		if h.Get(ZDRHeader) != ZDRValue || len(h.Values(ZDRHeader)) != 1 {
			t.Errorf("request %d carried %s %q, want exactly one %q", i+1, ZDRHeader, h.Values(ZDRHeader), ZDRValue)
		}
	}
}

func TestNoHeaderOfARequestOrAKeyOverridesTheZDRHeader(t *testing.T) {
	s := stub(t)
	e := Endpoint(s.srv.URL, "ik", s.srv.Client())
	for name, header := range map[string]http.Header{
		"another value": {ZDRHeader: {"optional"}},
		"empty":         {ZDRHeader: {""}},
		"lower case":    {"isoquant-zdr": {"optional"}},
		"none":          nil,
	} {
		resp, err := e.Open(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1/chat/completions", Header: header, Body: []byte(`{}`)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
	}
	for i, h := range s.requests() {
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

func TestAnAccountRefusalIsNotARequestRefusalThatStands(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   apierr.Error
	}{
		"402 of a dry account":             {http.StatusPaymentRequired, `{"error":{"code":"insufficient_credits","message":"vendor text","type":"gateway_error"}}`, apierr.ErrUpstreamUnavailable},
		"403 model_forbidden":              {http.StatusForbidden, `{"error":{"code":"model_forbidden","message":"Model is not available to this credential","type":"gateway_error"},"request_id":"iqr_1"}`, apierr.ErrUpstreamUnavailable},
		"403 of another kind":              {http.StatusForbidden, `{"error":{"code":"forbidden","message":"vendor text","type":"gateway_error"}}`, apierr.ErrUpstreamRefused},
		"400 unsupported_reasoning_effort": {http.StatusBadRequest, `{"error":{"code":"unsupported_reasoning_effort","message":"vendor text","type":"gateway_error"}}`, apierr.ErrInvalidRequest},
	} {
		s := stub(t)
		s.fail = func(w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
			return true
		}
		p := NewChat(s.srv.URL, "ik", "glm-5.3-flash", s.srv.Client())
		_, _, err := p.Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		var got apierr.Error
		if !errors.As(err, &got) || got.Code != tc.want.Code || strings.Contains(got.Message, "vendor text") {
			t.Errorf("%s: %v, want %s with no vendor text", name, err, tc.want.Code)
		}
	}
}
