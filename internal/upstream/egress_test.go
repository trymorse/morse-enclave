package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAnEgressCheckRefusesABodyBeforeItLeaves(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	e := Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}
	refuseJane := func(body []byte) error {
		if strings.Contains(string(body), "Jane") {
			return errors.New("leak")
		}
		return nil
	}
	ctx := WithEgress(context.Background(), refuseJane)
	_, err := e.Open(ctx, Request{Method: http.MethodPost, Path: "/v1/chat", Body: []byte(`{"content":"Jane"}`)})
	if !errors.Is(err, ErrEgressRefused) || !errors.Is(err, ErrNotSent) || received.Load() != 0 {
		t.Fatalf("a refused body: %v, %d received", err, received.Load())
	}
	if _, err := e.Open(ctx, Request{Method: http.MethodPost, Path: "/v1/chat", Body: []byte(`{"content":"[NAME_1]"}`)}); err != nil || received.Load() != 1 {
		t.Fatalf("a clean body: %v, %d received", err, received.Load())
	}
	if _, err := e.Open(WithoutEgress(ctx), Request{Method: http.MethodPost, Path: "/v1/chat", Body: []byte(`{"content":"Jane"}`)}); err != nil || received.Load() != 2 {
		t.Fatalf("a body sent past a lifted check: %v, %d received", err, received.Load())
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, io.NopCloser(strings.NewReader(`{"content":"[NAME_1]"}`)))
	if _, err := Do(srv.Client(), req); !errors.Is(err, ErrEgressRefused) || received.Load() != 2 {
		t.Fatalf("a body that cannot be read twice: %v, %d received", err, received.Load())
	}
	if err := CheckEgress(ctx, []byte(`Jane`)); !errors.Is(err, ErrEgressRefused) {
		t.Fatalf("CheckEgress = %v", err)
	}
}
