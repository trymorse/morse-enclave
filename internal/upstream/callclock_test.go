package upstream_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/upstream"
)

func TestACallClockTimesTheFirstCallsConnectionAndTheVendorsAnswerAndSeesTheNextReuseIt(t *testing.T) {
	const held = 50 * time.Millisecond
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(held)
		io.WriteString(w, "{}")
	}))
	t.Cleanup(srv.Close)
	vendor := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}
	call := func() upstream.CallTimes {
		t.Helper()
		var clock upstream.CallClock
		ctx := upstream.WithCallClock(context.Background(), &clock)
		for range 2 {
			resp, err := vendor.Open(ctx, upstream.Request{Method: http.MethodPost, Body: []byte("{}")})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return clock.Times()
	}
	first := call()
	if first.Reused || first.Dial <= 0 || first.TLS <= 0 || first.Connect < first.Dial || first.Sent < first.Connect {
		t.Errorf("first call %+v, want a new connection whose dial and TLS handshake the connect and the send include", first)
	}
	if first.Head < held || first.Head > held+time.Second {
		t.Errorf("first call's head %v, want the %v the vendor held its answer", first.Head, held)
	}
	again := call()
	if !again.Reused || again.Dial != 0 || again.TLS != 0 || again.Head < held {
		t.Errorf("next call %+v, want the pooled connection reused with no dial or handshake, and the vendor's %v", again, held)
	}
}

func TestAVendorAnswerSeenBeforeTheWriteIsReportedIsStillTimedAndTheSendEndsByIt(t *testing.T) {
	for _, writeReported := range []bool{true, false} {
		var answered time.Time
		vendor := upstream.Endpoint{BaseURL: "http://vendor.invalid", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			trace := httptrace.ContextClientTrace(r.Context())
			trace.GotConn(httptrace.GotConnInfo{})
			trace.GotFirstResponseByte()
			answered = time.Now()
			if writeReported {
				trace.WroteRequest(httptrace.WroteRequestInfo{})
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
		})}}
		var clock upstream.CallClock
		began := time.Now()
		resp, err := vendor.Open(upstream.WithCallClock(context.Background(), &clock), upstream.Request{Method: http.MethodPost, Body: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := clock.Times(); got.Head <= 0 || got.Sent < got.Connect || got.Sent > answered.Sub(began) {
			t.Errorf("write reported after the answer %v: %+v, want the answer timed and the send ended by the answer %v in", writeReported, got, answered.Sub(began))
		}
	}
}

func TestAContextWithNoCallClockSendsAsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{}") }))
	t.Cleanup(srv.Close)
	resp, err := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}.Open(context.Background(), upstream.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
