package upstream_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/capped"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/upstream"
)

func TestCallSendsOnlyJSONHeadersAndTheAuthHeaderAndCapsTheReply(t *testing.T) {
	var got http.Header
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		var b bytes.Buffer
		b.ReadFrom(r.Body)
		body = b.String()
		w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	vendor := upstream.Endpoint{BaseURL: srv.URL, Auth: upstream.Bearer("sk-vendor"), HTTP: srv.Client()}
	reply, err := vendor.Call(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1", Body: jsonx.Encode(map[string]string{"prompt": "a <b> & c"})}, 100)
	if err != nil || reply.Status != 200 || len(reply.Body) != 100 {
		t.Fatalf("err %v reply %+v", err, reply)
	}
	if got.Get("Authorization") != "Bearer sk-vendor" || got.Get("Content-Type") != "application/json" || got.Get("Cookie") != "" || got.Get("X-Forwarded-For") != "" {
		t.Errorf("headers %v", got)
	}
	if body != `{"prompt":"a <b> & c"}` {
		t.Errorf("body %q", body)
	}
	fal := upstream.Endpoint{BaseURL: srv.URL, Auth: http.Header{"Authorization": {"Key fal-id:fal-secret"}}, HTTP: srv.Client()}
	header := http.Header{"Authorization": {"Bearer stolen"}}
	header.Set("X-Fal-Store-IO", "0")
	if _, err := fal.Call(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/v1", Header: header}, 100); err != nil {
		t.Fatal(err)
	}
	if got.Values("Authorization")[0] != "Key fal-id:fal-secret" || len(got.Values("Authorization")) != 1 || got.Get("X-Fal-Store-Io") != "0" || got.Get("Content-Type") != "" || got.Get("Accept") != "application/json" {
		t.Errorf("caller headers %v", got)
	}
	keyed := upstream.Endpoint{BaseURL: srv.URL, Auth: http.Header{"X-Api-Key": {"pk"}}, HTTP: srv.Client()}
	if _, err := keyed.Call(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1", Body: jsonx.Encode(map[string]string{})}, 100); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Api-Key") != "pk" || got.Get("Authorization") != "" {
		t.Errorf("key header %v", got)
	}
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if _, err := vendor.Call(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1", Header: form, Body: []byte("a=b&c=d")}, 100); err != nil {
		t.Fatal(err)
	}
	if got.Get("Content-Type") != "application/x-www-form-urlencoded" || body != "a=b&c=d" {
		t.Errorf("form body %q with headers %v, want the caller's content type and bytes as sent", body, got)
	}
	if _, err := vendor.Call(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/v1"}, 99); !errors.Is(err, capped.ErrTooLarge) {
		t.Errorf("oversized reply: %v, want capped.ErrTooLarge", err)
	}
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(strings.Repeat("e", apierr.MaxErrorBody+10)))
	}))
	defer refused.Close()
	reply, err = upstream.Endpoint{BaseURL: refused.URL, HTTP: refused.Client()}.Call(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/v1"}, 64<<20)
	if err != nil || reply.Status != http.StatusBadRequest || len(reply.Body) != apierr.MaxErrorBody {
		t.Errorf("error reply: err %v status %d body %d bytes, want the first %d", err, reply.Status, len(reply.Body), apierr.MaxErrorBody)
	}
	gone := upstream.Endpoint{BaseURL: "http://127.0.0.1:9", Auth: upstream.Bearer("k"), HTTP: srv.Client()}
	if _, err := gone.Call(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/secret-path?token=t"}, 10); err == nil || strings.Contains(err.Error(), "secret-path") {
		t.Errorf("unreachable error %v leaks the URL", err)
	}
}

func TestA429OrA5xxReplyIsTransientAndEveryOtherStatusIsFinal(t *testing.T) {
	for status, transient := range map[int]bool{200: false, 400: false, 402: false, 408: false, 422: false, 429: true, 499: false, 500: true, 502: true, 503: true, 599: true} {
		if got := (upstream.Refused{Status: status}).Transient(); got != transient {
			t.Errorf("%d: transient %v", status, got)
		}
	}
}

func TestACallFollowsNoRedirectAndCarriesNoGoUserAgent(t *testing.T) {
	followed := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed++ }))
	defer elsewhere.Close()
	var agents []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.Header.Get("User-Agent"))
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	vendor := upstream.Endpoint{BaseURL: origin.URL, Auth: upstream.Bearer("k"), HTTP: &http.Client{}}
	reply, err := vendor.Call(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1", Body: jsonx.Encode(map[string]string{"prompt": "secret"})}, 100)
	if err != nil || reply.Status != http.StatusTemporaryRedirect {
		t.Errorf("a redirected call: %+v %v, want the 307 itself for the vendor to classify", reply, err)
	}
	if followed != 0 || len(agents) != 1 || agents[0] != "" {
		t.Errorf("followed %d redirects, user agents %q; want none followed and a blank agent", followed, agents)
	}
}

func TestJSONRefusesANon2xxThroughTheEndpointsClassifierAndDecodesOnlyA2xx(t *testing.T) {
	status, body := http.StatusBadRequest, `{"error":{"code":"context_length_exceeded","message":"VENDOR-CANARY"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	plain := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}
	var into struct{ A int }
	var refused upstream.Refused
	if _, err := plain.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, &into, 100); !errors.As(err, &refused) || refused.Status != status || !errors.Is(err, apierr.ErrContextLengthExceeded) || refused.Transient() {
		t.Errorf("default refusal %v, want the sanitized error carrying the vendor status", err)
	}
	var seen upstream.Reply
	custom := plain
	custom.Refuse = func(r upstream.Reply) error {
		seen = r
		return errors.New("refused")
	}
	reply, err := custom.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, &into, 100)
	if err == nil || err.Error() != "refused" || seen.Status != status || string(seen.Body) != body || reply.Status != status {
		t.Errorf("custom refusal %v saw %+v", err, seen)
	}
	status, body = http.StatusOK, `{"A":7}`
	if _, err := custom.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, &into, 100); err != nil || into.A != 7 {
		t.Errorf("decoded %+v err %v", into, err)
	}
	body = `<html>`
	if reply, err := custom.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, &into, 100); err != upstream.ErrMalformed || reply.Status != http.StatusOK {
		t.Errorf("malformed reply: %v status %d", err, reply.Status)
	}
	if reply, err := custom.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, nil, 100); err != nil || string(reply.Body) != body {
		t.Errorf("gate only: %v body %q", err, reply.Body)
	}
	status, body = http.StatusTemporaryRedirect, `{"A":9}`
	if _, err := custom.JSON(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/"}, &into, 100); err == nil || err.Error() != "refused" || into.A != 7 {
		t.Errorf("a 3xx with a decodable body: %v, decoded %+v; want it refused and not decoded", err, into)
	}
}

func TestAFailedPollIsFinalOnlyForALastingRefusalOrAnUnusableReplyTheCallerEndsOn(t *testing.T) {
	refused := func(status int) error { return upstream.Refused{Status: status, Err: apierr.ErrUpstream} }
	for _, c := range []struct {
		name          string
		err           error
		retries, ends bool
	}{
		{"no error", nil, false, false},
		{"refused 400", refused(400), true, true},
		{"refused 404", refused(404), true, true},
		{"refused 200", refused(200), true, true},
		{"refused 429", refused(429), false, false},
		{"refused 503", refused(503), false, false},
		{"unreachable", upstream.ErrUnreachable, false, false},
		{"deadline", context.DeadlineExceeded, false, false},
		{"malformed", upstream.ErrMalformed, false, true},
		{"oversized", capped.ErrTooLarge, false, true},
	} {
		if got := upstream.Final(c.err, upstream.UnusableRetries); got != c.retries {
			t.Errorf("%s, unusable retries: final %v", c.name, got)
		}
		if got := upstream.Final(c.err, upstream.UnusableEnds); got != c.ends {
			t.Errorf("%s, unusable ends: final %v", c.name, got)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestABodyInPartsIsSentWholeWithItsLengthAndCanBeSentAgain(t *testing.T) {
	var sends []string
	var length int64
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		length = r.ContentLength
		for range 2 {
			body, _ := io.ReadAll(r.Body)
			sends = append(sends, string(body))
			r.Body, _ = r.GetBody()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	vendor := upstream.Endpoint{BaseURL: "http://vendor.test", HTTP: client}
	if _, err := vendor.Call(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1", Body: []byte("head "), Parts: [][]byte{[]byte("audio"), nil, []byte(" tail")}}, 100); err != nil {
		t.Fatal(err)
	}
	if want := "head audio tail"; length != int64(len(want)) || len(sends) != 2 || sends[0] != want || sends[1] != want {
		t.Errorf("Content-Length %d, sends %q, want %d and %q twice", length, sends, len(want), want)
	}
}
