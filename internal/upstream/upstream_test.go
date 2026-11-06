package upstream_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/upstream"
)

func post(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	vendor := upstream.Endpoint{BaseURL: url, Auth: http.Header{"X-Api-Key": {"sk-vendor"}}, HTTP: client}
	return vendor.Open(context.Background(), upstream.Request{Method: http.MethodPost, Header: http.Header{"Accept": {"text/event-stream"}}, Body: []byte(`{"a":1}`)})
}

func TestOnlyTheCallersHeadersAndTheContentTypeGoUpstream(t *testing.T) {
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	target, _ := url.Parse(srv.URL)
	jar.SetCookies(target, []*http.Cookie{{Name: "session", Value: "tracked"}})
	client := &http.Client{Jar: jar}
	resp, err := post(t, client, srv.URL+"/v1/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for name := range got.Header {
		if !slices.Contains([]string{"Accept", "Accept-Encoding", "Content-Length", "Content-Type", "X-Api-Key"}, name) {
			t.Errorf("unexpected header %s: %q", name, got.Header.Get(name))
		}
	}
	if got.Header.Get("Content-Type") != "application/json" || got.Header.Get("X-Api-Key") != "sk-vendor" || body != `{"a":1}` || got.URL.Path != "/v1/x" {
		t.Errorf("request %s %v %s", got.URL, got.Header, body)
	}
}

func TestAVendorErrorIsSanitizedFromItsCodeAndNeverCarriesVendorText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"code":"context_length_exceeded","message":"VENDOR-CANARY org_1"}}`)
	}))
	t.Cleanup(srv.Close)
	_, err := post(t, srv.Client(), srv.URL)
	if !errors.Is(err, apierr.ErrContextLengthExceeded) {
		t.Errorf("err %v", err)
	}
}

func TestARedirectIsARefusalAndIsNeverFollowed(t *testing.T) {
	followed := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed++ }))
	t.Cleanup(elsewhere.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	following := &http.Client{}
	if _, err := post(t, following, origin.URL); !errors.Is(err, apierr.ErrUpstream) {
		t.Errorf("err %v, want the proxy-owned 502", err)
	}
	if followed != 0 || following.CheckRedirect != nil || following.Jar != nil {
		t.Errorf("followed %d times, or the caller's client was changed", followed)
	}
}

func TestAnUnreachableVendorIsOpaqueAndNamesNoAddress(t *testing.T) {
	_, err := post(t, &http.Client{}, "http://127.0.0.1:1")
	if !errors.Is(err, upstream.ErrUnreachable) || errors.As(err, new(apierr.Error)) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("err %v", err)
	}
}

func TestAVendorThatNeverReceivedTheRequestIsNotSentAndOneThatDroppedItIsOnlyUnreachable(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	dropping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(dropping.Close)
	for name, c := range map[string]struct {
		url     string
		notSent bool
	}{
		"a refused connection":                   {"http://127.0.0.1:1", true},
		"a name that never resolves":             {"http://vendor.invalid", true},
		"a failed tls handshake":                 {"https://" + plain.Listener.Addr().String(), true},
		"a connection dropped after the request": {dropping.URL, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := post(t, &http.Client{}, c.url)
			if !errors.Is(err, upstream.ErrUnreachable) || errors.Is(err, upstream.ErrNotSent) != c.notSent {
				t.Errorf("err %v, want unreachable and not sent %v", err, c.notSent)
			}
		})
	}
}

func TestACallerWhoLeavesDuringTheHandshakeGetsTheirCancelNotSentAndNotUnreachable(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := silent.Accept(); err == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		if conn, ok := <-accepted; ok {
			conn.Close()
		}
	})
	ctx, leave := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, leave)
	vendor := upstream.Endpoint{BaseURL: "https://" + silent.Addr().String(), HTTP: &http.Client{}}
	_, err = vendor.Open(ctx, upstream.Request{Method: http.MethodPost, Body: []byte(`{"a":1}`)})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, upstream.ErrNotSent) || errors.Is(err, upstream.ErrUnreachable) {
		t.Errorf("err %v, want the caller's cancel, not sent, and not unreachable", err)
	}
}

func TestOverHTTP2AStreamAbortedAfterItsBodyWasReadIsSentAndAClosedServerIsNot(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		panic(http.ErrAbortHandler)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := srv.Client()
	_, err := post(t, client, srv.URL)
	if !errors.Is(err, upstream.ErrUnreachable) || errors.Is(err, upstream.ErrNotSent) {
		t.Errorf("aborted stream: err %v, want unreachable and sent", err)
	}
	srv.Close()
	client.CloseIdleConnections()
	_, err = post(t, client, srv.URL)
	if !errors.Is(err, upstream.ErrUnreachable) || !errors.Is(err, upstream.ErrNotSent) {
		t.Errorf("closed server: err %v, want unreachable and not sent", err)
	}
}

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, apierr.ErrUnattested
}

func TestAProxyOwnedRefusalFromTheTransportPassesThroughWithoutTheURL(t *testing.T) {
	_, err := post(t, &http.Client{Transport: refusingTransport{}}, "https://vendor.example/secret-path")
	if err != apierr.ErrUnattested {
		t.Errorf("err %v", err)
	}
}

func TestACancelledCallIsTheContextError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}.Open(ctx, upstream.Request{Method: http.MethodGet})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("err %v", err)
	}
}

func TestOpenRefusesANon2xxThroughTheEndpointsClassifier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Why", "gone")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "no such request")
	}))
	t.Cleanup(srv.Close)
	var seen upstream.Reply
	gone := errors.New("gone")
	vendor := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client(), Refuse: func(r upstream.Reply) error {
		seen = r
		return gone
	}}
	_, err := vendor.Open(context.Background(), upstream.Request{Method: http.MethodGet, Path: "/x"})
	var refused upstream.Refused
	if !errors.Is(err, gone) || !errors.As(err, &refused) || refused.Status != http.StatusNotFound || refused.Transient() {
		t.Errorf("err %v", err)
	}
	if seen.Status != http.StatusNotFound || seen.Header.Get("X-Why") != "gone" || string(seen.Body) != "no such request" {
		t.Errorf("the classifier saw %+v", seen)
	}
}

func TestEveryCallConfirmsA2xxReplyAndRefusesItForGoodWhenTheConfirmationFails(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if confirmed {
				w.Header().Set("X-Zero-Data-Retention", "true")
			}
			io.WriteString(w, `{}`)
		}))
		t.Cleanup(srv.Close)
		confirm := func(header func(string) string) error {
			if header("X-Zero-Data-Retention") != "true" {
				return apierr.ErrUpstreamRetention
			}
			return nil
		}
		vendor := upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client(), Confirm: confirm}
		resp, openErr := vendor.Open(context.Background(), upstream.Request{Method: http.MethodPost, Body: []byte(`{}`)})
		_, jsonErr := vendor.JSON(context.Background(), upstream.Request{Method: http.MethodGet}, new(struct{}), 1<<10)
		for name, err := range map[string]error{"Open": openErr, "JSON": jsonErr} {
			var refused upstream.Refused
			switch {
			case confirmed && err != nil:
				t.Errorf("%s: a confirmed reply was refused: %v", name, err)
			case !confirmed && (!errors.Is(err, apierr.ErrUpstreamRetention) || !errors.As(err, &refused) || refused.Transient()):
				t.Errorf("%s: an unconfirmed reply gave %v, want a final retention refusal", name, err)
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
