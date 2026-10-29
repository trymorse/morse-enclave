package audio_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/audio"
	"morse/backend/internal/upstream"
)

type sent struct {
	path, auth, accept string
	fields             map[string]string
	filename, fileType string
	file               []byte
}

type vendor struct {
	mu    sync.Mutex
	calls []sent
	reply func(w http.ResponseWriter)
}

func (v *vendor) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := sent{path: r.Method + " " + r.URL.Path, auth: r.Header.Get("Authorization"), accept: r.Header.Get("Accept"), fields: map[string]string{}}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("the request's Content-Type %q: %v", r.Header.Get("Content-Type"), err)
		}
		form := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := form.NextPart()
			if err != nil {
				break
			}
			body, _ := io.ReadAll(p)
			if p.FormName() == "file" {
				call.filename, call.fileType, call.file = p.FileName(), p.Header.Get("Content-Type"), body
				continue
			}
			call.fields[p.FormName()] = string(body)
		}
		v.mu.Lock()
		v.calls = append(v.calls, call)
		v.mu.Unlock()
		v.reply(w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (v *vendor) only(t *testing.T) sent {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.calls) != 1 {
		t.Fatalf("the vendor got %d calls, want 1", len(v.calls))
	}
	return v.calls[0]
}

func replying(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func request(t *testing.T, language string, body []byte) *audio.Request {
	t.Helper()
	parts := []part{text("model", "whisper-large-v3-tee"), file(body)}
	if language != "" {
		parts = append(parts, text("language", language))
	}
	req, err := parse(t, parts...)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestTheClientSendsTheFileAsAWAVToTheUpstreamModelAndReadsVerboseJSON(t *testing.T) {
	v := &vendor{reply: replying(200, `{"text":" And so, my fellow Americans.","duration":10.2,"language":"fr","segments":[{"id":0}]}`)}
	srv := v.serve(t)
	clip := wav([]byte(audioCanary))
	got, err := audio.NewOpenAI(srv.URL, "sk-near", "openai/whisper-large-v3", srv.Client()).Transcribe(context.Background(), request(t, "fr", clip))
	if err != nil {
		t.Fatal(err)
	}
	if got.Text() != "And so, my fellow Americans." || got.Seconds() != 11 {
		t.Errorf("transcript %q, %d seconds", got.Text(), got.Seconds())
	}
	call := v.only(t)
	want := map[string]string{"model": "openai/whisper-large-v3", "response_format": "verbose_json", "language": "fr"}
	if call.path != "POST /v1/audio/transcriptions" || call.auth != "Bearer sk-near" || call.accept != "application/json" || len(call.fields) != len(want) {
		t.Errorf("call %+v", call)
	}
	for k, w := range want {
		if call.fields[k] != w {
			t.Errorf("field %s = %q, want %q", k, call.fields[k], w)
		}
	}
	if call.filename != "audio.wav" || call.fileType != "audio/wav" || !bytes.Equal(call.file, clip) {
		t.Errorf("file %q of type %q, %d bytes", call.filename, call.fileType, len(call.file))
	}
}

func TestTheClientSendsNoLanguageWhenTheRequestNamedNone(t *testing.T) {
	v := &vendor{reply: replying(200, `{"text":"hi"}`)}
	srv := v.serve(t)
	got, err := audio.NewOpenAI(srv.URL, "", "whisper-1", srv.Client()).Transcribe(context.Background(), request(t, "", wav([]byte(audioCanary))))
	if err != nil || got.Text() != "hi" || got.Seconds() != 0 {
		t.Fatalf("transcript %v, %v", got, err)
	}
	call := v.only(t)
	if _, named := call.fields["language"]; named || call.auth != "" || call.filename != "audio.wav" || call.fileType != "audio/wav" {
		t.Errorf("call %+v", call)
	}
}

func TestTheClientRefusesEachVendorStatusAsATranscriptionRefusal(t *testing.T) {
	for status, want := range map[int]apierr.Error{
		400: audio.ErrUnreadable,
		422: audio.ErrUnreadable,
		401: audio.ErrUpstreamUnavailable,
		402: audio.ErrUpstreamUnavailable,
		403: audio.ErrUpstreamUnavailable,
		404: audio.ErrUpstreamUnavailable,
		413: apierr.ErrRequestTooLarge,
		429: audio.ErrUpstreamBusy,
		503: audio.ErrUpstreamBusy,
		529: audio.ErrUpstreamBusy,
		500: audio.ErrUpstream,
		502: audio.ErrUpstream,
	} {
		v := &vendor{reply: replying(status, `{"error":{"message":"Audio could not be processed.","type":"invalid_request_error"}}`)}
		srv := v.serve(t)
		_, err := audio.NewOpenAI(srv.URL, "k", "m", srv.Client()).Transcribe(context.Background(), request(t, "", wav([]byte{1})))
		var got apierr.Error
		if !errors.As(err, &got) || got != want {
			t.Errorf("%d: err %v, want %v", status, err, want)
		}
		var refused upstream.Refused
		if !errors.As(err, &refused) || refused.Status != status {
			t.Errorf("%d: err %v carries no upstream.Refused with the vendor's status", status, err)
		}
	}
}

func TestTheClientRefusesAReplyWithNoTextAndLeavesATransportFailureBare(t *testing.T) {
	for name, body := range map[string]string{"no text": `{"duration":3}`, "text not a string": `{"text":7}`, "not json": `<html>`} {
		v := &vendor{reply: replying(200, body)}
		srv := v.serve(t)
		_, err := audio.NewOpenAI(srv.URL, "k", "m", srv.Client()).Transcribe(context.Background(), request(t, "", wav([]byte{1})))
		var refusal apierr.Error
		switch {
		case name == "no text" && !errors.Is(err, audio.ErrUpstream):
			t.Errorf("%s: err %v, want ErrUpstream", name, err)
		case name != "no text" && (err == nil || errors.As(err, &refusal)):
			t.Errorf("%s: err %v, want a bare malformed reply", name, err)
		}
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	_, err := audio.NewOpenAI(srv.URL, "k", "m", srv.Client()).Transcribe(context.Background(), request(t, "", wav([]byte{1})))
	if !errors.Is(err, upstream.ErrUnreachable) {
		t.Errorf("an unreachable vendor: err %v, want upstream.ErrUnreachable", err)
	}
	pinned := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, apierr.ErrUnattested })}
	_, err = audio.NewOpenAI("https://cloud-api.near.ai", "k", "m", pinned).Transcribe(context.Background(), request(t, "", wav([]byte{1})))
	var refusal apierr.Error
	if !errors.As(err, &refusal) || refusal != apierr.ErrUnattested {
		t.Errorf("a pinned client that refuses an unattested host: err %v, want upstream_unattested", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTheClientGivesUpAtItsTimeout(t *testing.T) {
	release := make(chan struct{})
	v := &vendor{reply: func(w http.ResponseWriter) { <-release }}
	srv := v.serve(t)
	defer close(release)
	client := audio.NewOpenAI(srv.URL, "k", "m", srv.Client())
	client.Timeout = 50 * time.Millisecond
	_, err := client.Transcribe(context.Background(), request(t, "", wav([]byte{1})))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err %v, want the deadline", err)
	}
}
