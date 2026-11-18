package speech_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/speech"
	"morse/backend/internal/upstream"
)

type sent struct {
	path, auth, accept string
	body               map[string]any
}

func vendor(t *testing.T, reply func(w http.ResponseWriter)) (*httptest.Server, *[]sent) {
	t.Helper()
	var calls []sent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := sent{path: r.Method + " " + r.URL.Path, auth: r.Header.Get("Authorization"), accept: r.Header.Get("Accept")}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &call.body); err != nil {
			t.Errorf("the vendor got %q: %v", raw, err)
		}
		calls = append(calls, call)
		reply(w)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func replying(status int, contentType, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func request(t *testing.T, body string) *speech.Request {
	t.Helper()
	req, err := speech.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestSpeakSendsOpenAIsSpeechBodyWithTheUpstreamModelAndReturnsTheAudioAsItCame(t *testing.T) {
	mp3 := "\xff\xf3\x84\xc4 audio frames"
	srv, calls := vendor(t, replying(200, "audio/mpeg", mp3))
	got, err := speech.NewOpenAI(srv.URL, "key", "hexgrad/Kokoro-82M", srv.Client()).Speak(context.Background(), request(t, `{"model":"kokoro-82m","input":"Hello there.","voice":"af_sky","speed":1.5}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), []byte(mp3)) {
		t.Errorf("got %v, want the vendor's mp3 bytes", got)
	}
	call := (*calls)[0]
	want := map[string]any{"model": "hexgrad/Kokoro-82M", "input": "Hello there.", "voice": "af_sky", "response_format": "mp3", "speed": 1.5}
	if call.path != "POST /v1/audio/speech" || call.auth != "Bearer key" || call.accept != "audio/mpeg" || len(call.body) != len(want) {
		t.Fatalf("sent %+v, want POST /v1/audio/speech with the key, asking for audio/mpeg, and %v", call, want)
	}
	for k, v := range want {
		if call.body[k] != v {
			t.Errorf("sent %s %v, want %v", k, call.body[k], v)
		}
	}
	var out bytes.Buffer
	if err := got.Write(&out); err != nil || out.String() != mp3 {
		t.Errorf("Write wrote %q, %v, want the audio", out.String(), err)
	}
}

func TestAnEmptyOrJSONReplyIsTheVendorsFailure(t *testing.T) {
	for name, reply := range map[string]func(http.ResponseWriter){
		"empty":           replying(200, "audio/mpeg", ""),
		"json as audio":   replying(200, "audio/mpeg", `{"error":"x"}`),
		"json":            replying(200, "application/json", `{"audio":"aGk="}`),
		"wav":             replying(200, "audio/wav", "RIFF....WAVE"),
		"no content type": func(w http.ResponseWriter) { w.Header()["Content-Type"] = nil; io.WriteString(w, "ID3") },
	} {
		srv, _ := vendor(t, reply)
		_, err := speech.NewOpenAI(srv.URL, "key", "m", srv.Client()).Speak(context.Background(), request(t, `{"model":"m","input":"Hi.","voice":"af_sky"}`))
		if !errors.Is(err, speech.ErrUpstream) {
			t.Errorf("%s: err %v, want %v", name, err, speech.ErrUpstream)
		}
	}
}

func TestAVendorRefusalMapsByStatusAndNeverCarriesTheVendorsBody(t *testing.T) {
	quoted := `{"message":"1 validation error for KokoroTextToSpeechIn: input_value='my secret plan'"}`
	for status, want := range map[int]apierr.Error{
		400: speech.ErrUnreadable, 422: speech.ErrUnreadable, 413: speech.ErrUnreadable,
		401: speech.ErrUpstreamUnavailable, 402: speech.ErrUpstreamUnavailable, 403: speech.ErrUpstreamUnavailable, 404: speech.ErrUpstreamUnavailable,
		429: speech.ErrUpstreamBusy, 503: speech.ErrUpstreamBusy, 529: speech.ErrUpstreamBusy,
		500: speech.ErrUpstream, 502: speech.ErrUpstream,
	} {
		srv, _ := vendor(t, replying(status, "application/json", quoted))
		_, err := speech.NewOpenAI(srv.URL, "key", "m", srv.Client()).Speak(context.Background(), request(t, `{"model":"m","input":"my secret plan","voice":"af_sky"}`))
		var refused upstream.Refused
		if !errors.As(err, &refused) || refused.Status != status || !errors.Is(err, want) {
			t.Errorf("status %d: err %v, want %v wrapped as a refusal of that status", status, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("status %d: the error %q carries the vendor's body", status, err)
		}
	}
}

func TestSpeakGivesUpAtItsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv, _ := vendor(t, func(w http.ResponseWriter) { <-release })
	defer close(release)
	o := speech.NewOpenAI(srv.URL, "key", "m", srv.Client())
	o.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := o.Speak(context.Background(), request(t, `{"model":"m","input":"Hi.","voice":"af_sky"}`)); err == nil {
		t.Fatal("a vendor that never answers returned audio")
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("Speak waited %v past its 50ms timeout", waited)
	}
}
