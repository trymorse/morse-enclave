package worker

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/audio"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

type silentTranscriber struct{}

type audioAttester struct{}

func (audioAttester) Attest(context.Context, string) (chat.Attestation, error) {
	return chat.Attestation{BindModel: "openai/whisper-large-v3"}, nil
}

func (silentTranscriber) Transcribe(context.Context, *audio.Request) (audio.Transcript, error) {
	return audio.NewTranscript("", 0), nil
}

func dictationOpening(t *testing.T, model string, header map[string]string) Opening {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	w.WriteField("model", model)
	f, err := w.CreateFormFile("file", "clip.wav")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("RIFF\x26\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x80\x3e\x00\x00\x00\x7d\x00\x00\x02\x00\x10\x00data\x02\x00\x00\x00\x01\x02"))
	w.Close()
	o := Opening{Method: "POST", Path: "/v1/audio/transcriptions", Header: http.Header{"Content-Type": {w.FormDataContentType()}}, Body: &b}
	for k, v := range header {
		o.Header.Set(k, v)
	}
	return o
}

func TestATranscriptionModelIsAttestedExactlyAtAnAttestedTier(t *testing.T) {
	for name, m := range map[string]Model{
		"no vendor":             {Tier: catalog.Anon, Serves: Transcription{}},
		"tee without attester":  {Tier: catalog.TEE, Attester: "near", Serves: Transcription{Transcriber: silentTranscriber{}}},
		"anon with an attester": {Tier: catalog.Anon, Serves: Transcription{Transcriber: silentTranscriber{}, Attester: audioAttester{}}},
		"private with attester": {Tier: catalog.Private, Serves: Transcription{Transcriber: silentTranscriber{}, Attester: audioAttester{}}},
	} {
		if _, err := NewInProcess(Config{Models: map[string]Model{"m": m}}); err == nil || !strings.Contains(err.Error(), "model m ") {
			t.Errorf("%s: NewInProcess gave %v, want a refusal naming model m", name, err)
		}
	}
	if _, err := NewInProcess(Config{Models: map[string]Model{
		"anon": {Tier: catalog.Anon, Serves: Transcription{Transcriber: silentTranscriber{}}},
		"tee":  {Tier: catalog.TEE, Attester: "near", Serves: Transcription{Transcriber: silentTranscriber{}, Attester: audioAttester{}}},
	}}); err != nil {
		t.Errorf("transcription models equipped for their tiers were refused: %v", err)
	}
}

func TestATranscriptionOpensAsACallAndAttestsOnlyThroughItsOwnAttester(t *testing.T) {
	w, err := NewInProcess(Config{Models: map[string]Model{
		"whisper-tee": {Tier: catalog.TEE, Attester: "near", Serves: Transcription{Transcriber: silentTranscriber{}, Attester: audioAttester{}}},
		"whisper":     {Tier: catalog.Anon, Serves: Transcription{Transcriber: silentTranscriber{}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admitted, err := w.Open(ctx, dictationOpening(t, "whisper-tee", nil))
	if call, ok := admitted.(CallAdmission); err != nil || !ok || call.Route != "whisper-tee" {
		t.Fatalf("opened %#v, %v, want a call on whisper-tee", admitted, err)
	}
	w.Cut(admitted.Handle(), measure.CutByProxy)
	if _, err := w.Open(ctx, dictationOpening(t, "nobody", nil)); !errors.Is(err, apierr.ErrModelNotFound) {
		t.Errorf("an unknown model: %v, want model_not_found", err)
	}
	var refusal apierr.Error
	if _, err := w.Open(ctx, dictationOpening(t, "whisper-tee", map[string]string{"X-E2EE-Version": "2"})); !errors.As(err, &refusal) || !strings.HasPrefix(refusal.Code, "e2ee_") {
		t.Errorf("e2ee headers on a transcription: %v, want an e2ee refusal", err)
	}
	if att, err := w.Attest(ctx, Vendor{Route: "whisper-tee", Attester: "near"}, "ab"); err != nil || att.BindModel != "openai/whisper-large-v3" {
		t.Errorf("attest the tee transcription: %+v %v", att, err)
	}
	for _, v := range []Vendor{{Route: "whisper-tee", Attester: "phala"}, {Route: "whisper", Attester: ""}, {Route: "whisper", Attester: "near"}} {
		if _, err := w.Attest(ctx, v, "ab"); !errors.Is(err, errNoSuchVendor) {
			t.Errorf("attest %+v: %v, want no such vendor", v, err)
		}
	}
}
