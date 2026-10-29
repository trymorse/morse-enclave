package worker

import (
	"context"
	"io"

	"morse/backend/internal/apierr"
	"morse/backend/internal/audio"
)

type transcriber struct {
	Transcription
	attester string
}

func (w *InProcess) openTranscription(o Opening) (Admission, error) {
	req, err := audio.ParseRequest(o.Header.Get("Content-Type"), o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendor, known := w.transcribers[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	oc := &openedCall{cuts: newCuts(), call: func(ctx context.Context) (func(io.Writer) error, error) {
		transcript, err := vendor.Transcribe(ctx, req)
		return func(w io.Writer) error { return audio.WriteTranscript(w, transcript) }, err
	}}
	return CallAdmission{admitted: admitted{w.keep(o, oc)}, Route: req.Model}, nil
}
