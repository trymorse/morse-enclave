package worker

import (
	"context"
	"io"

	"morse/backend/internal/apierr"
	"morse/backend/internal/speech"
)

func (w *InProcess) openSpeech(o Opening) (Admission, error) {
	req, err := speech.ParseRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendor, known := w.speakers[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	oc := &openedCall{cuts: newCuts(), endpoint: w.endpoints[req.Model], contentType: speech.ContentType, call: func(ctx context.Context) (func(io.Writer) error, error) {
		audio, err := vendor.Speak(ctx, req)
		return audio.Write, err
	}}
	return CallAdmission{admitted: admitted{w.keep(o, oc)}, Route: req.Model}, nil
}
