package dialect

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"morse/backend/internal/apierr"
)

// Errors is w for a client of d: a JSON reply of status 400 or above, which the relay and the worker write in the Chat
// Completions envelope, leaves in d's envelope instead. Every other reply passes through as written. Chat Completions
// gets w itself.
func (d Dialect) Errors(w http.ResponseWriter) http.ResponseWriter {
	if d.Envelope == nil {
		return w
	}
	return &errorWriter{ResponseWriter: w, envelope: d.Envelope}
}

type errorWriter struct {
	http.ResponseWriter
	envelope func(apierr.Error) []byte
	status   int
	held     []byte
	holding  bool
	released bool
}

func (w *errorWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	if code >= http.StatusBadRequest && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.holding = true
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *errorWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.holding || w.released {
		return w.ResponseWriter.Write(p)
	}
	w.held = append(w.held, p...)
	if !json.Valid(w.held) {
		return len(p), nil
	}
	body := w.held
	if refusal, ok := ParseEnvelope(w.status, bytes.TrimSpace(body)); ok {
		body = w.envelope(refusal)
	}
	if err := w.release(body); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *errorWriter) release(body []byte) error {
	if !w.holding || w.released {
		return nil
	}
	w.released = true
	w.ResponseWriter.WriteHeader(w.status)
	_, err := w.ResponseWriter.Write(body)
	return err
}

// FlushError sends a refusal held part-written as it came, since a flush would otherwise send a status of 200.
func (w *errorWriter) FlushError() error {
	if err := w.release(w.held); err != nil {
		return err
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets an http.ResponseController reach the writer beneath, to flush and set deadlines.
func (w *errorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
