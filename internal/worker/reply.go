package worker

import (
	"context"
	"net/http"
	"time"

	"morse/backend/internal/health"
)

type replyWriter struct {
	outer     http.ResponseWriter
	header    http.Header
	status    int
	firstBody time.Time
	writeErr  error
}

func newReplyWriter(outer http.ResponseWriter) *replyWriter {
	return &replyWriter{outer: outer, header: http.Header{}}
}

func (w *replyWriter) Header() http.Header { return w.header }

func (w *replyWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	outer := w.outer.Header()
	for name, values := range w.header {
		outer[name] = values
	}
	w.outer.WriteHeader(code)
}

func (w *replyWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	if w.firstBody.IsZero() && len(p) > 0 {
		w.firstBody = time.Now()
	}
	n, err := w.outer.Write(p)
	if w.writeErr == nil {
		w.writeErr = err
	}
	return n, err
}

func (w *replyWriter) FlushError() error {
	err := http.NewResponseController(w.outer).Flush()
	if w.writeErr == nil {
		w.writeErr = err
	}
	return err
}

func (w *replyWriter) streamed() bool { return streamed(w.header.Get("Content-Type")) }

func (w *replyWriter) observed(ctx context.Context, callErr error, cutForCaller bool, opened, returned time.Time) health.Observation {
	began := !w.firstBody.IsZero()
	evidence := evidenceOf(ctx, callErr, w.writeErr, began)
	if cutForCaller {
		evidence.Cut = health.CutByCaller
	}
	o := health.Observation{Outcome: health.Classify(evidence), Duration: returned.Sub(opened)}
	if began && w.streamed() {
		o.TTFT = w.firstBody.Sub(opened)
	}
	return o
}
