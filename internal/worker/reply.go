package worker

import (
	"context"
	"errors"
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
	// claim, when set, is asked once before the first write reaches outer. A writer it refuses has lost the reply to
	// another, and nothing it writes reaches outer.
	claim func() bool
	lost  bool
}

var errLostTheReply = errors.New("worker: another endpoint's call began the reply first")

func newReplyWriter(outer http.ResponseWriter) *replyWriter {
	return &replyWriter{outer: outer, header: http.Header{}}
}

// claiming is a writer of its own headers that writes to outer only once claim lets it.
func claiming(outer http.ResponseWriter, claim func() bool) *replyWriter {
	w := newReplyWriter(outer)
	w.claim = claim
	return w
}

func (w *replyWriter) Header() http.Header { return w.header }

func (w *replyWriter) WriteHeader(code int) {
	if w.status != 0 || w.lost {
		return
	}
	if w.claim != nil && !w.claim() {
		w.lost = true
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
	if w.lost {
		return 0, errLostTheReply
	}
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
	if w.claim != nil {
		w.WriteHeader(http.StatusOK)
	}
	if w.lost {
		return errLostTheReply
	}
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
