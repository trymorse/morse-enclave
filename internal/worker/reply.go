package worker

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"morse/backend/internal/health"
)

type replyPhase uint8

const (
	unclaimed replyPhase = iota
	claimed
	bodyBegun
	lost
)

func (p replyPhase) holdsTheReply() bool { return p == claimed || p == bodyBegun }

type replyWriter struct {
	outer     http.ResponseWriter
	header    http.Header
	at        replyPhase
	firstBody time.Time
	writeErr  error
	claim     func() bool
	heldCode  int
	since     time.Time
	firstByte atomic.Int64
}

var errLostTheReply = errors.New("worker: another endpoint's call began the reply first")

func newReplyWriter(outer http.ResponseWriter) *replyWriter {
	return &replyWriter{outer: outer, header: http.Header{}}
}

func claiming(outer http.ResponseWriter, since time.Time, claim func() bool) *replyWriter {
	w := newReplyWriter(outer)
	w.claim, w.since = claim, since
	return w
}

func (w *replyWriter) firstByteAfter() time.Duration { return time.Duration(w.firstByte.Load()) }

func (w *replyWriter) phase() replyPhase { return w.at }

func (w *replyWriter) enter(next replyPhase) {
	w.at = next
	if next == bodyBegun {
		w.firstBody = time.Now()
	}
}

func (w *replyWriter) unsent(callErr error) bool { return callErr != nil && w.at == unclaimed }

func (w *replyWriter) Header() http.Header { return w.header }

func (w *replyWriter) holdsItsHeaderUntilItsFirstBodyByte() bool { return w.claim != nil }

func (w *replyWriter) WriteHeader(code int) {
	if !w.holdsItsHeaderUntilItsFirstBodyByte() {
		w.sendHeader(code)
		return
	}
	if w.heldCode == 0 {
		w.heldCode = code
	}
}

func (w *replyWriter) sendHeader(code int) {
	if w.at != unclaimed {
		return
	}
	if w.claim != nil && !w.claim() {
		w.enter(lost)
		return
	}
	w.enter(claimed)
	outer := w.outer.Header()
	for name, values := range w.header {
		outer[name] = values
	}
	w.outer.WriteHeader(code)
}

func (w *replyWriter) sendHeldHeaderOfAnEmptyReply() {
	if w.heldCode != 0 {
		w.sendHeader(w.heldCode)
	}
}

func (w *replyWriter) Write(p []byte) (int, error) {
	if len(p) == 0 && w.at == unclaimed && w.holdsItsHeaderUntilItsFirstBodyByte() {
		return 0, nil
	}
	if len(p) > 0 && w.claim != nil && w.firstByte.Load() == 0 {
		w.firstByte.Store(int64(max(time.Since(w.since), 1)))
	}
	w.sendHeader(cmp.Or(w.heldCode, http.StatusOK))
	if w.at == lost {
		return 0, errLostTheReply
	}
	if w.at == claimed && len(p) > 0 {
		w.enter(bodyBegun)
	}
	n, err := w.outer.Write(p)
	if w.writeErr == nil {
		w.writeErr = err
	}
	return n, err
}

func (w *replyWriter) FlushError() error {
	if w.at == lost {
		return errLostTheReply
	}
	if w.at == unclaimed && w.holdsItsHeaderUntilItsFirstBodyByte() {
		return nil
	}
	err := http.NewResponseController(w.outer).Flush()
	if w.writeErr == nil {
		w.writeErr = err
	}
	return err
}

func (w *replyWriter) streamed() bool { return streamed(w.header.Get("Content-Type")) }

func (w *replyWriter) observed(ctx context.Context, callErr error, cutForCaller bool, opened, returned time.Time) health.Observation {
	began := w.at == bodyBegun
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
