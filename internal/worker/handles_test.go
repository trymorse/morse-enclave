package worker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"morse/backend/internal/billing/measure"
)

type heldRun struct {
	started chan struct{}
	proceed chan struct{}
	wrote   chan error
}

func (*heldRun) cut(measure.Cut) {}

func (r *heldRun) run(_ context.Context, _ *InProcess, _ Handle, _ Grant, reply http.ResponseWriter) Measured {
	close(r.started)
	<-r.proceed
	_, err := reply.Write([]byte("late"))
	r.wrote <- err
	return Measured{}
}

func TestARunWritesNothingMoreToTheRelayOnceItsClientLeftAndKeepsWritingWhenTheRelayCutsIt(t *testing.T) {
	for reason, want := range map[measure.Cut]error{
		measure.CutByClient:   errClientLeft,
		measure.CutByDeadline: errClientLeft,
		measure.CutByProxy:    nil,
	} {
		w, err := NewInProcess(Config{})
		if err != nil {
			t.Fatal(err)
		}
		run := &heldRun{started: make(chan struct{}), proceed: make(chan struct{}), wrote: make(chan error, 1)}
		h := w.keep(Opening{}, run)
		recorder := httptest.NewRecorder()
		done := make(chan Measured)
		go func() { done <- w.Run(context.Background(), h, ChatGrant{}, &chunkedReply{ResponseWriter: recorder}) }()
		<-run.started
		w.Cut(h, reason)
		close(run.proceed)
		<-done
		if got := <-run.wrote; !errors.Is(got, want) {
			t.Errorf("after a cut %v the run's write returned %v, want %v", reason, got, want)
		}
	}
}
