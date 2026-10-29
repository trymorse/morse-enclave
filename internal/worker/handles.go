package worker

import (
	"context"
	"errors"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/health"
	"morse/backend/internal/media"
)

type opened interface{ cut(reason measure.Cut) }

type runs interface {
	run(ctx context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured
}

type submits interface {
	submit(w *InProcess, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured
}

type entry struct {
	opened
	phase     phase
	expire    *time.Timer
	cek       *[32]byte
	acked     chan struct{}
	leave     func()
	counted   <-chan Count
	stopCount context.CancelFunc
}

type leaver interface{ leave() }

type phase uint8

const (
	waiting phase = iota
	running
	counting
)

const OpenedFor = 30 * time.Second

func (w *InProcess) keep(o Opening, run opened) Handle {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last++
	h := Handle{w.last}
	e := &entry{opened: run, cek: o.cek, acked: make(chan struct{}, 1)}
	e.expire = time.AfterFunc(OpenedFor, func() { w.forget(h) })
	w.opened[h] = e
	return h
}

func (w *InProcess) entry(h Handle) *entry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.opened[h]
}

func (w *InProcess) forget(h Handle) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.opened, h)
}

func (w *InProcess) start(h Handle, reply http.ResponseWriter) *entry {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[h]
	if e == nil || e.phase != waiting {
		return nil
	}
	e.expire.Stop()
	e.phase = running
	if l, ok := reply.(leaver); ok {
		e.leave = l.leave
	}
	return e
}

func (w *InProcess) ran(h Handle, m Measured) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[h]
	switch {
	case e == nil:
	case m.Follow == FollowNone:
		delete(w.opened, h)
	default:
		e.phase, e.leave, e.counted = counting, nil, m.Counted
		e.expire.Reset(OpenedFor)
	}
}

func (w *InProcess) ack(h Handle) bool {
	e := w.entry(h)
	if e == nil {
		return false
	}
	select {
	case e.acked <- struct{}{}:
	default:
	}
	return true
}

func (w *InProcess) takeCount(h Handle) <-chan Count {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[h]
	if e == nil || e.phase != counting {
		return nil
	}
	counted := e.counted
	e.counted = nil
	return counted
}

func (w *InProcess) Run(ctx context.Context, h Handle, g Grant, reply http.ResponseWriter) Measured {
	return w.serve(h, reply, func(e *entry, reply http.ResponseWriter) Measured {
		r, ok := e.opened.(runs)
		if !ok {
			return unrunnable(reply)
		}
		return r.run(ctx, w, h, g, reply)
	})
}

func (w *InProcess) Submit(_ context.Context, h Handle, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured {
	return w.serve(h, reply, func(e *entry, reply http.ResponseWriter) Measured {
		s, ok := e.opened.(submits)
		if !ok {
			return unrunnable(reply)
		}
		return s.submit(w, g, reply, accepted)
	})
}

func (w *InProcess) serve(h Handle, reply http.ResponseWriter, run func(e *entry, reply http.ResponseWriter) Measured) Measured {
	e := w.start(h, reply)
	if e == nil {
		return unrunnable(reply)
	}
	var sealed *sealedReply
	if e.cek != nil {
		sealed = newSealedReply(reply, *e.cek)
		defer sealed.close()
		reply = sealed
	}
	m := run(e, reply)
	if sealed != nil {
		sealed.finish(&m)
	}
	w.ran(h, m)
	return m
}

func unrunnable(reply http.ResponseWriter) Measured {
	apierr.WriteError(reply, apierr.ErrUnavailable)
	return Measured{Measurement: measure.Measurement{Outcome: measure.Failed}, Health: health.Observation{Outcome: health.UpstreamUnavailable}}
}

func (w *InProcess) Cut(h Handle, reason measure.Cut) {
	w.mu.Lock()
	e := w.opened[h]
	if e == nil {
		w.mu.Unlock()
		return
	}
	if e.phase == waiting {
		e.expire.Stop()
		delete(w.opened, h)
		w.mu.Unlock()
		return
	}
	leave, stopCount := e.leave, e.stopCount
	w.mu.Unlock()
	e.cut(reason)
	if leave != nil && reason != measure.CutByProxy {
		leave()
	}
	if stopCount != nil && reason == measure.CutByProxy {
		stopCount()
	}
}

var ErrShutdown = errors.New("proxy: streams cut at shutdown")

var cutCauses = map[measure.Cut]error{
	measure.CutByClient:   context.Canceled,
	measure.CutByDeadline: context.DeadlineExceeded,
	measure.CutByProxy:    ErrShutdown,
}

type cuts struct {
	run, client   context.Context
	cancel, leave context.CancelCauseFunc
}

func newCuts() cuts {
	var c cuts
	c.run, c.cancel = context.WithCancelCause(context.Background())
	c.client, c.leave = context.WithCancelCause(context.Background())
	return c
}

func (c cuts) cut(reason measure.Cut, endsWithCaller bool) {
	cause := cutCauses[reason]
	c.leave(cause)
	if reason != measure.CutByClient || endsWithCaller {
		c.cancel(cause)
	}
}
