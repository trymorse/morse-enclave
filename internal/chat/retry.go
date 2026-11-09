package chat

import (
	"context"
	"errors"
	"time"

	"morse/backend/internal/apierr"
)

var BusyWaits = []time.Duration{time.Second, 2 * time.Second}

// A Reroutable busy refusal names a provider that routes past whatever refused, as OpenRouter's does when it names
// the host that was busy.
type Reroutable interface {
	error
	Reroute() Provider
}

// BusyRetry calls again on a busy refusal that arrives before the first chunk: at once on the provider a Reroutable
// refusal names, otherwise on its own provider after the next of Waits. Waits get len(Waits) tries and reroutes get
// max(len(Waits), 1), so a call reaches the vendor at most 1+len(Waits)+max(len(Waits), 1) times, twice that when
// each is hedged. A refusal after a chunk went out stands. A Stream call that has emitted nothing by HedgeAfter is
// raced by a second identical call: the first to emit serves the client and the other is cut, and when both fail
// before emitting the first call's error stands. Zero never races. A Stream call that has emitted nothing by
// StallAfter, hedge and all, is cut and ends upstream.ErrStalled, which no busy wait retries. Zero waits on.
type BusyRetry struct {
	Provider
	Waits      []time.Duration
	HedgeAfter time.Duration
	StallAfter time.Duration
}

// Attempts is what the retries left behind. Hedges counts the second calls the hedge made. Refused is set when the
// last call ended in a busy refusal before any chunk: the vendor served nothing and has nothing in flight, whoever
// cut the request meanwhile.
type Attempts struct {
	Retries int
	Hedges  int
	Refused bool
}

func (r BusyRetry) Stream(ctx context.Context, c Call, emit func(Chunk) error) (Usage, Attempts, error) {
	emitted := false
	counted := func(ch Chunk) error {
		emitted = true
		return emit(ch)
	}
	t := tries{BusyRetry: r}
	for p := r.Provider; ; {
		u, err := t.stream(ctx, p, c, counted)
		if emitted {
			return u, t.attempts(), err
		}
		if p = t.next(ctx, err); p == nil {
			return u, t.ended(err), err
		}
	}
}

func (r BusyRetry) Complete(ctx context.Context, c Call) (Chunk, Usage, Attempts, error) {
	t := tries{BusyRetry: r}
	for p := r.Provider; ; {
		ch, u, err := p.Complete(ctx, c)
		if p = t.next(ctx, err); p == nil {
			return ch, u, t.ended(err), err
		}
	}
}

type tries struct {
	BusyRetry
	retries, rerouted, waited, hedges int
}

func (t *tries) stream(ctx context.Context, p Provider, c Call, emit func(Chunk) error) (Usage, error) {
	if t.HedgeAfter == 0 && t.StallAfter == 0 {
		return p.Stream(ctx, c, emit)
	}
	u, hedged, err := hedged(ctx, p, c, emit, t.HedgeAfter, t.StallAfter)
	if hedged {
		t.hedges++
	}
	return u, err
}

func (t *tries) attempts() Attempts { return Attempts{Retries: t.retries, Hedges: t.hedges} }

func (t *tries) ended(err error) Attempts {
	a := t.attempts()
	a.Refused = busy(err)
	return a
}

func (t *tries) next(ctx context.Context, err error) Provider {
	if !busy(err) {
		return nil
	}
	if re, ok := errors.AsType[Reroutable](err); ok && t.rerouted < max(len(t.Waits), 1) {
		t.rerouted++
		t.retries++
		return re.Reroute()
	}
	if t.waited == len(t.Waits) {
		return nil
	}
	timer := time.NewTimer(t.Waits[t.waited])
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		t.waited++
		t.retries++
		return t.Provider
	}
}

func busy(err error) bool {
	var e apierr.Error
	return errors.As(err, &e) && e.Code == apierr.ErrUpstreamBusy.Code
}
