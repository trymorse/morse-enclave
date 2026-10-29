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
// refusal names, otherwise on its own provider after the next of Waits. Reroutes and waits each get len(Waits), so a
// call reaches the vendor at most 1+2*len(Waits) times. A refusal after a chunk went out stands.
type BusyRetry struct {
	Provider
	Waits []time.Duration
}

// Attempts is what the retries left behind. Refused is set when the last call ended in a busy refusal before any
// chunk: the vendor served nothing and has nothing in flight, whoever cut the request meanwhile.
type Attempts struct {
	Retries int
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
		u, err := p.Stream(ctx, c, counted)
		if emitted {
			return u, Attempts{Retries: t.retries}, err
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
	retries, rerouted, waited int
}

func (t *tries) ended(err error) Attempts { return Attempts{Retries: t.retries, Refused: busy(err)} }

func (t *tries) next(ctx context.Context, err error) Provider {
	if !busy(err) {
		return nil
	}
	if re, ok := errors.AsType[Reroutable](err); ok && t.rerouted < len(t.Waits) {
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
