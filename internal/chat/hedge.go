package chat

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"morse/backend/internal/upstream"
)

// A Hedge is a second, identical call to the provider, made when the first has emitted nothing by After plus the
// prompt's prefill at PrefillTokensPerSecond. Whichever call emits first serves the client and the other is cut. The
// zero Hedge never makes one.
type Hedge struct {
	After                  time.Duration
	PrefillTokensPerSecond int
}

// DefaultHedge waits 3s, and a second more for each 5,000 prompt tokens, since a long prefill makes a first token late
// without a stall.
var DefaultHedge = Hedge{After: 3 * time.Second, PrefillTokensPerSecond: 5000}

// Wait is how long a call with promptTokens may stay silent before the hedge, or 0 for never.
func (h Hedge) Wait(promptTokens int) time.Duration {
	switch {
	case h.After == 0:
		return 0
	case h.PrefillTokensPerSecond <= 0:
		return h.After
	}
	return h.After + time.Second*time.Duration(promptTokens)/time.Duration(h.PrefillTokensPerSecond)
}

var errHedgeLost = errors.New("chat: the hedge's other call emitted first")

type leg struct{ cancel context.CancelFunc }

type legEvent struct {
	leg     *leg
	claimed bool
	usage   Usage
	err     error
}

func hedged(ctx context.Context, p Provider, c Call, emit func(Chunk) error, after time.Duration) (Usage, bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var winner atomic.Int32
	events := make(chan legEvent, 4)
	start := func(n int32) *leg {
		ctx, cancel := context.WithCancel(ctx)
		l := &leg{cancel: cancel}
		go func() {
			u, err := p.Stream(ctx, c, func(ch Chunk) error {
				if winner.CompareAndSwap(0, n) {
					events <- legEvent{leg: l, claimed: true}
				}
				if winner.Load() != n {
					return errHedgeLost
				}
				return emit(ch)
			})
			events <- legEvent{leg: l, usage: u, err: err}
		}()
		return l
	}
	first := start(1)
	var second, won *leg
	var usage Usage
	var err, hedgeErr error
	timer := time.NewTimer(after)
	defer timer.Stop()
	fire := timer.C
	for live := 1; live > 0; {
		select {
		case <-fire:
			fire = nil
			if winner.Load() == 0 {
				second = start(2)
				live++
			}
		case e := <-events:
			switch {
			case e.claimed:
				won, fire = e.leg, nil
				for _, l := range []*leg{first, second} {
					if l != nil && l != won {
						l.cancel()
					}
				}
			case e.leg == won, won == nil && e.leg == first:
				usage, err = e.usage, e.err
				live--
			case won == nil && e.leg == second:
				hedgeErr = e.err
				live--
			default:
				live--
			}
		}
	}
	// With no winner the first call's error stands, unless it never reached the host and the hedge did: a chat a host
	// received is billed as received.
	if won == nil && errors.Is(err, upstream.ErrNotSent) && hedgeErr != nil && !errors.Is(hedgeErr, upstream.ErrNotSent) {
		err = hedgeErr
	}
	return usage, second != nil, err
}
