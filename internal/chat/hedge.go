package chat

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"morse/backend/internal/upstream"
)

// A Hedge is how long a call may emit nothing on a route where a late first chunk is the vendor's stall. Past Wait, a
// second call races it: whichever emits first serves the client and the other is cut. Past Stall, StallWaits times
// as long, the call is given up as stalled, so a chat moves past a host that sent no headers, or headers and then
// nothing. The zero Hedge does neither.
type Hedge struct {
	After                  time.Duration
	PrefillTokensPerSecond int
}

// StallWaits sizes the stall deadline from the hedge's wait. DefaultHedge then gives a call up after 30s of silence
// for a short prompt, 50s at 10,000 tokens, and 230s at 100,000: long past a healthy host's first token and the
// prefill the wait already allows for.
const StallWaits = 10

// DefaultHedge races a call silent for 3s, and a second more for each 5,000 prompt tokens, since a long prefill makes a
// first token late without a stall.
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

// Stall is how long a call with promptTokens may stay silent before it is given up, or 0 for never.
func (h Hedge) Stall(promptTokens int) time.Duration { return StallWaits * h.Wait(promptTokens) }

var errHedgeLost = errors.New("chat: the hedge's other call emitted first")

type leg struct{ cancel context.CancelFunc }

type legEvent struct {
	leg     *leg
	claimed bool
	usage   Usage
	err     error
}

// hedged makes the call, and a second identical one when the first has emitted nothing by after, 0 for never. When
// neither has emitted by stall, 0 for never, both are cut and the call ends upstream.ErrStalled.
func hedged(ctx context.Context, p Provider, c Call, emit func(Chunk) error, after, stall time.Duration) (Usage, bool, error) {
	caller := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// winner is the leg that emitted first, or -1 once the call was given up, after which no leg may emit.
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
	fire, stop := timer(after)
	defer stop()
	giveUp, stopGiveUp := timer(stall)
	defer stopGiveUp()
	stalled := false
	for live := 1; live > 0; {
		select {
		case <-fire:
			fire = nil
			if winner.Load() == 0 {
				second = start(2)
				live++
			}
		case <-giveUp:
			fire, giveUp = nil, nil
			if caller.Err() == nil && winner.CompareAndSwap(0, -1) {
				stalled = true
				cancel()
			}
		case e := <-events:
			switch {
			case e.claimed:
				won, fire, giveUp = e.leg, nil, nil
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
	if stalled {
		err = upstream.Stalled(err)
	}
	return usage, second != nil, err
}

// timer fires once after d, or never when d is 0.
func timer(d time.Duration) (<-chan time.Time, func() bool) {
	if d <= 0 {
		return nil, func() bool { return false }
	}
	t := time.NewTimer(d)
	return t.C, t.Stop
}
