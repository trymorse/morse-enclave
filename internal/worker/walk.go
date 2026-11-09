package worker

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"morse/backend/internal/billing/measure"
)

// A leg is one endpoint's try in a walk. It writes through its own writer, which reaches the client only once the leg
// claims the reply.
type leg struct {
	// at is the endpoint's place in the grant.
	at     int
	a      attempt
	rw     *replyWriter
	opened time.Time
	hedge  *time.Timer
	// silent is set once the leg has been silent for its hedge wait, after which the next endpoint may race it.
	silent bool
}

type legEnd struct {
	*leg
	got served
	e   measure.Evidence
	m   Measured
	// panicked is what the try panicked with. The walk raises it again when the try had begun the client's reply or no
	// other try answered, and reports it otherwise.
	panicked any
}

// walk tries the granted endpoints in order. It moves to the next when a try fails over before the client's first
// byte, and also when a streamed try has been silent for its hedge wait: the next endpoint's call then races it, and
// the first to write serves the client. At most two endpoints run at once. The walk ends once the serving try does, or
// once a try ends with an outcome that stands while no earlier endpoint's try is still running, as it would have ended
// with no race. A try left running loses the reply and runs on to its first chunk, which ends it unreported, or to its
// failure, which Late yields: a stalled host's try ends at its stall deadline, so the host's breaker hears of the
// stall even when another endpoint answered the chat. An endpoint with no next that can race it hedges with a second
// call to itself, as the last one does.
func (o *openedChat) walk(ctx context.Context, w *InProcess, granted []chatRoute, g ChatGrant, rw *replyWriter) legEnd {
	var claim atomic.Pointer[leg]
	silent := make(chan *leg, len(granted))
	ended := make(chan legEnd, len(granted))
	opened := time.Now()
	var flying []*leg
	var won, stood, panicked *legEnd
	var failed []legEnd
	next, retries, hedges := 0, 0, 0
	races := func(i int) bool { return i < len(granted) && granted[i].hedge(o.call).After > 0 }
	start := func() {
		i := next
		next++
		h := granted[i].hedge(o.call)
		away := races(i + 1)
		l := &leg{at: i, a: o.attempt(granted[i], g, i == len(granted)-1, !away), opened: time.Now()}
		l.rw = claiming(rw, func() bool { return claim.CompareAndSwap(nil, l) || claim.Load() == l })
		l.rw.Header().Set(HeaderTier, l.a.route.tier.String())
		if wait := h.Wait(o.promptTokens()); away && wait > 0 {
			l.hedge = time.AfterFunc(wait, func() { silent <- l })
		}
		flying = append(flying, l)
		go func() {
			end := legEnd{leg: l}
			defer func() {
				end.panicked = recover()
				ended <- end
			}()
			end.got, end.e, end.m = o.try(ctx, w, l.a, g, l.rw)
		}()
	}
	start()
	// answered says the walk has its answer: a try served, or one stands that no earlier try can overtake and that now
	// holds the reply, so a try left running can no longer write to the client.
	answered := func() bool {
		if won != nil {
			return true
		}
		return stood != nil && !slices.ContainsFunc(flying, func(l *leg) bool { return l.at < stood.at }) &&
			(claim.CompareAndSwap(nil, stood.leg) || claim.Load() == stood.leg)
	}
	for len(flying) > 0 && !answered() {
		select {
		case l := <-silent:
			l.silent = true
		case end := <-ended:
			flying = slices.DeleteFunc(flying, func(l *leg) bool { return l == end.leg })
			if end.hedge != nil {
				end.hedge.Stop()
			}
			retries, hedges = retries+end.m.Health.Retries, hedges+end.m.Health.Hedges
			switch {
			case end.panicked != nil:
				panicked = cmp.Or(panicked, &end)
			case claim.Load() == end.leg:
				won = &end
			case end.rw.lost:
			case end.failedOver():
				failed = append(failed, end)
			case stood == nil || end.at < stood.at:
				stood = &end
			}
		}
		switch {
		case claim.Load() != nil, stood != nil, panicked != nil, next == len(granted):
		case len(flying) == 0:
			retries++
			start()
		case len(flying) == 1 && flying[0].silent && races(next):
			hedges++
			start()
		}
	}
	final := cmp.Or(won, stood)
	if panicked != nil {
		if final == nil || claim.Load() == panicked.leg {
			panic(panicked.panicked)
		}
		w.reports.Failed(string(panicked.a.route.endpoint), fmt.Errorf("worker: a try panicked while another answered: %v", panicked.panicked))
	}
	if final == nil {
		final, failed = &failed[len(failed)-1], failed[:len(failed)-1]
	}
	m := &final.m
	for _, f := range failed {
		m.FailedOver = append(m.FailedOver, Try{Endpoint: f.a.route.endpoint, Health: f.m.Health})
	}
	m.Health.Retries, m.Health.Hedges = retries, hedges
	if m.Health.TTFT > 0 {
		m.VendorWait = final.opened.Sub(opened) + m.Health.TTFT
	}
	if len(flying) > 0 {
		m.Late, m.Lingers = lingering(w.reports, ended, len(flying)), true
	}
	return *final
}

func (e legEnd) failedOver() bool {
	return e.m.Health.Outcome.FailsOver() && !brokeSeal(e.got.callErr)
}

// lingering waits out the n tries an answered walk left running, yields each that failed over as it ends, and closes once
// all have ended. A try that panicked is reported, since no handler is left to raise it.
func lingering(reports Reporter, ended <-chan legEnd, n int) <-chan Try {
	late := make(chan Try, n)
	go func() {
		defer close(late)
		for range n {
			switch end := <-ended; {
			case end.panicked != nil:
				reports.Failed(string(end.a.route.endpoint), fmt.Errorf("worker: a try the walk left running panicked: %v", end.panicked))
			case !end.rw.lost && end.failedOver():
				late <- Try{Endpoint: end.a.route.endpoint, Health: end.m.Health}
			}
		}
	}()
	return late
}
