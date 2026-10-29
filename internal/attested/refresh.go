package attested

import (
	"context"
	"errors"
	"time"
)

const (
	reverifyTimeout          = 10 * time.Second
	reverifyWindow           = 30 * time.Second
	backgroundRefreshTimeout = 60 * time.Second
	refreshEvery             = 10 * time.Minute
	wakeWindow               = time.Minute
	minBackoff               = 5 * time.Second
	maxBackoff               = 2 * time.Minute
)

var errRateLimited = errors.New("attested: a verification was attempted within the reverify window")

type attempt struct {
	done chan struct{}
	err  error
}

func (g *Gate[K]) Reverify(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, reverifyTimeout)
	defer cancel()
	return g.refresh(ctx, reverifyWindow)
}

func (g *Gate[K]) refresh(ctx context.Context, window time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	a := g.attempt
	if a == nil {
		if g.now().Sub(g.lastAttempt) < window {
			g.mu.Unlock()
			return errRateLimited
		}
		a = &attempt{done: make(chan struct{})}
		g.attempt, g.lastAttempt = a, g.now()
		go g.verify(context.WithoutCancel(ctx), a)
	}
	g.mu.Unlock()
	select {
	case <-a.done:
		return a.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *Gate[K]) verify(ctx context.Context, a *attempt) {
	ctx, cancel := context.WithTimeout(ctx, backgroundRefreshTimeout)
	defer cancel()
	a.err = g.verifyOnce(ctx)
	if a.err != nil {
		g.failed(a.err)
	}
	g.mu.Lock()
	g.attempt = nil
	g.mu.Unlock()
	close(a.done)
}

func (g *Gate[K]) earliestExpiry() (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var earliest time.Time
	for _, ep := range g.endpoints {
		if earliest.IsZero() || ep.notAfter.Before(earliest) {
			earliest = ep.notAfter
		}
	}
	return earliest, !earliest.IsZero()
}

func (g *Gate[K]) Wake() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (g *Gate[K]) Run(ctx context.Context) {
	backoff := g.minBackoff
	for {
		err := g.refresh(ctx, 0)
		if ctx.Err() != nil {
			return
		}
		wait := refreshEvery
		if err != nil {
			wait, backoff = backoff, min(2*backoff, g.maxBackoff)
		} else {
			backoff = g.minBackoff
		}
		if expiry, ok := g.earliestExpiry(); ok {
			wait = min(wait, max(expiry.Sub(g.now()), 0))
		}
		if !g.sleep(ctx, wait) {
			return
		}
		g.reanchor()
	}
}

func (g *Gate[K]) sleep(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var deferred <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-g.wake:
			deferred = g.wakeNow(ctx, deferred)
		case <-deferred:
			deferred = g.wakeNow(ctx, nil)
		}
	}
}

func (g *Gate[K]) wakeNow(ctx context.Context, deferred <-chan time.Time) <-chan time.Time {
	if err := g.refresh(ctx, wakeWindow); !errors.Is(err, errRateLimited) {
		return nil
	}
	if deferred != nil {
		return deferred
	}
	g.mu.Lock()
	remaining := wakeWindow - g.now().Sub(g.lastAttempt)
	g.mu.Unlock()
	return g.after(max(remaining, 0))
}
