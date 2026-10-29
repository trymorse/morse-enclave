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

func (g *Gate[K]) Reverify(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, reverifyTimeout)
	defer cancel()
	return g.refresh(ctx, reverifyWindow)
}

func (g *Gate[K]) refresh(ctx context.Context, window time.Duration) error {
	g.mu.Lock()
	limited := !g.verifying && g.now().Sub(g.lastAttempt) < window
	g.mu.Unlock()
	if limited {
		return errRateLimited
	}
	_, err := g.flight.Do(ctx, "verify", backgroundRefreshTimeout, func(ctx context.Context) (struct{}, error) {
		g.mu.Lock()
		g.verifying, g.lastAttempt = true, g.now()
		g.mu.Unlock()
		err := g.verifyOnce(ctx)
		if err != nil {
			g.failed(err)
		}
		g.mu.Lock()
		g.verifying = false
		g.mu.Unlock()
		return struct{}{}, err
	})
	return err
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
