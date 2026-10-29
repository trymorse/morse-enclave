package flight

import (
	"context"
	"sync/atomic"
	"time"
)

// Cache holds the last value Fetch produced. Fetch attempts are at least MinRefetch apart, and one that fails
// keeps the previous value and reports its error until the next attempt.
type Cache[T any] struct {
	Fetch      func(context.Context) (T, error)
	MaxAge     time.Duration
	MinRefetch time.Duration
	Timeout    time.Duration

	latest atomic.Pointer[cached[T]]
	group  Group[refresh[T]]
}

type cached[T any] struct {
	value     T
	fetchedAt time.Time
	triedAt   time.Time
	err       error
}

type refresh[T any] struct {
	*cached[T]
	fetched bool
}

// Current is the value while it is younger than MaxAge, whatever a later attempt did, and otherwise a Refresh.
func (c *Cache[T]) Current(ctx context.Context, now time.Time) (T, error) {
	if e := c.young(now); e != nil {
		return e.value, nil
	}
	value, _, err := c.Refresh(ctx, now)
	return value, err
}

// Read is Current with the last attempt's failure reported beside a value that is still young.
func (c *Cache[T]) Read(ctx context.Context, now time.Time) (value T, fetched bool, err error) {
	if e := c.young(now); e != nil {
		return e.value, false, e.err
	}
	return c.Refresh(ctx, now)
}

func (c *Cache[T]) young(now time.Time) *cached[T] {
	if e := c.latest.Load(); e != nil && !e.fetchedAt.IsZero() && now.Sub(e.fetchedAt) < c.MaxAge {
		return e
	}
	return nil
}

// Refresh fetches unless the last attempt is younger than MinRefetch, and fetched reports whether it did. Its
// value is the latest one fetched, even when err reports that the last attempt failed or that ctx ended first.
func (c *Cache[T]) Refresh(ctx context.Context, now time.Time) (value T, fetched bool, err error) {
	r, err := c.group.Do(ctx, "", c.Timeout, func(ctx context.Context) (refresh[T], error) {
		prev := c.latest.Load()
		if prev != nil && now.Sub(prev.triedAt) < c.MinRefetch {
			return refresh[T]{cached: prev}, nil
		}
		value, err := c.Fetch(ctx)
		next := &cached[T]{triedAt: now, err: err}
		switch {
		case err == nil:
			next.value, next.fetchedAt = value, now
		case prev != nil:
			next.value, next.fetchedAt = prev.value, prev.fetchedAt
		}
		c.latest.Store(next)
		return refresh[T]{cached: next, fetched: true}, nil
	})
	if err != nil {
		if e := c.latest.Load(); e != nil {
			return e.value, false, err
		}
		return value, false, err
	}
	return r.value, r.fetched, r.err
}
