package flight

import (
	"context"
	"sync"
	"time"
)

// Keyed holds a value per key until the expiry Fetch gave it, and at most Max keys: making room drops the key that
// expires first. Concurrent misses on one key share a fetch. A value whose expiry is not after its fetch's now
// goes to the callers that waited on it and is not kept.
type Keyed[V any] struct {
	Fetch   func(ctx context.Context, key string, now time.Time) (value V, until time.Time, err error)
	Max     int
	Timeout time.Duration

	mu      sync.Mutex
	entries map[string]expiring[V]
	group   Group[V]
}

type expiring[V any] struct {
	value V
	until time.Time
}

// Peek is the value key holds at now, without a fetch.
func (k *Keyed[V]) Peek(key string, now time.Time) (V, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.entries[key]
	if !ok || !now.Before(e.until) {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Get is the value key holds at now, or else what Fetch makes of it.
func (k *Keyed[V]) Get(ctx context.Context, key string, now time.Time) (V, error) {
	if v, ok := k.Peek(key, now); ok {
		return v, nil
	}
	return k.group.Do(ctx, key, k.Timeout, func(ctx context.Context) (V, error) {
		v, until, err := k.Fetch(ctx, key, now)
		if err == nil && now.Before(until) {
			k.keep(key, expiring[V]{v, until}, now)
		}
		return v, err
	})
}

func (k *Keyed[V]) keep(key string, e expiring[V], now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.entries == nil {
		k.entries = map[string]expiring[V]{}
	}
	soonest := ""
	for other, held := range k.entries {
		if !now.Before(held.until) {
			delete(k.entries, other)
		} else if soonest == "" || held.until.Before(k.entries[soonest].until) {
			soonest = other
		}
	}
	if _, held := k.entries[key]; !held && len(k.entries) >= k.Max {
		delete(k.entries, soonest)
	}
	k.entries[key] = e
}
