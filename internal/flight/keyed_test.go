package flight

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type fetchLog struct{ fetched []string }

func (l *fetchLog) keyed(max int, lifetime func(key string) time.Duration) *Keyed[string] {
	return &Keyed[string]{Max: max, Timeout: time.Minute, Fetch: func(_ context.Context, key string, now time.Time) (string, time.Time, error) {
		l.fetched = append(l.fetched, key)
		return "value of " + key, now.Add(lifetime(key)), nil
	}}
}

func TestAKeyServesAgainUntilItsExpiryAndIsFetchedAfter(t *testing.T) {
	var log fetchLog
	k := log.keyed(4, func(string) time.Duration { return time.Minute })
	ctx, start := context.Background(), time.Now()
	for _, at := range []time.Duration{0, time.Second, time.Minute - time.Nanosecond, time.Minute} {
		if v, err := k.Get(ctx, "a", start.Add(at)); v != "value of a" || err != nil {
			t.Fatalf("at %v: %q %v", at, v, err)
		}
	}
	if len(log.fetched) != 2 {
		t.Errorf("fetched %q, want once at the start and once at the expiry", log.fetched)
	}
	if _, ok := k.Peek("a", start.Add(2*time.Minute)); ok {
		t.Errorf("Peek served a value past its expiry")
	}
}

func TestAValueThatExpiresAtOnceAndAFailureAreNotKept(t *testing.T) {
	var log fetchLog
	k := log.keyed(4, func(string) time.Duration { return 0 })
	ctx, now := context.Background(), time.Now()
	for range 2 {
		if v, err := k.Get(ctx, "a", now); v != "value of a" || err != nil {
			t.Errorf("%q %v, want the value handed to its caller", v, err)
		}
	}
	failures := 0
	failing := &Keyed[string]{Max: 4, Timeout: time.Minute, Fetch: func(context.Context, string, time.Time) (string, time.Time, error) {
		failures++
		return "", now.Add(time.Hour), errors.New("down")
	}}
	for range 2 {
		failing.Get(ctx, "a", now)
	}
	if len(log.fetched) != 2 || failures != 2 {
		t.Errorf("%d and %d fetches, want each get to fetch", len(log.fetched), failures)
	}
}

func TestAFullCacheDropsTheKeyThatExpiresFirst(t *testing.T) {
	var log fetchLog
	const max = 3
	k := log.keyed(max, func(key string) time.Duration {
		if key == "short" {
			return time.Minute
		}
		return time.Hour
	})
	ctx, now := context.Background(), time.Now()
	for i := range max - 1 {
		k.Get(ctx, fmt.Sprint(i), now.Add(time.Duration(i)*time.Second))
	}
	k.Get(ctx, "short", now.Add(time.Hour/2))
	k.Get(ctx, "newest", now.Add(time.Hour/2))
	if _, ok := k.Peek("short", now.Add(time.Hour/2)); ok {
		t.Errorf("the key expiring first is still held")
	}
	for _, key := range []string{"0", "1", "newest"} {
		if _, ok := k.Peek(key, now.Add(time.Hour/2)); !ok {
			t.Errorf("%s was dropped", key)
		}
	}
	k.Get(ctx, "later", now.Add(time.Hour/2+time.Second))
	if _, ok := k.Peek("0", now.Add(time.Hour/2+time.Second)); ok {
		t.Errorf("the oldest of keys with one lifetime is still held")
	}
}
