package lookup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"morse/backend/internal/plans/limits"
)

type upstreamLog struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (u *upstreamLog) add(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = append(u.requests, r.Clone(context.Background()))
}

func (u *upstreamLog) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

func (u *upstreamLog) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[len(u.requests)-1]
}

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

const reply = `{"ok":true}`

func serving(t *testing.T, handle http.HandlerFunc) (*httptest.Server, *upstreamLog) {
	t.Helper()
	log := &upstreamLog{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		handle(w, r)
	}))
	t.Cleanup(up.Close)
	return up, log
}

func answering(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(body))
	}
}

func relayTo(up *httptest.Server, s Service, c *clock) *Relay {
	s.Base = up.URL
	if s.TTL == nil {
		s.TTL = fixed(time.Hour)
	}
	if s.Limit == (limits.SharedLimit{}) {
		s.Limit = shared("test", 60)
	}
	return New(map[string]Service{"svc": s}, up.Client(), c.now)
}

func TestOnlyAllowlistedPathsOfKnownServicesReachTheUpstream(t *testing.T) {
	up, log := serving(t, answering(reply))
	r := relayTo(up, Service{Paths: []string{"/w/api.php"}}, &clock{at: time.Now()})
	for _, tc := range []struct{ service, path string }{
		{"nope", "w/api.php"},
		{"svc", "w/index.php"},
		{"svc", "w/api.php/extra"},
		{"svc", "w"},
		{"svc", ""},
		{"svc", "w/../w/api.php"},
	} {
		if _, err := r.Look(tc.service, tc.path, "q=1"); !errors.Is(err, ErrNotFound) {
			t.Errorf("look %s %q: %v, want lookup_not_found", tc.service, tc.path, err)
		}
		if _, err := r.Get(context.Background(), tc.service, tc.path, "q=1"); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s %q: %v, want lookup_not_found", tc.service, tc.path, err)
		}
	}
	if log.count() != 0 {
		t.Errorf("refused lookups made %d upstream calls, want none", log.count())
	}
	if body, err := r.Get(context.Background(), "svc", "w/api.php", "q=1"); err != nil || string(body) != reply {
		t.Fatalf("allowlisted path: %q %v", body, err)
	}
	if got := log.last().URL.RequestURI(); got != "/w/api.php?q=1" {
		t.Errorf("upstream saw %s, want /w/api.php?q=1", got)
	}
}

func TestTheUpstreamSeesOnlyOurUserAgentAndAccept(t *testing.T) {
	up, log := serving(t, answering(reply))
	r := relayTo(up, Service{Paths: []string{"/a"}}, &clock{at: time.Now()})
	if _, err := r.Get(context.Background(), "svc", "a", ""); err != nil {
		t.Fatal(err)
	}
	h := log.last().Header
	if h.Get("User-Agent") != UserAgent {
		t.Errorf("User-Agent %q, want %q", h.Get("User-Agent"), UserAgent)
	}
	for name := range h {
		switch name {
		case "User-Agent", "Accept", "Accept-Encoding":
		default:
			t.Errorf("upstream got header %s: %q", name, h.Values(name))
		}
	}
}

func TestACacheHitNeitherCallsTheUpstreamNorLooksLikeAMiss(t *testing.T) {
	up, log := serving(t, answering(reply))
	c := &clock{at: time.Now()}
	limit := shared("wiki", 30)
	r := relayTo(up, Service{Paths: []string{"/a"}, TTL: fixed(time.Minute), Limit: limit}, c)
	var looks []bool
	for _, query := range []string{"b=2&a=1", "a=1&b=2", "a=1&b=2"} {
		l, err := r.Look("svc", "a", query)
		if err != nil || l.Limit != limit {
			t.Fatalf("%s: look %+v %v, want the service's limit %+v", query, l, err, limit)
		}
		looks = append(looks, l.Cached)
		if body, err := r.Get(context.Background(), "svc", "a", query); err != nil || string(body) != reply {
			t.Fatalf("%s: %q %v", query, body, err)
		}
	}
	if log.count() != 1 || !slices.Equal(looks, []bool{false, true, true}) {
		t.Errorf("three lookups of one canonical query: %d upstream calls, cached %v, want 1 and only the first a miss", log.count(), looks)
	}
	c.at = c.at.Add(time.Minute)
	if l, _ := r.Look("svc", "a", "a=1&b=2"); l.Cached {
		t.Error("after the TTL the lookup still looks cached")
	}
	if _, err := r.Get(context.Background(), "svc", "a", "a=1&b=2"); err != nil {
		t.Fatal(err)
	}
	if log.count() != 2 {
		t.Errorf("after the TTL: %d upstream calls, want 2", log.count())
	}
}

func TestMETRepliesAreCachedUntilTheirExpires(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
	expires := c.at.Add(7 * time.Minute)
	up, log := serving(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lat") == "1" {
			w.Header().Set("Expires", expires.Format(http.TimeFormat))
		}
		answering(reply)(w, r)
	})
	met := Services(Keys{})["met"]
	r := relayTo(up, met, c)
	lookup := func(query string) {
		t.Helper()
		if _, err := r.Get(context.Background(), "svc", strings.TrimPrefix(met.Paths[0], "/"), query); err != nil {
			t.Fatal(err)
		}
	}
	lookup("lat=1")
	lookup("lat=2")
	c.at = expires.Add(-time.Second)
	lookup("lat=1")
	if log.count() != 2 {
		t.Fatalf("before Expires: %d upstream calls, want 2", log.count())
	}
	c.at = expires
	lookup("lat=1")
	if log.count() != 3 {
		t.Errorf("at Expires: %d upstream calls, want 3", log.count())
	}
	c.at = c.at.Add(30*time.Minute - 7*time.Minute - time.Second)
	lookup("lat=2")
	if log.count() != 3 {
		t.Errorf("a reply with no Expires was refetched before the 30 minute fallback")
	}
}

func TestConcurrentIdenticalMissesMakeOneCall(t *testing.T) {
	release := make(chan struct{})
	var arrived atomic.Int32
	up, log := serving(t, func(w http.ResponseWriter, r *http.Request) {
		arrived.Add(1)
		<-release
		answering(reply)(w, r)
	})
	r := relayTo(up, Service{Paths: []string{"/a"}}, &clock{at: time.Now()})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := r.Get(context.Background(), "svc", "a", "q=1")
			errs <- err
		})
	}
	for arrived.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if log.count() != 1 {
		t.Errorf("8 concurrent identical lookups: %d upstream calls, want 1", log.count())
	}
}

func TestUpstreamFailuresMapToTheContract(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", MaxReplyBytes) + `"}`
	for _, tc := range []struct {
		name   string
		handle http.HandlerFunc
		want   error
	}{
		{"429 with Retry-After", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "12")
			w.WriteHeader(http.StatusTooManyRequests)
		}, Busy{RetryAfter: 12 * time.Second}},
		{"429 without Retry-After", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }, Busy{RetryAfter: busyRetryAfter}},
		{"404", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, ErrNotFound},
		{"500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, ErrUnavailable},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		}, ErrUnavailable},
		{"html", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(reply))
		}, ErrUnavailable},
		{"json type, not json", answering("<html>"), ErrUnavailable},
		{"over the size cap", answering(big), ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, _ := serving(t, tc.handle)
			r := relayTo(up, Service{Paths: []string{"/a"}}, &clock{at: time.Now()})
			body, err := r.Get(context.Background(), "svc", "a", "")
			if !errors.Is(err, tc.want) || body != nil {
				t.Errorf("%T %v with %d bytes, want %v", err, err, len(body), tc.want)
			}
			if tc.want == ErrUnavailable && err.Error() == ErrUnavailable.Error() {
				t.Errorf("%v carries no cause for the log", err)
			}
		})
	}
}

func TestAMalformedQueryIsRefusedBeforeAnyCall(t *testing.T) {
	up, log := serving(t, answering(reply))
	r := relayTo(up, Service{Paths: []string{"/a"}}, &clock{at: time.Now()})
	for _, q := range []string{"a=%zz", "a=1;b=2", "a=" + strings.Repeat("x", maxQueryBytes)} {
		if _, err := r.Get(context.Background(), "svc", "a", q); !errors.Is(err, ErrBadQuery) {
			t.Errorf("%.20s: %v, want invalid_lookup_query", q, err)
		}
	}
	if log.count() != 0 {
		t.Errorf("malformed queries reached the upstream")
	}
}

func TestCoinGeckoUsesTheProEndpointAndHeaderOnlyWhenKeyed(t *testing.T) {
	keyless, keyed := Services(Keys{})["coingecko"], Services(Keys{CoinGecko: "cg-key"})["coingecko"]
	if keyless.Base != "https://api.coingecko.com" || keyless.AuthHeader != nil || keyless.Limit.RPM != 10 {
		t.Errorf("keyless: %s %v %d rpm", keyless.Base, keyless.AuthHeader, keyless.Limit.RPM)
	}
	if keyed.Base != "https://pro-api.coingecko.com" || keyed.Limit.RPM != 250 || keyed.Limit.Subject != keyless.Limit.Subject {
		t.Errorf("keyed: %s %d rpm %s", keyed.Base, keyed.Limit.RPM, keyed.Limit.Subject)
	}
	for _, tc := range []struct {
		s    Service
		want string
	}{{keyless, ""}, {keyed, "cg-key"}} {
		up, log := serving(t, answering(reply))
		r := relayTo(up, tc.s, &clock{at: time.Now()})
		if _, err := r.Get(context.Background(), "svc", "api/v3/simple/price", "ids=bitcoin"); err != nil {
			t.Fatal(err)
		}
		if got := log.last().Header.Get("x-cg-pro-api-key"); got != tc.want {
			t.Errorf("x-cg-pro-api-key %q, want %q", got, tc.want)
		}
	}
}

func TestAClientCannotAddOrOverrideTheServicesKeyInTheQuery(t *testing.T) {
	up, log := serving(t, answering(reply))
	r := relayTo(up, Services(Keys{OpenAlex: "oa-key"})["openalex"], &clock{at: time.Now()})
	for _, query := range []string{"search=x&api_key=client-key", "api_key=client-key&search=x&api_key=another"} {
		if _, err := r.Get(context.Background(), "svc", "works", query); err != nil {
			t.Fatal(err)
		}
		if got := log.last().URL.Query(); !slices.Equal(got["api_key"], []string{"oa-key"}) || got.Get("search") != "x" {
			t.Errorf("%s: upstream query %v, want only the service's api_key", query, got)
		}
	}
}

func TestTheOpenAlexKeyGoesUpstreamOnlyWhenSet(t *testing.T) {
	up, log := serving(t, answering(reply))
	c := &clock{at: time.Now()}
	r := relayTo(up, Services(Keys{OpenAlex: "oa-key"})["openalex"], c)
	for range 2 {
		if _, err := r.Get(context.Background(), "svc", "works", "search=x"); err != nil {
			t.Fatal(err)
		}
	}
	if got := log.last().URL.Query(); got.Get("api_key") != "oa-key" || got.Get("search") != "x" {
		t.Errorf("upstream query %v", got)
	}
	if log.count() != 1 {
		t.Errorf("%d upstream calls, want 1", log.count())
	}
	keyless, keylessLog := serving(t, answering(reply))
	kr := relayTo(keyless, Services(Keys{})["openalex"], c)
	if _, err := kr.Get(context.Background(), "svc", "works", "search=x"); err != nil {
		t.Fatal(err)
	}
	if got := keylessLog.last().URL.RawQuery; got != "search=x" {
		t.Errorf("keyless upstream query %q, want search=x", got)
	}
}

func TestTheCacheEvictsTheLeastRecentlyUsedPastEitherBound(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)
	c := newCache(2, 10)
	c.put("a", []byte("aaaa"), later)
	c.put("b", []byte("bbbb"), later)
	c.get("a", now)
	c.put("c", []byte("cc"), later)
	if _, ok := c.get("b", now); ok {
		t.Error("b, least recently used, survived a third entry")
	}
	c.put("d", []byte("dddddd"), later)
	if _, ok := c.get("a", now); ok {
		t.Error("a survived past the byte bound")
	}
	if _, ok := c.get("d", now); !ok {
		t.Error("the newest entry was evicted")
	}
	c.put("huge", make([]byte, 11), later)
	if _, ok := c.get("huge", now); ok || c.bytes > c.maxBytes {
		t.Errorf("an entry over the byte bound was cached: %d bytes", c.bytes)
	}
}
