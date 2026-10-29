package attested

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"morse/backend/internal/attestation"
	"morse/backend/internal/flight"
)

const (
	trustedFor = time.Hour
)

var (
	ErrReportRefused = errors.New("attested: the report was refused, so the scope is unpinned until one verifies")
	ErrNoEndpoint    = errors.New("attested: the report judged no endpoint")
	ErrLapsed        = errors.New("attested: every verified endpoint lapsed, so the scope is unpinned until one verifies")
	ErrDisowned      = errors.New("attested: the upstream disowned the endpoint's key, so it is unheld until a report lists it again")
)

type Key interface {
	comparable
	String() string
}

type Verifier[K Key] func(ctx context.Context, report []byte, nonce attestation.Nonce) (attestation.Verdicts[K], error)

type Fetch func(ctx context.Context, nonce attestation.Nonce) ([]byte, error)

type Config[K Key] struct {
	Scope    string
	Verifier Verifier[K]
	Fetch    Fetch
	Observe  func(Event)
	Now      func() time.Time
}

type Held[K Key] struct {
	Keys     []K
	NotAfter time.Time
	Served   bool
}

func (h Held[K]) Holds(k K, now time.Time) bool {
	return slices.Contains(h.Keys, k) && now.Before(h.NotAfter)
}

func (h Held[K]) Serves(now time.Time) bool {
	return h.Served && now.Before(h.NotAfter)
}

type Anchor[K Key] struct {
	Keys       map[K]time.Time
	Endpoints  map[string]Held[K]
	Report     json.RawMessage
	Generation uint64
}

func (a *Anchor[K]) lapsed(now time.Time) bool {
	for _, h := range a.Endpoints {
		if !now.Before(h.NotAfter) {
			return true
		}
	}
	return false
}

type Kind string

const (
	Anchored           Kind = "anchored"
	Verified           Kind = "verified"
	Refused            Kind = "refused"
	Unlisted           Kind = "unlisted"
	EndpointRefused    Kind = "endpoint_refused"
	Unpinned           Kind = "unpinned"
	RefreshFailed      Kind = "refresh_failed"
	GPUVerdictWithheld Kind = "gpu_verdict_withheld"
)

type Event struct {
	Kind       Kind
	Scope      string
	Generation uint64
	Endpoints  []attestation.Verified
	Drift      []attestation.Drift
	Keys       []string
	Key        string
	Endpoint   string
	Resumed    bool
	Err        error
}

type endpoint[K Key] struct {
	notAfter time.Time
	round    uint64
	keys     []K
}

type Gate[K Key] struct {
	scope    string
	verifier Verifier[K]
	fetch    Fetch
	changed  func(generation uint64)
	observer func(Event)

	now        func() time.Time
	after      func(time.Duration) <-chan time.Time
	nonce      func() (attestation.Nonce, error)
	minBackoff time.Duration
	maxBackoff time.Duration

	anchor atomic.Pointer[Anchor[K]]
	wake   chan struct{}
	flight flight.Group[struct{}]

	mu          sync.Mutex
	endpoints   map[string]endpoint[K]
	serve       attestation.Serve
	round       uint64
	generation  uint64
	verifying   bool
	lastAttempt time.Time
}

func newGate[K Key](c Config[K], changed func(generation uint64)) *Gate[K] {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	return &Gate[K]{
		scope:      c.Scope,
		verifier:   c.Verifier,
		fetch:      c.Fetch,
		changed:    changed,
		observer:   c.Observe,
		now:        now,
		after:      time.After,
		nonce:      attestation.NewNonce,
		minBackoff: minBackoff,
		maxBackoff: maxBackoff,
		endpoints:  map[string]endpoint[K]{},
		wake:       make(chan struct{}, 1),
	}
}

// Anchor is the latest snapshot with every lapsed endpoint pruned.
func (g *Gate[K]) Anchor() *Anchor[K] {
	a := g.anchor.Load()
	if a != nil && a.lapsed(g.now()) {
		g.reanchor()
		a = g.anchor.Load()
	}
	return a
}

func (g *Gate[K]) Ready() bool {
	a := g.anchor.Load()
	if a == nil {
		return false
	}
	now := g.now()
	for _, notAfter := range a.Keys {
		if now.Before(notAfter) {
			return true
		}
	}
	return false
}

func (g *Gate[K]) Holds(k K) bool {
	a := g.anchor.Load()
	if a == nil {
		return false
	}
	notAfter, ok := a.Keys[k]
	return ok && g.now().Before(notAfter)
}

func refusedReport(refusal error) error {
	return fmt.Errorf("%w: %w", ErrReportRefused, refusal)
}

func (g *Gate[K]) verifyOnce(ctx context.Context) error {
	nonce, err := g.nonce()
	if err != nil {
		return err
	}
	report, err := g.fetch(ctx, nonce)
	if err != nil {
		return err
	}
	verdicts, err := g.verifier(ctx, report, nonce)
	switch {
	case attestation.Unjudged(err):
		return err
	case err != nil:
		return g.unpin(refusedReport(err))
	}
	var judged []attestation.Refusal
	for _, r := range verdicts.Refused {
		if !attestation.Unjudged(r.Err) {
			judged = append(judged, r)
			g.observe(Event{Kind: EndpointRefused, Endpoint: r.EndpointID, Err: r.Err})
		}
	}
	if len(verdicts.Endpoints) > 0 {
		g.admit(verdicts, judged)
		return nil
	}
	switch {
	case len(judged) > 0:
		anchor, changed := g.rebuild(func() { g.forgetLocked(judged) })
		return g.refuse(anchor, changed, refusedReport(judged[len(judged)-1].Err))
	case len(verdicts.Refused) > 0:
		return verdicts.Refused[0].Err
	}
	return ErrNoEndpoint
}

func (g *Gate[K]) admit(verdicts attestation.Verdicts[K], judged []attestation.Refusal) {
	ev := Event{Kind: Verified}
	anchor, changed := g.rebuild(func() {
		now := g.now()
		g.round++
		g.forgetLocked(judged)
		for _, e := range verdicts.Endpoints {
			notAfter := e.NotAfter
			if cap := now.Add(trustedFor); cap.Before(notAfter) {
				notAfter = cap
			}
			g.endpoints[e.ID] = endpoint[K]{notAfter: notAfter, round: g.round, keys: e.Keys}
			ev.Endpoints = append(ev.Endpoints, e.Verified)
			ev.Drift = append(ev.Drift, e.Drift...)
		}
		g.serve = verdicts.Serve
	})
	if changed {
		ev.Kind = Anchored
	}
	g.announce(ev, anchor)
}

func (g *Gate[K]) forgetLocked(judged []attestation.Refusal) {
	for _, r := range judged {
		delete(g.endpoints, r.EndpointID)
	}
}

func (g *Gate[K]) pruneLocked(now time.Time) {
	maps.DeleteFunc(g.endpoints, func(_ string, ep endpoint[K]) bool { return !now.Before(ep.notAfter) })
}

func (g *Gate[K]) reanchor() { g.prune(func() {}, ErrLapsed) }

func (g *Gate[K]) Forget(endpointID string) {
	g.observe(Event{Kind: EndpointRefused, Endpoint: endpointID, Err: ErrDisowned})
	g.prune(func() { delete(g.endpoints, endpointID) }, ErrDisowned)
	g.Wake()
}

func (g *Gate[K]) prune(mutate func(), unpinned error) {
	anchor, changed := g.rebuild(mutate)
	switch {
	case !changed:
	case len(anchor.Keys) == 0:
		g.announce(Event{Kind: Unpinned, Err: unpinned}, anchor)
	default:
		g.announce(Event{Kind: Anchored}, anchor)
	}
}

func (g *Gate[K]) announce(ev Event, anchor *Anchor[K]) {
	ev.Generation = anchor.Generation
	ev.Keys = make([]string, 0, len(anchor.Keys))
	for k := range anchor.Keys {
		ev.Keys = append(ev.Keys, k.String())
	}
	slices.Sort(ev.Keys)
	g.observe(ev)
}

func (g *Gate[K]) unpin(err error) error {
	anchor, changed := g.rebuild(func() { clear(g.endpoints) })
	return g.refuse(anchor, changed, err)
}

func (g *Gate[K]) refuse(anchor *Anchor[K], changed bool, err error) error {
	if changed && len(anchor.Keys) > 0 {
		g.announce(Event{Kind: Anchored}, anchor)
	}
	return err
}

func (g *Gate[K]) failed(err error) {
	ev := Event{Kind: RefreshFailed, Err: err}
	if a := g.anchor.Load(); a != nil {
		ev.Generation = a.Generation
	}
	if !g.Ready() {
		ev.Kind = Unpinned
	}
	g.observe(ev)
}

func (g *Gate[K]) rebuild(mutate func()) (*Anchor[K], bool) {
	g.mu.Lock()
	mutate()
	g.pruneLocked(g.now())
	keys := map[K]time.Time{}
	endpoints := map[string]Held[K]{}
	anyServed := false
	for id, ep := range g.endpoints {
		h := Held[K]{Keys: ep.keys, NotAfter: ep.notAfter, Served: g.serve != nil && ep.round == g.round}
		endpoints[id] = h
		anyServed = anyServed || h.Served
		for _, k := range ep.keys {
			if ep.notAfter.After(keys[k]) {
				keys[k] = ep.notAfter
			}
		}
	}
	var prevKeys map[K]time.Time
	if prev := g.anchor.Load(); prev != nil {
		prevKeys = prev.Keys
	}
	changed := !maps.EqualFunc(prevKeys, keys, func(time.Time, time.Time) bool { return true })
	if changed {
		g.generation++
	}
	anchor := &Anchor[K]{Keys: keys, Endpoints: endpoints, Generation: g.generation}
	if anyServed {
		anchor.Report = g.serve(func(id string) bool { return endpoints[id].Served })
	}
	g.anchor.Store(anchor)
	g.mu.Unlock()
	if changed {
		g.changed(anchor.Generation)
	}
	return anchor, changed
}

func (g *Gate[K]) observe(ev Event) {
	if g.observer != nil {
		ev.Scope = g.scope
		g.observer(ev)
	}
}
