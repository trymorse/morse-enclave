package vendors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"morse/backend/internal/attestation"
	"morse/backend/internal/attested"
	"morse/backend/internal/attester"
	"morse/backend/internal/tee"
)

type Gates struct {
	deps     tee.Deps
	gates    map[tee.Scope]gateEntry
	unpinned *attested.UnpinnedReleases
}

type gateEntry struct {
	gate  tee.Gate
	route string
	up    attester.Upstream
}

func NewGates(base *http.Transport, unpinned *http.Client, policy attestation.Policy, observe func(attested.Event)) *Gates {
	return &Gates{deps: tee.Deps{Base: base, Unpinned: unpinned, Policy: policy, Observe: observe}, gates: map[tee.Scope]gateEntry{}, unpinned: attested.NewUnpinnedReleases(time.Now)}
}

func Pinned(set attestation.VendorSet) func(vendor, field, release string) bool {
	return func(vendor, field, release string) bool {
		switch vendor {
		case attester.Phala.Name:
			return set.Phala.Lists(field, release)
		case attester.Near.Name:
			return set.Near.Lists(field, release)
		case attester.Tinfoil.Name:
			return set.Tinfoil.Lists(field, release)
		}
		return false
	}
}

func (gs *Gates) Unpinned() []attested.UnpinnedRelease {
	if gs == nil {
		return nil
	}
	seen := gs.unpinned.Seen()
	listed := Pinned(attestation.Vendors())
	for i, r := range seen {
		seen[i].Listed = listed(r.Vendor, r.Field, r.Release)
	}
	return seen
}

func (gs *Gates) observedBy(by *attester.Vendor) tee.Deps {
	deps := gs.deps
	deps.Observe = func(ev attested.Event) {
		gs.unpinned.Observe(by.Name, ev)
		gs.deps.Observe(ev)
	}
	return deps
}

func (gs *Gates) gate(route string, by *attester.Vendor, up attester.Upstream) (tee.Gate, error) {
	v := tee.Of(by)
	scope := v.Scope(up)
	first, ok := gs.gates[scope]
	if !ok {
		first = gateEntry{gate: v.NewGate(up, gs.observedBy(by)), route: route, up: up}
		gs.gates[scope] = first
	}
	if err := v.Share(first.up, up); err != nil {
		return nil, fmt.Errorf("routes %q and %q %w", first.route, route, err)
	}
	return first.gate, nil
}

// A relay builds no gates, so a nil set runs and lists nothing.
func (gs *Gates) Run(ctx context.Context) {
	if gs == nil {
		return
	}
	for _, g := range gs.gates {
		go g.gate.Run(ctx)
	}
}

func (gs *Gates) Scopes() []tee.Scope {
	if gs == nil {
		return nil
	}
	scopes := make([]tee.Scope, 0, len(gs.gates))
	for scope := range gs.gates {
		scopes = append(scopes, scope)
	}
	return scopes
}

// Wake has every gate verify again soon: the vendor pins changed, so an endpoint refused on an anchor may now pass.
func (gs *Gates) Wake() {
	if gs == nil {
		return
	}
	for _, g := range gs.gates {
		g.gate.Wake()
	}
}
