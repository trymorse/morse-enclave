package vendors

import (
	"context"
	"fmt"
	"net/http"

	"morse/backend/internal/attestation"
	"morse/backend/internal/attested"
	"morse/backend/internal/attester"
	"morse/backend/internal/tee"
)

type Gates struct {
	deps  tee.Deps
	gates map[tee.Scope]gateEntry
}

type gateEntry struct {
	gate  tee.Gate
	route string
	up    attester.Upstream
}

func NewGates(base *http.Transport, unpinned *http.Client, policy attestation.Policy, observe func(attested.Event)) *Gates {
	return &Gates{deps: tee.Deps{Base: base, Unpinned: unpinned, Policy: policy, Observe: observe}, gates: map[tee.Scope]gateEntry{}}
}

func (gs *Gates) gate(route string, by *attester.Vendor, up attester.Upstream) (tee.Gate, error) {
	v := tee.Of(by)
	scope := v.Scope(up)
	first, ok := gs.gates[scope]
	if !ok {
		first = gateEntry{gate: v.NewGate(up, gs.deps), route: route, up: up}
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
