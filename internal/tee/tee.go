package tee

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/attestation"
	"morse/backend/internal/attested"
	"morse/backend/internal/attester"
	"morse/backend/internal/audio"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/near"
	"morse/backend/internal/phala"
	"morse/backend/internal/tinfoil"
)

type Plain interface {
	chat.Attester
	chat.Provider
}

// Transcriber transcribes in the clear over the gate's attested TLS, and attests the model it reaches.
type Transcriber interface {
	chat.Attester
	audio.Transcriber
}

type Gate interface {
	Run(context.Context)
	Route(attester.Upstream) chat.VerbatimRoute
	Plain(attester.Upstream) (Plain, bool) // false for a vendor that serves only sealed chats
}

// Transcribing is a gate whose attester Transcribes.
type Transcribing interface {
	Gate
	Transcriber(attester.Upstream) Transcriber
}

type Deps struct {
	Base     *http.Transport
	Unpinned *http.Client
	Policy   attestation.Policy
	Observe  func(attested.Event)
}

// A Vendor builds the gates of one attester, and states what the routes behind them do: the scheme a verbatim
// route relays under, whether its replies have receipts, and whether it lists the attested sessions they cite.
type Vendor interface {
	Scope(attester.Upstream) Scope
	Share(first, next attester.Upstream) error
	NewGate(attester.Upstream, Deps) Gate
	Speaks() *chat.Scheme
	Receipts() bool
	Sessions() bool
}

func Of(v *attester.Vendor) Vendor {
	switch v {
	case attester.Phala:
		return phalaVendor{vendor{v}}
	case attester.Near:
		return nearVendor{vendor{v}}
	case attester.Tinfoil:
		return tinfoilVendor{vendor{v}}
	}
	panic(fmt.Sprintf("tee: attester %s has no vendor", v))
}

type Scope struct {
	Vendor *attester.Vendor
	Host   string
	Model  string
}

func (s Scope) String() string {
	parts := []string{s.Vendor.Name, s.Host}
	if s.Model != "" {
		parts = append(parts, s.Model)
	}
	return strings.Join(parts, "/")
}

type vendor struct{ *attester.Vendor }

func (v vendor) Scope(up attester.Upstream) Scope {
	return Scope{Vendor: v.Vendor, Host: up.Host}
}

func (v vendor) Share(first, next attester.Upstream) error {
	if first.APIKey != next.APIKey {
		return fmt.Errorf("share attestation gate %s but name different api keys; a gate attests with one key", v.Scope(next))
	}
	return nil
}

type phalaVendor struct{ vendor }

func (v phalaVendor) NewGate(up attester.Upstream, d Deps) Gate {
	gateway := phala.NewGateway(up.BaseURL, up.APIKey, d.Unpinned)
	keys := &e2eeKeys{now: time.Now}
	return phalaGate{TLSGate: attested.NewTLSGate(attested.Config[aci.SPKI]{
		Scope:    v.Scope(up).String(),
		Verifier: phalaVerifier(d.Policy, up.Host, keys),
		Fetch: func(ctx context.Context, nonce attestation.Nonce) ([]byte, error) {
			return gateway.Report(ctx, nonce.String())
		},
		Observe: d.Observe,
		Now:     keys.now,
	}, up.Host, d.Base), keys: keys}
}

func phalaVerifier(policy attestation.Policy, host string, keys *e2eeKeys) attested.Verifier[aci.SPKI] {
	return func(ctx context.Context, report []byte, nonce attestation.Nonce) (attestation.Verdicts[aci.SPKI], error) {
		r, err := policy.VerifyPhala(ctx, report, nonce, host)
		if err != nil {
			return attestation.Verdicts[aci.SPKI]{}, err
		}
		keys.keep(r)
		return attestation.PhalaPins().Judge(r)
	}
}

func (phalaVendor) Speaks() *chat.Scheme { return (*phala.Route)(nil).Speaks() }

func (phalaVendor) Receipts() bool { return true }

func (phalaVendor) Sessions() bool { return true }

type phalaGate struct {
	*attested.TLSGate
	keys *e2eeKeys
}

type e2eeKeys struct {
	now        func() time.Time
	mu         sync.Mutex
	byEndpoint map[string]keyset
}

type keyset struct {
	notAfter time.Time
	aci.Keyset
}

func (k *e2eeKeys) keep(r attestation.PhalaReport) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	maps.DeleteFunc(k.byEndpoint, func(_ string, ks keyset) bool { return !now.Before(ks.notAfter) })
	if k.byEndpoint == nil {
		k.byEndpoint = map[string]keyset{}
	}
	k.byEndpoint[r.Endpoint.ID] = keyset{notAfter: r.Endpoint.NotAfter, Keyset: r.Keyset}
}

func (g phalaGate) Holds(key []byte) bool {
	_, held := g.firstHeld(func(k aci.Key) bool { return bytes.Equal(k.Public, key) })
	return held
}

func (g phalaGate) HeldX25519() (*ecdh.PublicKey, bool) {
	held, ok := g.firstHeld(func(k aci.Key) bool { return k.Algo == e2ee.X25519.Algo() })
	if !ok {
		return nil, false
	}
	key, err := ecdh.X25519().NewPublicKey(held.Public)
	return key, err == nil
}

func (g phalaGate) firstHeld(match func(aci.Key) bool) (aci.Key, bool) {
	for ks := range g.verified() {
		if i := slices.IndexFunc(ks.E2EEKeys, match); i >= 0 {
			return ks.E2EEKeys[i], true
		}
	}
	return aci.Key{}, false
}

func (g phalaGate) Keyset(digest aci.Hash) (aci.Keyset, bool) {
	for ks := range g.verified() {
		if ks.Digest == digest {
			return ks, true
		}
	}
	return aci.Keyset{}, false
}

func (g phalaGate) verified() iter.Seq[aci.Keyset] {
	return func(yield func(aci.Keyset) bool) {
		a := g.Anchor()
		if a == nil {
			return
		}
		g.keys.mu.Lock()
		defer g.keys.mu.Unlock()
		now := g.keys.now()
		for _, id := range slices.Sorted(maps.Keys(a.Endpoints)) {
			ks := g.keys.byEndpoint[id]
			if now.Before(ks.notAfter) && !yield(ks.Keyset) {
				return
			}
		}
	}
}

func (g phalaGate) Route(up attester.Upstream) chat.VerbatimRoute { return g.route(up) }

func (g phalaGate) Plain(up attester.Upstream) (Plain, bool) { return g.route(up), true }

func (g phalaGate) route(up attester.Upstream) *phala.Route {
	return phala.New(up.BaseURL, up.Model, up.APIKey, phala.Clients{Plaintext: g.Client(), Sealed: g.Unbound()}, g)
}

type nearVendor struct{ vendor }

func (v nearVendor) Scope(up attester.Upstream) Scope {
	s := v.vendor.Scope(up)
	s.Model = up.Model
	return s
}

func (v nearVendor) NewGate(up attester.Upstream, d Deps) Gate {
	gateway := near.NewGateway(up.BaseURL, up.APIKey, d.Unpinned)
	scope := v.Scope(up).String()
	return nearGate{TLSGate: attested.NewTLSGate(attested.Config[aci.SPKI]{
		Scope:    scope,
		Verifier: nearVerifier(d.Policy, up.Model),
		Fetch: func(ctx context.Context, nonce attestation.Nonce) ([]byte, error) {
			return gateway.Report(ctx, up.Model, nonce.String())
		},
		Observe: d.Observe,
	}, up.Host, d.Base), scope: scope, policy: d.Policy, observe: d.Observe}
}

func (nearVendor) Speaks() *chat.Scheme { return (*near.Route)(nil).Speaks() }

func (nearVendor) Receipts() bool { return true }

func (nearVendor) Sessions() bool { return false }

func nearVerifier(policy attestation.Policy, model string) attested.Verifier[aci.SPKI] {
	return func(ctx context.Context, report []byte, nonce attestation.Nonce) (attestation.Verdicts[aci.SPKI], error) {
		r, err := policy.VerifyNear(ctx, report, nonce, model)
		if err != nil {
			return attestation.Verdicts[aci.SPKI]{}, err
		}
		return attestation.NearPins().Judge(r), nil
	}
}

type nearGate struct {
	*attested.TLSGate
	scope   string
	policy  attestation.Policy
	observe func(attested.Event)
}

func (g nearGate) Route(up attester.Upstream) chat.VerbatimRoute {
	return near.New(up.BaseURL, up.Model, up.APIKey, g.Client(), g, g.gpuVerdicts)
}

func (nearGate) Plain(attester.Upstream) (Plain, bool) { return nil, false }

func (g nearGate) Transcriber(up attester.Upstream) Transcriber {
	return near.NewTranscriber(up.BaseURL, up.Model, up.APIKey, g.Client(), g, g.gpuVerdicts)
}

func (g nearGate) gpuVerdicts(ctx context.Context, report []byte, nonce attestation.Nonce) map[string]attestation.GPUVerdict {
	verdicts, refused := g.policy.NearGPUVerdicts(ctx, report, nonce)
	if g.observe != nil {
		for _, r := range refused {
			g.observe(attested.Event{Kind: attested.GPUVerdictWithheld, Scope: g.scope, Endpoint: r.EndpointID, Err: r.Err})
		}
	}
	return verdicts
}

func (g nearGate) Forget(k near.SigningKey) { g.TLSGate.Forget(k.String()) }

func (g nearGate) Held() (near.SigningKey, bool) {
	a := g.Anchor()
	if a == nil || len(a.Endpoints) == 0 {
		return near.SigningKey{}, false
	}
	raw, err := hex.DecodeString(slices.Min(slices.Collect(maps.Keys(a.Endpoints))))
	if err != nil || len(raw) != len(near.SigningKey{}) {
		return near.SigningKey{}, false
	}
	return near.SigningKey(raw), true
}

func (g nearGate) Holds(k near.SigningKey) bool {
	a := g.Anchor()
	if a == nil {
		return false
	}
	_, ok := a.Endpoints[k.String()]
	return ok
}

// tinfoilVendor's gate verifies one router host's bundle, which binds no nonce, and pins the route's client
// to the TLS key its report binds. The router signs no receipts.
type tinfoilVendor struct{ vendor }

func (v tinfoilVendor) NewGate(up attester.Upstream, d Deps) Gate {
	gateway := tinfoil.NewGateway(up.BaseURL, up.Host, d.Unpinned)
	return tinfoilGate{TLSGate: attested.NewTLSGate(attested.Config[aci.SPKI]{
		Scope:    v.Scope(up).String(),
		Verifier: tinfoilVerifier(d.Policy, up.Host),
		Fetch: func(ctx context.Context, _ attestation.Nonce) ([]byte, error) {
			return gateway.Bundle(ctx)
		},
		Observe: d.Observe,
	}, up.Host, d.Base)}
}

// tinfoilVerifier serves the bundle it verified, so a client checks the report whose keys the gate pinned.
func tinfoilVerifier(policy attestation.Policy, host string) attested.Verifier[aci.SPKI] {
	return func(ctx context.Context, bundle []byte, _ attestation.Nonce) (attestation.Verdicts[aci.SPKI], error) {
		r, err := policy.VerifyTinfoil(ctx, bundle, host)
		if err != nil {
			return attestation.Verdicts[aci.SPKI]{}, err
		}
		v, err := attestation.TinfoilPins().Judge(r)
		if err != nil {
			return attestation.Verdicts[aci.SPKI]{}, err
		}
		v.Serve = func(func(string) bool) json.RawMessage { return bundle }
		return v, nil
	}
}

func (tinfoilVendor) Speaks() *chat.Scheme { return ehbp.Scheme }

func (tinfoilVendor) Receipts() bool { return false }

func (tinfoilVendor) Sessions() bool { return false }

type tinfoilGate struct {
	*attested.TLSGate
}

func (g tinfoilGate) Route(up attester.Upstream) chat.VerbatimRoute {
	return tinfoil.New(up.BaseURL, up.Host, up.Model, up.APIKey, g.Client(), g)
}

func (tinfoilGate) Plain(attester.Upstream) (Plain, bool) { return nil, false }

func (g tinfoilGate) Report() json.RawMessage {
	if a := g.Anchor(); a != nil {
		return a.Report
	}
	return nil
}
