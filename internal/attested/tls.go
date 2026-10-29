package attested

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/apierr"
)

const (
	handshakeTimeout = 25 * time.Second
)

type TLSGate struct {
	*Gate[aci.SPKI]
	host    string
	bound   *pinned
	unbound *pinned
}

type pinned struct {
	g      *TLSGate
	base   *http.Transport
	client *http.Client

	mu   sync.Mutex
	pool pool
}

type pool struct {
	generation uint64
	transport  *http.Transport
}

func NewTLSGate(c Config[aci.SPKI], host string, base *http.Transport) *TLSGate {
	g := &TLSGate{host: host}
	g.Gate = newGate(c, func(generation uint64) {
		g.bound.transportFor(generation)
		g.unbound.transportFor(generation)
	})
	g.bound = g.pin(base, g.verifyConnection)
	g.unbound = g.pin(base, g.noteConnection)
	return g
}

func (g *TLSGate) pin(base *http.Transport, verify func(tls.ConnectionState) error) *pinned {
	p := &pinned{g: g, base: base.Clone()}
	if p.base.TLSClientConfig == nil {
		p.base.TLSClientConfig = &tls.Config{}
	}
	p.base.TLSClientConfig.VerifyConnection = verify
	p.base.TLSHandshakeTimeout = handshakeTimeout
	p.pool = pool{transport: p.base.Clone()}
	p.client = &http.Client{Transport: p}
	return p
}

func (g *TLSGate) Client() *http.Client { return g.bound.client }

// Unbound is for bodies the far end seals to a quote-bound key or signs with one: a key no verified keyset lists is reported and the handshake goes on.
func (g *TLSGate) Unbound() *http.Client { return g.unbound.client }

func (p *pinned) RoundTrip(req *http.Request) (*http.Response, error) {
	if host := req.URL.Hostname(); host != p.g.host {
		return nil, fmt.Errorf("attested: client is pinned to %s and cannot reach %s", p.g.host, host)
	}
	if !p.g.Ready() {
		return nil, apierr.ErrUnattested
	}
	return p.transportFor(p.g.Anchor().Generation).RoundTrip(req)
}

func (p *pinned) transportFor(generation uint64) *http.Transport {
	p.mu.Lock()
	prev := p.pool
	if generation > prev.generation {
		p.pool = pool{generation: generation, transport: p.base.Clone()}
	}
	current := p.pool.transport
	p.mu.Unlock()
	if current != prev.transport {
		prev.transport.CloseIdleConnections()
	}
	return current
}

func (g *TLSGate) verifyConnection(cs tls.ConnectionState) error {
	spki, listed, err := g.lists(cs)
	if err != nil || listed {
		return err
	}
	g.observe(Event{Kind: Refused, Key: spki.String(), Resumed: cs.DidResume})
	return fmt.Errorf("%w: %s presented spki %s, which no verified keyset lists for it", apierr.ErrUnattested, g.host, spki)
}

func (g *TLSGate) noteConnection(cs tls.ConnectionState) error {
	spki, listed, err := g.lists(cs)
	if err != nil || listed {
		return err
	}
	if !g.Ready() {
		return fmt.Errorf("%w: %s holds no verified keyset after the reverify for spki %s", apierr.ErrUnattested, g.host, spki)
	}
	g.observe(Event{Kind: Unlisted, Key: spki.String(), Resumed: cs.DidResume})
	return nil
}

func (g *TLSGate) lists(cs tls.ConnectionState) (aci.SPKI, bool, error) {
	if len(cs.PeerCertificates) == 0 {
		return aci.SPKI{}, false, fmt.Errorf("%w: %s presented no certificate", apierr.ErrUnattested, g.host)
	}
	spki := aci.SPKI(sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo))
	if g.Holds(spki) {
		return spki, true, nil
	}
	g.Reverify(context.Background())
	return spki, g.Holds(spki), nil
}
