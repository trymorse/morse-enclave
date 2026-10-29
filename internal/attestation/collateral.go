package attestation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"morse/backend/internal/flight"
	"morse/backend/internal/upstream"
	"net/http"
	"time"
)

const (
	collateralMaxAge    = 24 * time.Hour
	collateralTimeout   = 30 * time.Second
	maxCollateralLen    = 4 << 20
	maxCollateralCached = 64
)

type Collateral interface {
	Get(url string) (header map[string][]string, body []byte, err error)
}

type CollateralSource interface {
	For(ctx context.Context) Collateral
}

type cachedCollateral struct {
	header map[string][]string
	body   []byte
}

type CollateralCache struct {
	docs   flight.Keyed[cachedCollateral]
	source func(ctx context.Context) Collateral
	now    func() time.Time
}

func NewCollateralCache() *CollateralCache {
	c := &CollateralCache{
		source: func(ctx context.Context) Collateral { return intelPCS{ctx} },
		now:    time.Now,
	}
	c.docs = flight.Keyed[cachedCollateral]{Fetch: c.fetch, Max: maxCollateralCached, Timeout: collateralTimeout}
	return c
}

func (c *CollateralCache) For(ctx context.Context) Collateral { return boundCache{c, ctx} }

type boundCache struct {
	cache *CollateralCache
	ctx   context.Context
}

func (b boundCache) Get(url string) (map[string][]string, []byte, error) {
	doc, err := b.cache.docs.Get(b.ctx, url, b.cache.now())
	if err != nil {
		return nil, nil, err
	}
	return doc.header, doc.body, nil
}

func (c *CollateralCache) fetch(ctx context.Context, url string, now time.Time) (cachedCollateral, time.Time, error) {
	header, body, err := c.source(ctx).Get(url)
	if err != nil {
		return cachedCollateral{}, time.Time{}, err
	}
	expires, err := usable(url, body, now)
	if err != nil {
		return cachedCollateral{}, time.Time{}, err
	}
	if limit := now.Add(collateralMaxAge); limit.Before(expires) {
		expires = limit
	}
	return cachedCollateral{header: header, body: body}, expires, nil
}

func usable(url string, body []byte, now time.Time) (time.Time, error) {
	next, ok := nextUpdate(body)
	if !ok {
		return time.Time{}, fmt.Errorf("collateral %s carries no nextUpdate, so it is not a TCB info, enclave identity, or CRL", url)
	}
	if !next.After(now) {
		return time.Time{}, fmt.Errorf("collateral %s is past its nextUpdate %s", url, next.UTC().Format(time.RFC3339))
	}
	return next, nil
}

func nextUpdate(body []byte) (time.Time, bool) {
	var signed struct {
		TCBInfo struct {
			NextUpdate time.Time `json:"nextUpdate"`
		} `json:"tcbInfo"`
		EnclaveIdentity struct {
			NextUpdate time.Time `json:"nextUpdate"`
		} `json:"enclaveIdentity"`
	}
	if json.Unmarshal(body, &signed) == nil {
		for _, next := range []time.Time{signed.TCBInfo.NextUpdate, signed.EnclaveIdentity.NextUpdate} {
			if !next.IsZero() {
				return next, true
			}
		}
	}
	if crl, err := x509.ParseRevocationList(body); err == nil && !crl.NextUpdate.IsZero() {
		return crl.NextUpdate, true
	}
	return time.Time{}, false
}

var intelPCSEndpoint = upstream.Endpoint{HTTP: &http.Client{Timeout: collateralTimeout}}

// Intel serves CRLs as DER, so the fetch accepts any type instead of Endpoint's default JSON.
var acceptAny = http.Header{"Accept": {"*/*"}}

type intelPCS struct{ ctx context.Context }

func (g intelPCS) Get(url string) (map[string][]string, []byte, error) {
	reply, err := intelPCSEndpoint.Call(g.ctx, upstream.Request{Method: http.MethodGet, Path: url, Header: acceptAny}, maxCollateralLen)
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("collateral %s: %w", url, err)
	case reply.Status != http.StatusOK:
		return nil, nil, fmt.Errorf("collateral %s answered %d", url, reply.Status)
	}
	return reply.Header, reply.Body, nil
}
