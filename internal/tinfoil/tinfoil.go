package tinfoil

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"morse/backend/internal/attestation"
	"morse/backend/internal/capped"
	"morse/backend/internal/upstream"
)

const (
	attestationPath = "/.well-known/tinfoil-attestation"
	certificatePath = "/.well-known/tinfoil-certificate"
	maxWellKnown    = 256 << 10
	maxVCEK         = 16 << 10
	maxVCEKs        = 64
)

// Gateway fetches one router host's attestation bundle: its report and certificate from the
// host's well-known endpoints, and the VCEK AMD issued for the report's chip and TCB from AMD's key
// distribution service, which rate-limits callers, so each VCEK is fetched once.
type Gateway struct {
	host   string
	router upstream.Endpoint
	kds    *http.Client
	vceks  *vcekCache
}

func NewGateway(baseURL, host string, client *http.Client) Gateway {
	return Gateway{host: host, router: upstream.Objects(baseURL, "", client), kds: client, vceks: &vcekCache{byURL: map[string][]byte{}}}
}

func (g Gateway) Bundle(ctx context.Context) ([]byte, error) {
	var att struct{ Format, Body string }
	if err := g.object(ctx, attestationPath, &att); err != nil {
		return nil, err
	}
	var cert struct{ Certificate string }
	if err := g.object(ctx, certificatePath, &cert); err != nil {
		return nil, err
	}
	vcek, err := g.vcek(ctx, att.Body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(attestation.TinfoilBundle{Host: g.host, Format: att.Format, Body: att.Body, VCEK: base64.StdEncoding.EncodeToString(vcek), Certificate: cert.Certificate})
}

func (g Gateway) object(ctx context.Context, path string, into any) error {
	return object(ctx, g.router, path, into)
}

func nonced(ctx context.Context, router upstream.Endpoint, host, nonce string) ([]byte, error) {
	var d attestation.TinfoilNonced
	if err := object(ctx, router, attestationPath+"?nonce="+nonce, &d); err != nil {
		return nil, err
	}
	if d.Format != attestation.TinfoilNoncedFormat || d.Challenge.Nonce != nonce {
		return nil, fmt.Errorf("%w: the router answered format %q for nonce %q", attestation.ErrTinfoilNonced, d.Format, d.Challenge.Nonce)
	}
	d.Host = host
	d.Collateral = slices.DeleteFunc(d.Collateral, func(c attestation.TinfoilCollateral) bool { return !c.AMDCollateral() })
	if _, err := d.VCEK(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

func object(ctx context.Context, router upstream.Endpoint, path string, into any) error {
	raw, err := router.Object(ctx, path, maxWellKnown)
	if err != nil {
		return fmt.Errorf("tinfoil: %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("tinfoil: %s: %w", path, err)
	}
	return nil
}

func (g Gateway) vcek(ctx context.Context, body string) ([]byte, error) {
	url, err := attestation.VCEKURL(body)
	if err != nil {
		return nil, err
	}
	if der, ok := g.vceks.get(url); ok {
		return der, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := upstream.Do(g.kds, req)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: AMD KDS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tinfoil: AMD KDS answered %d for the router's VCEK", resp.StatusCode)
	}
	der, err := capped.ReadAll(resp.Body, maxVCEK)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: AMD KDS: %w", err)
	}
	g.vceks.put(url, der)
	return der, nil
}

type vcekCache struct {
	mu    sync.Mutex
	byURL map[string][]byte
}

func (c *vcekCache) get(url string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	der, ok := c.byURL[url]
	return der, ok
}

// put keeps at most maxVCEKs: a router's chip and TCB change rarely, so a full cache starts over.
func (c *vcekCache) put(url string, der []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byURL) >= maxVCEKs {
		clear(c.byURL)
	}
	c.byURL[url] = der
}
