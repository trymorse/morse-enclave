package tinfoil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"morse/backend/internal/attestation"
	"morse/backend/internal/upstream"
)

const (
	// why: Tinfoil's unversioned endpoint answers its legacy v2 document to a request without a nonce;
	// /v3 only ever answers v3 (tinfoilsh/cvmimage tinfoil/cmd/shim/api.go).
	attestationPath = "/.well-known/tinfoil-attestation/v3"
	maxWellKnown    = 256 << 10
	// why: Tinfoil's shim names the format it served in this reply header (tinfoilsh/cvmimage api.go).
	formatHeader = "Tinfoil-Pt"
)

func wellKnown(baseURL string, client *http.Client) upstream.Endpoint {
	e := upstream.Objects(baseURL, "", client)
	e.Confirm = func(get func(string) string) error {
		if served := get(formatHeader); served != "" && !strings.EqualFold(served, attestation.TinfoilNoncedFormat) {
			return fmt.Errorf("%w: %s names format %q", attestation.ErrUnreadable, formatHeader, served)
		}
		return nil
	}
	return e
}

type Gateway struct {
	host   string
	router upstream.Endpoint
}

func NewGateway(baseURL, host string, client *http.Client) Gateway {
	return Gateway{host: host, router: wellKnown(baseURL, client)}
}

// Nonced fetches the host's v3 document for nonce, keeping the collateral Morse reads: AMD's and the
// release's Sigstore bundle.
func (g Gateway) Nonced(ctx context.Context, nonce string) ([]byte, error) {
	return nonced(ctx, g.router, g.host, nonce, attestation.TinfoilCollateral.Relayed)
}

// nonced fetches the router's v3 document for nonce and keeps the collateral keep admits.
func nonced(ctx context.Context, router upstream.Endpoint, host, nonce string, keep func(attestation.TinfoilCollateral) bool) ([]byte, error) {
	var d attestation.TinfoilNonced
	if err := object(ctx, router, attestationPath+"?nonce="+nonce, &d); err != nil {
		return nil, err
	}
	if d.Format != attestation.TinfoilNoncedFormat || d.Challenge.Nonce != nonce {
		return nil, fmt.Errorf("%w: the router answered format %q for nonce %q", attestation.ErrTinfoilNonced, d.Format, d.Challenge.Nonce)
	}
	d.Host = host
	d.Collateral = slices.DeleteFunc(d.Collateral, func(c attestation.TinfoilCollateral) bool { return !keep(c) })
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
