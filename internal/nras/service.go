package nras

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"morse/backend/internal/flight"
	"morse/backend/internal/upstream"
	"net/http"
	"time"
)

const (
	attestPath          = "/v3/attest/gpu"
	jwksPath            = "/.well-known/jwks.json"
	maxBodyLen          = 4 << 20
	jwksRefetchInterval = time.Minute
	jwksMaxAge          = time.Hour
	jwksFetchTimeout    = 30 * time.Second
	serviceTimeout      = 30 * time.Second
)

type Service struct {
	Base   string
	Client *http.Client
}

// NRAS 400 codes 4003 and 4400 name our own request, and 4008, 4009, 4015, and 4020 name NVIDIA's
// reference data. Probed live 2026-10-03: most bad evidence instead returns a signed 200 with a
// false result.
var evidenceRefusals = map[int]string{
	4004: "INVALID_GPU_ARCH",
	4005: "INVALID_EVIDENCE",
	4006: "INVALID_EVIDENCE_FORMAT",
	4007: "INVALID_CERTIFICATE_CHAIN",
	4010: "NONCE_NOT_MATCHING",
	4011: "CERTIFICATE_EXPIRED",
	4012: "GPU_ARCHITECTURE_NOT_SUPPORTED",
	4013: "INVALID_EVIDENCE_SIGNATURE",
	4014: "INVALID_ATTESTATION_CERTIFICATE_CHAIN",
	4016: "FWID_NOT_MATCHING",
	4022: "INVALID_FIRMWARE_VERSION",
	4023: "OPAQUE_DATA_VERSION_NOT_SUPPORTED",
}

func (s Service) Attest(ctx context.Context, payload []byte) ([]byte, error) {
	reply, err := s.exchange(ctx, http.MethodPost, attestPath, payload)
	if err == nil {
		return reply.Body, nil
	}
	var refusal struct {
		ErrorCode int `json:"errorCode"`
	}
	if reply.Status == http.StatusBadRequest && json.Unmarshal(reply.Body, &refusal) == nil {
		if name, ok := evidenceRefusals[refusal.ErrorCode]; ok {
			return nil, fmt.Errorf("%w: NRAS refused it with %d %s", ErrEvidence, refusal.ErrorCode, name)
		}
	}
	return nil, err
}

func (s Service) JWKS(ctx context.Context) ([]byte, error) {
	reply, err := s.exchange(ctx, http.MethodGet, jwksPath, nil)
	if err != nil {
		return nil, err
	}
	return reply.Body, nil
}

func (s Service) exchange(ctx context.Context, method, path string, payload []byte) (upstream.Reply, error) {
	reply, err := upstream.Endpoint{BaseURL: s.Base, HTTP: s.Client}.Call(ctx, upstream.Request{Method: method, Path: path, Body: payload}, maxBodyLen)
	switch {
	case err != nil:
		return reply, fmt.Errorf("%w: %s %s: %w", ErrUnreachable, method, path, err)
	case reply.Status != http.StatusOK:
		return reply, fmt.Errorf("%w: %s %s answered %d", ErrUnreachable, method, path, reply.Status)
	}
	return reply, nil
}

type Cache struct {
	service Service
	keys    flight.Cache[jwks]
}

func NVIDIA() Service {
	return Service{Base: DefaultBase, Client: &http.Client{Timeout: serviceTimeout}}
}

func NewCache(s Service) *Cache {
	c := &Cache{service: s}
	c.keys = flight.Cache[jwks]{Fetch: c.fetch, MaxAge: jwksMaxAge, MinRefetch: jwksRefetchInterval, Timeout: jwksFetchTimeout}
	return c
}

func (c *Cache) VerifyGPU(ctx context.Context, payload []byte, nonce [32]byte, now time.Time) (Verdict, error) {
	resp, err := c.service.Attest(ctx, payload)
	if err != nil {
		return Verdict{}, err
	}
	keys, err := c.keyset(ctx, now)
	if err != nil {
		return Verdict{}, err
	}
	verdict, err := verify(resp, keys, nonce, now, Roots())
	if !errors.Is(err, ErrUnknownKID) {
		return verdict, err
	}
	keys, fetched, refetchErr := c.keys.Refresh(ctx, now)
	switch {
	case refetchErr != nil:
		return Verdict{}, unreachable(refetchErr)
	case !fetched:
		return Verdict{}, fmt.Errorf("%w: the jwks was fetched less than %s ago, so an unlisted kid is not a verdict: %w", ErrUnreachable, jwksRefetchInterval, err)
	}
	return verify(resp, keys, nonce, now, Roots())
}

func (c *Cache) keyset(ctx context.Context, now time.Time) (jwks, error) {
	keys, err := c.keys.Current(ctx, now)
	if err != nil {
		return jwks{}, unreachable(err)
	}
	return keys, nil
}

func (c *Cache) fetch(ctx context.Context) (jwks, error) {
	raw, err := c.service.JWKS(ctx)
	if err != nil {
		return jwks{}, err
	}
	return parseJWKS(raw)
}

func unreachable(err error) error {
	if errors.Is(err, ErrUnreachable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}
