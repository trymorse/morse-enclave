// Package nitro attests the proxy's HPKE key: on an enclave through /dev/nsm, and elsewhere with a stand-in document
// that a production build of the web app refuses.
package nitro

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/seal"
)

const devicePath = "/dev/nsm"

type Attester interface {
	Attest(ctx context.Context, environment string, publicKey, tls, nonce []byte) ([]byte, error)
	Time(document []byte) (time.Time, error)
	Peer(document []byte, expect verify.Expectation) ([]byte, verify.Key, error)
}

func Open() Attester {
	if _, err := os.Stat(devicePath); err == nil {
		return NSM{open: openDefault}
	}
	return Dev{}
}

type session interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

func openDefault() (session, error) { return nsm.OpenDefaultSession() }

type NSM struct {
	open func() (session, error)
}

func (n NSM) Attest(_ context.Context, environment string, publicKey, tls, nonce []byte) ([]byte, error) {
	sess, err := n.open()
	if err != nil {
		return nil, fmt.Errorf("nitro: %w", err)
	}
	defer sess.Close()
	res, err := sess.Send(&request.Attestation{UserData: verify.UserData(environment, publicKey), PublicKey: tls, Nonce: nonce})
	switch {
	case err != nil:
		return nil, fmt.Errorf("nitro: %w", err)
	case res.Error != "":
		return nil, fmt.Errorf("nitro: %s", res.Error)
	case res.Attestation == nil || len(res.Attestation.Document) == 0:
		return nil, errors.New("nitro: the module returned no document")
	}
	return res.Attestation.Document, nil
}

type Dev struct{}

func (Dev) Attest(_ context.Context, environment string, publicKey, tls, nonce []byte) ([]byte, error) {
	return verify.StandIn{Environment: environment, PublicKey: publicKey, TLS: tls, Nonce: nonce, IssuedAt: time.Now()}.Document(), nil
}

func (NSM) Time(document []byte) (time.Time, error) { return verify.TimestampUnverified(document) }

func (NSM) Peer(document []byte, expect verify.Expectation) ([]byte, verify.Key, error) {
	expect.Root = verify.Root
	return verify.AttestedSPKI(document, expect)
}

func (Dev) Time(document []byte) (time.Time, error) {
	s, err := verify.ParseStandIn(document)
	return s.IssuedAt, err
}

func (Dev) Peer(document []byte, expect verify.Expectation) ([]byte, verify.Key, error) {
	s, err := verify.ParseStandIn(document)
	if err != nil {
		return nil, verify.Key{}, err
	}
	if s.Environment != expect.Environment {
		return nil, verify.Key{}, fmt.Errorf("the stand-in is for %s, not %s", s.Environment, expect.Environment)
	}
	if err := verify.Fresh(s.IssuedAt, expect.Now); err != nil {
		return nil, verify.Key{}, err
	}
	if err := verify.P256(s.TLS); err != nil {
		return nil, verify.Key{}, err
	}
	return s.TLS, verify.Key{PublicKey: s.PublicKey, TLS: s.TLS, Nonce: s.Nonce, IssuedAt: s.IssuedAt}, nil
}

type Self struct {
	Attester    Attester
	Identity    *seal.Identity
	Environment string
}

func (s Self) Attest(ctx context.Context, tls, nonce []byte) ([]byte, error) {
	return s.Attester.Attest(ctx, s.Environment, s.Identity.PublicKey(), tls, nonce)
}

func (s Self) Time(document []byte) (time.Time, error) { return s.Attester.Time(document) }

func (s Self) Peer(document []byte, expect verify.Expectation) ([]byte, verify.Key, error) {
	return s.Attester.Peer(document, expect)
}

func (s Self) Open(sealed []byte) (seal.Request, error) { return s.Identity.Open(sealed) }
