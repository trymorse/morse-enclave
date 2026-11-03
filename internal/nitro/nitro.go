// Package nitro attests the proxy's HPKE key: on an enclave through /dev/nsm, and elsewhere with a stand-in document
// that a production build of the web app refuses. deploy/enclave/DESIGN.md section 2 is the rule.
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
)

const devicePath = "/dev/nsm"

type Attester interface {
	Attest(ctx context.Context, environment string, publicKey []byte) ([]byte, error)
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

func (n NSM) Attest(_ context.Context, environment string, publicKey []byte) ([]byte, error) {
	sess, err := n.open()
	if err != nil {
		return nil, fmt.Errorf("nitro: %w", err)
	}
	defer sess.Close()
	res, err := sess.Send(&request.Attestation{UserData: verify.UserData(environment, publicKey)})
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

func (Dev) Attest(_ context.Context, environment string, publicKey []byte) ([]byte, error) {
	return verify.StandIn{Environment: environment, PublicKey: publicKey, IssuedAt: time.Now()}.Document(), nil
}
