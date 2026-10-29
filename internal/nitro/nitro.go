// Package nitro attests the proxy's HPKE key: on an enclave through /dev/nsm, and elsewhere with a stand-in document
// that a production build of the web app refuses. deploy/enclave/DESIGN.md section 2 is the rule.
package nitro

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const UserDataPrefix = "morse-proxy-hpke-v1|"

const devicePath = "/dev/nsm"

type Attester interface {
	Attest(ctx context.Context, environment string, publicKey []byte) ([]byte, error)
}

func UserData(environment string, publicKey []byte) []byte {
	return append([]byte(UserDataPrefix+environment+"|"), publicKey...)
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
	res, err := sess.Send(&request.Attestation{UserData: UserData(environment, publicKey)})
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

type StandIn struct {
	Object      string `json:"object"`
	Warning     string `json:"warning"`
	Environment string `json:"environment"`
	UserData    []byte `json:"user_data"`
	Timestamp   int64  `json:"timestamp"`
}

const (
	StandInObject  = "proxy_attestation_stand_in"
	standInWarning = "not an AWS Nitro attestation: this proxy runs outside an enclave"
)

func (Dev) Attest(_ context.Context, environment string, publicKey []byte) ([]byte, error) {
	return json.Marshal(StandIn{Object: StandInObject, Warning: standInWarning, Environment: environment, UserData: UserData(environment, publicKey), Timestamp: time.Now().UnixMilli()})
}

func ParseStandIn(document []byte) (environment string, publicKey []byte, err error) {
	var s StandIn
	if err := json.Unmarshal(document, &s); err != nil || s.Object != StandInObject {
		return "", nil, errors.New("nitro: not a stand-in document")
	}
	prefix := []byte(UserDataPrefix + s.Environment + "|")
	if len(s.UserData) != len(prefix)+32 || string(s.UserData[:len(prefix)]) != string(prefix) {
		return "", nil, errors.New("nitro: the stand-in's user data does not name a key")
	}
	return s.Environment, s.UserData[len(prefix):], nil
}
