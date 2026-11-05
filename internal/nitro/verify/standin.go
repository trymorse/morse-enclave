package verify

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	standInObject  = "proxy_attestation_stand_in"
	standInWarning = "not an AWS Nitro attestation: this proxy runs outside an enclave"
)

type StandIn struct {
	Environment string
	PublicKey   []byte
	TLS         []byte
	Nonce       []byte
	IssuedAt    time.Time
}

type standInDocument struct {
	Object      string `json:"object"`
	Warning     string `json:"warning"`
	Environment string `json:"environment"`
	UserData    []byte `json:"user_data"`
	PublicKey   []byte `json:"public_key"`
	Nonce       []byte `json:"nonce,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

func UserData(environment string, publicKey []byte) []byte {
	return append([]byte(UserDataPrefix+environment+"|"), publicKey...)
}

func (s StandIn) Document() []byte {
	document, _ := json.Marshal(standInDocument{Object: standInObject, Warning: standInWarning, Environment: s.Environment, UserData: UserData(s.Environment, s.PublicKey), PublicKey: s.TLS, Nonce: s.Nonce, Timestamp: s.IssuedAt.UnixMilli()})
	return document
}

func ParseStandIn(document []byte) (StandIn, error) {
	var d standInDocument
	if err := json.Unmarshal(document, &d); err != nil || d.Object != standInObject {
		return StandIn{}, errors.New("verify: not a stand-in document")
	}
	publicKey, err := KeyInUserData(d.UserData, d.Environment)
	if err != nil {
		return StandIn{}, errors.New("verify: the stand-in's user data does not name a key")
	}
	return StandIn{Environment: d.Environment, PublicKey: publicKey, TLS: d.PublicKey, Nonce: d.Nonce, IssuedAt: time.UnixMilli(d.Timestamp)}, nil
}
