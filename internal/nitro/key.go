package nitro

import (
	"encoding/hex"
	"errors"

	"morse/backend/internal/seal"
)

const devKeyBytes = 32

func Key(a Attester, devKey string) (*seal.Identity, error) {
	if devKey == "" {
		return seal.NewIdentity()
	}
	if _, enclave := a.(NSM); enclave {
		return nil, errors.New("PROXY_HPKE_DEV_KEY is set on an enclave, whose key nothing outside it may choose")
	}
	key, err := hex.DecodeString(devKey)
	if err != nil || len(key) != devKeyBytes {
		return nil, errors.New("PROXY_HPKE_DEV_KEY must be 64 hexadecimal characters, a 32-byte X25519 private key such as openssl rand -hex 32")
	}
	return seal.IdentityFromKey(key)
}

func Name(a Attester) string {
	if _, enclave := a.(NSM); enclave {
		return "nsm"
	}
	return "stand-in"
}
