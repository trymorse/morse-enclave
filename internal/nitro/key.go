package nitro

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"morse/backend/internal/seal"
	"morse/backend/internal/taskseal"
)

const (
	devKeyBytes    = 32
	devTaskKeyInfo = "morse-task-key-v1"
)

// Key is the worker's sealing identity and its task key. On an enclave, and off one with no dev key, both are drawn
// fresh and die with the process. A dev key fixes both, the task key by HKDF-SHA256 over it, so tasks adopted off an
// enclave outlive a restart.
func Key(a Attester, devKey string) (*seal.Identity, *taskseal.Key, error) {
	if devKey == "" {
		identity, err := seal.NewIdentity()
		if err != nil {
			return nil, nil, err
		}
		return identity, taskseal.NewKey(), nil
	}
	if _, enclave := a.(NSM); enclave {
		return nil, nil, errors.New("PROXY_HPKE_DEV_KEY is set on an enclave, whose key nothing outside it may choose")
	}
	key, err := hex.DecodeString(devKey)
	if err != nil || len(key) != devKeyBytes {
		return nil, nil, errors.New("PROXY_HPKE_DEV_KEY must be 64 hexadecimal characters, a 32-byte X25519 private key such as openssl rand -hex 32")
	}
	identity, err := seal.IdentityFromKey(key)
	if err != nil {
		return nil, nil, err
	}
	secret, err := hkdf.Key(sha256.New, key, nil, devTaskKeyInfo, devKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return identity, taskseal.KeyFromSecret([32]byte(secret)), nil
}

func Name(a Attester) string {
	if _, enclave := a.(NSM); enclave {
		return "nsm"
	}
	return "stand-in"
}
