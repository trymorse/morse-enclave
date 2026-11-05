package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
)

func AttestedSPKI(document []byte, expect Expectation) ([]byte, Key, error) {
	key, err := Document(document, expect)
	if err != nil {
		return nil, Key{}, err
	}
	if err := P256(key.TLS); err != nil {
		return nil, Key{}, err
	}
	return key.TLS, key, nil
}

func P256(spki []byte) error {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("public_key is not a SubjectPublicKeyInfo: %w", err)
	}
	if ec, ok := parsed.(*ecdsa.PublicKey); !ok || ec.Curve != elliptic.P256() {
		return errors.New("public_key is not a P-256 key")
	}
	return nil
}
