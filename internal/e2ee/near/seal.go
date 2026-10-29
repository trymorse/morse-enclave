package near

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ephemeralLen     = 32
	nonceLen         = chacha20poly1305.NonceSizeX
	tagLen           = chacha20poly1305.Overhead
	MinCiphertextHex = 2 * (ephemeralLen + nonceLen + tagLen)
	kdfInfo          = "ed25519_encryption"
)

var errSealedTooShort = errors.New("near: sealed value is shorter than ephemeral key, nonce, and tag")

func Seal(recipient ed25519.PublicKey, plaintext []byte) (string, error) {
	point, err := new(edwards25519.Point).SetBytes(recipient)
	if err != nil {
		return "", err
	}
	target, err := ecdh.X25519().NewPublicKey(point.BytesMontgomery())
	if err != nil {
		return "", err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	aead, err := fieldCipher(ephemeral, target)
	if err != nil {
		return "", err
	}
	sealed := append(ephemeral.PublicKey().Bytes(), make([]byte, nonceLen)...)
	nonce := sealed[ephemeralLen:]
	rand.Read(nonce)
	return hex.EncodeToString(aead.Seal(sealed, nonce, plaintext, nil)), nil
}

func Open(recipient ed25519.PrivateKey, sealed string) ([]byte, error) {
	raw, err := hex.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	if len(raw) < ephemeralLen+nonceLen+tagLen {
		return nil, errSealedTooShort
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(raw[:ephemeralLen])
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum512(recipient.Seed())
	private, err := ecdh.X25519().NewPrivateKey(digest[:32])
	if err != nil {
		return nil, err
	}
	aead, err := fieldCipher(private, ephemeral)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, raw[ephemeralLen:ephemeralLen+nonceLen], raw[ephemeralLen+nonceLen:], nil)
}

func fieldCipher(private *ecdh.PrivateKey, public *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, kdfInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(key)
}

func IsCiphertext(rawJSON []byte) bool {
	if len(rawJSON) < 2 || rawJSON[0] != '"' || rawJSON[len(rawJSON)-1] != '"' {
		return false
	}
	body := rawJSON[1 : len(rawJSON)-1]
	if len(body) < MinCiphertextHex || len(body)%2 != 0 {
		return false
	}
	for _, c := range body {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
