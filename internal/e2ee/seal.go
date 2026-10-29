package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"morse/backend/internal/jcs"
)

const (
	requestPurpose  = "aci.e2ee.request.v2"
	responsePurpose = "aci.e2ee.response.v2"
)

type ResponseField struct {
	Choice int
	Part   string
	Name   string
}

func (f ResponseField) String() string {
	return "choices." + strconv.Itoa(f.Choice) + "." + f.Part + "." + f.Name
}

type AAD struct {
	suite   Suite
	purpose string
	model   string
	id      string
	field   string
	nonce   string
	ts      int64
}

func (p Params) RequestAAD(model string, message int) AAD {
	return AAD{suite: p.suite, purpose: requestPurpose, model: model, field: "messages." + strconv.Itoa(message) + ".content", nonce: p.nonce, ts: p.ts}
}

func (p Params) ResponseAAD(model, id string, field ResponseField) AAD {
	return AAD{suite: p.suite, purpose: responsePurpose, model: model, id: id, field: field.String(), nonce: p.nonce, ts: p.ts}
}

func (a AAD) Bytes() []byte {
	out := append([]byte(`{"algo":`), jcs.String(a.suite.Algo())...)
	out = jcs.AppendString(append(out, `,"field":`...), a.field)
	if a.purpose == responsePurpose {
		out = jcs.AppendString(append(out, `,"id":`...), a.id)
	}
	out = jcs.AppendString(append(out, `,"model":`...), a.model)
	out = jcs.AppendString(append(out, `,"nonce":`...), a.nonce)
	out = jcs.AppendString(append(out, `,"purpose":`...), a.purpose)
	out = strconv.AppendInt(append(out, `,"ts":`...), a.ts, 10)
	return append(out, '}')
}

const aesKeyLen = 32

var (
	errSuiteNotSealable = errors.New("e2ee: Seal and Open serve the X25519 suite only")
	errSealedTooShort   = errors.New("e2ee: sealed value is shorter than ephemeral key, nonce, and tag")
)

func Seal(recipient *ecdh.PublicKey, aad AAD, plaintext []byte) (string, error) {
	if aad.suite != X25519 {
		return "", errSuiteNotSealable
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	gcm, err := fieldCipher(ephemeral, recipient)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcmNonceLen)
	rand.Read(nonce)
	sealed := append(ephemeral.PublicKey().Bytes(), nonce...)
	return hex.EncodeToString(gcm.Seal(sealed, nonce, plaintext, aad.Bytes())), nil
}

func Open(recipient *ecdh.PrivateKey, aad AAD, sealed string) ([]byte, error) {
	if aad.suite != X25519 {
		return nil, errSuiteNotSealable
	}
	raw, err := hex.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	ephemeralLen := suites[X25519].ephemeralLen
	if len(raw) < ephemeralLen+gcmNonceLen+gcmTagLen {
		return nil, errSealedTooShort
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(raw[:ephemeralLen])
	if err != nil {
		return nil, err
	}
	gcm, err := fieldCipher(recipient, ephemeral)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := raw[ephemeralLen:ephemeralLen+gcmNonceLen], raw[ephemeralLen+gcmNonceLen:]
	return gcm.Open(nil, nonce, ciphertext, aad.Bytes())
}

func fieldCipher(private *ecdh.PrivateKey, public *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, suites[X25519].info, aesKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
