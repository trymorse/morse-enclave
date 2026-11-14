package near

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"filippo.io/edwards25519"

	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
)

const (
	HeaderSigningAlgo = "X-Signing-Algo"
	HeaderClientKey   = "X-Client-Pub-Key"
	HeaderModelKey    = "X-Model-Pub-Key"
	HeaderVersion     = "X-Encryption-Version"
	HeaderAllFields   = "X-Encrypt-All-Fields"
	Version           = "2"
	Protocol          = "near-ed25519-v2"
)

var RequestHeaders = [...]string{HeaderSigningAlgo, HeaderClientKey, HeaderModelKey, HeaderVersion, HeaderAllFields}

type Params struct {
	Client ed25519.PublicKey
	Model  ed25519.PublicKey
}

var (
	ErrHeaderMissing  = &e2ee.Error{Type: "e2ee_header_missing", Message: "NEAR E2EE needs X-Signing-Algo, X-Client-Pub-Key, X-Model-Pub-Key, X-Encryption-Version, and X-Encrypt-All-Fields."}
	ErrInvalidAlgo    = &e2ee.Error{Type: "e2ee_invalid_algo", Message: "X-Signing-Algo must be ed25519. This proxy does not serve NEAR's ecdsa encryption."}
	ErrInvalidVersion = &e2ee.Error{Type: "e2ee_invalid_version", Message: "X-Encryption-Version must be 2. Without it NEAR selects version 1, which this proxy does not serve."}
	ErrPartialFields  = &e2ee.Error{Type: "e2ee_all_fields_required", Message: "X-Encrypt-All-Fields must be true, or NEAR leaves tool calls, refusals, and logprobs in plaintext."}
	ErrInvalidKey     = &e2ee.Error{Type: "e2ee_invalid_public_key", Message: "X-Client-Pub-Key and X-Model-Pub-Key must each be an ed25519 public key in 64 hexadecimal characters."}
)

// PromptComment is the SSE comment line a launch chat's streamed reply opens with: the system message the proxy
// sealed and put first, which NEAR's receipt hashes with the client's own messages, so the client can rebuild the
// bytes forwarded.
func PromptComment(sealed string) []byte { return []byte(": wm-prompt " + sealed + "\n") }

var Scheme = &chat.Scheme{Name: Protocol, Version: Version, Headers: []string{HeaderSigningAlgo, HeaderClientKey, HeaderModelKey, HeaderVersion, HeaderAllFields}, Parse: parse, ErrHeaderMissing: ErrHeaderMissing, Vendor: "NEAR", ProviderRule: "is forwarded verbatim and may carry no provider field"}

func parse(get func(name string) string) (chat.E2EE, bool, error) {
	params, sealed, err := ParseHeaders(get)
	return params, sealed, err
}

func ParseHeaders(get func(name string) string) (params Params, sealed bool, err error) {
	if get(HeaderSigningAlgo) == "" || get(HeaderVersion) == "" && get(HeaderAllFields) == "" {
		return Params{}, false, nil
	}
	if !strings.EqualFold(get(HeaderSigningAlgo), "ed25519") {
		return Params{}, true, ErrInvalidAlgo
	}
	if get(HeaderVersion) != Version {
		return Params{}, true, ErrInvalidVersion
	}
	if !strings.EqualFold(get(HeaderAllFields), "true") {
		return Params{}, true, ErrPartialFields
	}
	if get(HeaderClientKey) == "" || get(HeaderModelKey) == "" {
		return Params{}, true, ErrHeaderMissing
	}
	client, clientOK := parseKey(get(HeaderClientKey))
	model, modelOK := parseKey(get(HeaderModelKey))
	if !clientOK || !modelOK {
		return Params{}, true, ErrInvalidKey
	}
	return Params{Client: client, Model: model}, true, nil
}

func (p Params) Forward(set func(name, value string)) {
	set(HeaderSigningAlgo, "ed25519")
	set(HeaderClientKey, hex.EncodeToString(p.Client))
	set(HeaderModelKey, hex.EncodeToString(p.Model))
	set(HeaderVersion, Version)
	set(HeaderAllFields, "true")
}

func (Params) Confirm(func(name string) string) error { return nil }

func (Params) WriteApplied(func(name, value string)) {}

func (Params) IsCiphertext(rawJSON []byte) bool { return IsCiphertext(rawJSON) }

func (Params) ConfirmsEncryption() bool { return false }

func (p Params) ModelKey() []byte { return p.Model }

func parseKey(header string) (ed25519.PublicKey, bool) {
	key, err := hex.DecodeString(header)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, false
	}
	if _, err := new(edwards25519.Point).SetBytes(key); err != nil {
		return nil, false
	}
	return key, true
}
