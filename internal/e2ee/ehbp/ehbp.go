// Package ehbp is the Encrypted HTTP Body Protocol as the proxy relays it: the client seals the whole
// request body with HPKE to the key an attested enclave's report binds, and the enclave seals its reply under
// a key derived from the same context, so the proxy forwards ciphertext it can't read. Headers stay clear:
// the client names the model and its output limit in them, and the enclave refuses a body that names
// another model. Tinfoil's router speaks it.
package ehbp

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
)

const (
	HeaderEncapsulatedKey = "Ehbp-Encapsulated-Key"
	HeaderResponseNonce   = "Ehbp-Response-Nonce"
	HeaderModel           = "X-Tinfoil-Model"
	HeaderMaxOutput       = "X-Tinfoil-Max-Output-Tokens"
	// HeaderCompletionCount replaces the sealed body's n inside the enclave, so a proxy that can't read the
	// body still bounds a reply to one choice of at most HeaderMaxOutput tokens. Router v0.0.169 and later.
	HeaderCompletionCount = "X-Tinfoil-Completion-Count"
	Version               = "1"
	Protocol              = "tinfoil-ehbp-v1"
	keyLen                = 32
	nonceLen              = 32
)

var RequestHeaders = [...]string{HeaderEncapsulatedKey, HeaderModel, HeaderMaxOutput}

var (
	ErrHeaderMissing = &e2ee.Error{Type: "e2ee_header_missing", Message: "EHBP needs Ehbp-Encapsulated-Key, X-Tinfoil-Model, and X-Tinfoil-Max-Output-Tokens."}
	ErrInvalidKey    = &e2ee.Error{Type: "e2ee_invalid_public_key", Message: "Ehbp-Encapsulated-Key must be the request's X25519 encapsulated key in 64 lowercase hexadecimal characters."}
	ErrInvalidLimit  = &e2ee.Error{Type: "e2ee_output_limit_required", Message: "X-Tinfoil-Max-Output-Tokens must be a positive integer, because the proxy can't read the sealed body's limit."}
	errNotApplied    = fmt.Errorf("%w: no %s of %d bytes", e2ee.ErrNotApplied, HeaderResponseNonce, nonceLen)
)

var Scheme = &chat.Scheme{Name: Protocol, Version: Version, Headers: RequestHeaders[:], Parse: parse, ErrHeaderMissing: ErrHeaderMissing, SealsBody: true}

type Params struct {
	Encapsulated [keyLen]byte
	Model        string
	Limit        int
}

var _ chat.BodySealed = Params{}

func parse(get func(name string) string) (chat.E2EE, bool, error) {
	if get(HeaderEncapsulatedKey) == "" && get(HeaderModel) == "" && get(HeaderMaxOutput) == "" {
		return nil, false, nil
	}
	if get(HeaderEncapsulatedKey) == "" || get(HeaderModel) == "" || get(HeaderMaxOutput) == "" {
		return nil, true, ErrHeaderMissing
	}
	var p Params
	if key, ok := lowerHex(get(HeaderEncapsulatedKey), keyLen); ok {
		copy(p.Encapsulated[:], key)
	} else {
		return nil, true, ErrInvalidKey
	}
	limit, err := strconv.Atoi(get(HeaderMaxOutput))
	if err != nil || limit <= 0 {
		return nil, true, ErrInvalidLimit
	}
	p.Model, p.Limit = get(HeaderModel), limit
	return p, true, nil
}

func lowerHex(text string, n int) ([]byte, bool) {
	b, err := hex.DecodeString(text)
	return b, err == nil && len(b) == n && hex.EncodeToString(b) == text
}

// Forward passes the encapsulated key, which the enclave opens the body with. The route names the model and
// the limit itself, from what it admitted.
func (p Params) Forward(set func(name, value string)) {
	set(HeaderEncapsulatedKey, hex.EncodeToString(p.Encapsulated[:]))
}

// Confirm requires the response nonce every sealed reply carries: without it the reply is not sealed to the
// request's context.
func (Params) Confirm(get func(name string) string) error {
	if _, ok := lowerHex(get(HeaderResponseNonce), nonceLen); !ok {
		return errNotApplied
	}
	return nil
}

// WriteApplied writes nothing: the route relays the response nonce, which the client derives its reply key from.
func (Params) WriteApplied(func(name, value string)) {}

// IsCiphertext is false for every field: the body is sealed whole, so the proxy reads none.
func (Params) IsCiphertext([]byte) bool { return false }

func (Params) ConfirmsEncryption() bool { return true }

// ModelKey is nil: the request is sealed to the key the enclave's report binds, not one a header names.
func (Params) ModelKey() []byte { return nil }

func (p Params) SealedModel() string { return p.Model }

func (p Params) OutputLimit() int { return p.Limit }
