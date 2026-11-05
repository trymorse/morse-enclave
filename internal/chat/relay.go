package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

var (
	ErrSealBroken    = errors.New("the sealed reply broke its seal")
	ErrUnsealedReply = fmt.Errorf("%w: it carried a generated field that is not ciphertext", ErrSealBroken)
)

type Mismatch struct {
	Field string
	Want  json.RawMessage
}

func (m *Mismatch) Error() string {
	return "chat: verbatim body field " + m.Field + " is not " + string(m.Want)
}

type Header struct{ Name, Value string }

type Relayed struct {
	ContentType string
	Headers     []Header
}

type E2EE interface {
	Forward(set func(name, value string))
	Confirm(get func(name string) string) error
	WriteApplied(set func(name, value string))
	IsCiphertext(rawJSON []byte) bool
	ConfirmsEncryption() bool
	ModelKey() []byte // the key the request is sealed to, as the wire names it
}

// A Scheme is one E2EE protocol as its headers select it. Parse answers sealed for a request that names the
// scheme, with its params or why they are refused; ErrHeaderMissing refuses a request that names none on a
// route that speaks this scheme. Routes and requests compare schemes by identity.
type Scheme struct {
	Name, Version    string
	Headers          []string
	Parse            func(get func(name string) string) (params E2EE, sealed bool, err error)
	ErrHeaderMissing error
	// SealsBody is a scheme that seals the whole request body, so its params are BodySealed: the clear
	// headers name what the proxy can't read inside the body.
	SealsBody bool
}

// BodySealed is the params of a scheme that seals the whole body: the model the request names, which the
// upstream refuses unless the body names it too, and the output limit the client asks for.
type BodySealed interface {
	E2EE
	SealedModel() string
	OutputLimit() int
}

type Replied struct {
	Usage  Usage
	Events int
	// Tokens, when set, bounds the completion tokens the relayed events carry more closely than one an event,
	// for a relay that can't read them (a reply sealed whole). The bill falls back on it without a usage.
	Tokens        int
	UnknownFields []string
}

type Relayer interface {
	Check(req *Request) error
	Relay(ctx context.Context, c Call, sealed E2EE, begin func(Relayed) io.Writer) (Replied, error)
}

type VerbatimRoute interface {
	Attester
	Relayer
	Receipter
	Speaks() *Scheme
	// SealPrompt seals prompt as the content of the system message a request opens with, to the model key the
	// request is sealed to, once a verified report lists that key.
	SealPrompt(sealed E2EE, prompt string) (string, error)
	// OnBehalf serves a plaintext chat sealed to a key a verified report lists, and opens the reply.
	OnBehalf() Provider
}

const (
	HeaderReceiptID    = "X-Receipt-Id"
	HeaderKeysetDigest = "X-Aci-Keyset-Digest"
)

var ReceiptHeaders = []string{HeaderReceiptID, "X-Aci-Version", HeaderKeysetDigest, "X-Aci-Identity"}

type InvalidReceiptID struct{ Form string }

func (e *InvalidReceiptID) Error() string { return "chat: receipt id must be " + e.Form }

var ErrReceiptNotFound = errors.New("chat: no receipt with that id")

type Receipter interface {
	Receipt(ctx context.Context, id string) (json.RawMessage, error)
}

var (
	ErrInvalidSessionID = errors.New("chat: session id must be 64 lowercase hexadecimal characters")
	ErrSessionNotFound  = errors.New("chat: no attested session with that id")
	ErrSessionTooLarge  = errors.New("chat: the attested session exceeds the size limit")
)

var sessionID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidSessionID reports whether id has the form of an attested session's id, the hex sha256 of its record.
func ValidSessionID(id string) bool { return sessionID.MatchString(id) }

// A ListedSession is an attested session its gateway lists now, by its id and when the gateway established it
// in Unix seconds.
type ListedSession struct {
	ID            string `json:"session_id"`
	EstablishedAt int64  `json:"established_at"`
}

// A Sessioner serves the attested-session records a gateway's receipts cite, as the gateway's bytes, and lists
// the sessions the gateway holds now for the route's model.
type Sessioner interface {
	Session(ctx context.Context, id string) (json.RawMessage, error)
	ListSessions(ctx context.Context) ([]ListedSession, error)
}
