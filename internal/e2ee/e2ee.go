package e2ee

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"

	"morse/backend/internal/chat"
)

const (
	HeaderVersion   = "X-E2EE-Version"
	HeaderClientKey = "X-Client-Pub-Key"
	HeaderModelKey  = "X-Model-Pub-Key"
	HeaderNonce     = "X-E2EE-Nonce"
	HeaderTimestamp = "X-E2EE-Timestamp"
	HeaderLegacy    = "X-Signing-Algo"
	HeaderApplied   = "X-E2EE-Applied"
	HeaderAlgo      = "X-E2EE-Algo"
	Version         = "2"
	Protocol        = "phala-aci-v2"
)

const (
	nonceHexLen = 64
	gcmNonceLen = 12
	gcmTagLen   = 16
)

var RequestHeaders = [...]string{HeaderVersion, HeaderClientKey, HeaderModelKey, HeaderNonce, HeaderTimestamp}

type Suite uint8

const (
	X25519 Suite = iota + 1
	Secp256k1
)

type suiteSpec struct {
	algo         string
	info         string
	keyLens      []int
	ephemeralLen int
}

var suites = [...]suiteSpec{
	X25519:    {"x25519-aes-256-gcm-hkdf-sha256", "aci.e2ee.v2.x25519", []int{32}, 32},
	Secp256k1: {"secp256k1-aes-256-gcm-hkdf-sha256", "aci.e2ee.v2.secp256k1", []int{64, 65}, 65},
}

func (s Suite) valid() bool { return s >= X25519 && s <= Secp256k1 }

func (s Suite) Algo() string {
	if !s.valid() {
		return ""
	}
	return suites[s].algo
}

func (s Suite) String() string { return s.Algo() }

func (s Suite) MinCiphertextHex() int {
	return 2 * (suites[s].ephemeralLen + gcmNonceLen + gcmTagLen)
}

func (s Suite) IsCiphertext(rawJSON []byte) bool {
	if len(rawJSON) < 2 || rawJSON[0] != '"' || rawJSON[len(rawJSON)-1] != '"' {
		return false
	}
	body := rawJSON[1 : len(rawJSON)-1]
	if len(body) < s.MinCiphertextHex() || len(body)%2 != 0 {
		return false
	}
	for _, c := range body {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type Params struct {
	suite     Suite
	clientKey string
	modelKey  string
	nonce     string
	timestamp string
	ts        int64
}

func NewParams(client *ecdh.PrivateKey, model *ecdh.PublicKey, ts int64) (Params, error) {
	if client.Curve() != ecdh.X25519() || model.Curve() != ecdh.X25519() {
		return Params{}, errSuiteNotSealable
	}
	nonce := make([]byte, hex.DecodedLen(nonceHexLen))
	rand.Read(nonce)
	return Params{
		suite:     X25519,
		clientKey: hex.EncodeToString(client.PublicKey().Bytes()),
		modelKey:  hex.EncodeToString(model.Bytes()),
		nonce:     hex.EncodeToString(nonce),
		timestamp: strconv.FormatInt(ts, 10),
		ts:        ts,
	}, nil
}

func (p Params) Suite() Suite { return p.suite }

func (p Params) ClientX25519() (*ecdh.PublicKey, error) { return p.x25519Key(p.clientKey) }

func (p Params) ModelX25519() (*ecdh.PublicKey, error) { return p.x25519Key(p.modelKey) }

func (p Params) ModelKey() []byte {
	key, _ := decodeKey(p.modelKey)
	return key
}

func (p Params) x25519Key(header string) (*ecdh.PublicKey, error) {
	if p.suite != X25519 {
		return nil, errSuiteNotSealable
	}
	key, err := decodeKey(header)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(key)
}

type Error struct {
	Type    string
	Message string
}

func (e *Error) Error() string { return "e2ee: " + e.Type + ": " + e.Message }

var (
	ErrHeaderMissing    = &Error{"e2ee_header_missing", "E2EE v2 needs X-E2EE-Version, X-Client-Pub-Key, X-Model-Pub-Key, X-E2EE-Nonce, and X-E2EE-Timestamp."}
	ErrLegacy           = &Error{"e2ee_invalid_version", "X-Signing-Algo selects the legacy protocol. This proxy serves E2EE v2 only."}
	ErrInvalidVersion   = &Error{"e2ee_invalid_version", "X-E2EE-Version must be 2."}
	ErrInvalidKey       = &Error{"e2ee_invalid_public_key", "A public key is not valid hex of a supported suite's length."}
	ErrInvalidNonce     = &Error{"e2ee_invalid_nonce", "X-E2EE-Nonce must be exactly 64 hexadecimal characters."}
	ErrInvalidTimestamp = &Error{"e2ee_invalid_timestamp", "X-E2EE-Timestamp must be Unix seconds."}
)

var ErrNotApplied = errors.New("e2ee: upstream did not confirm E2EE v2 with the requested suite")

var Scheme = &chat.Scheme{Name: Protocol, Version: Version, Headers: []string{HeaderVersion, HeaderClientKey, HeaderModelKey, HeaderNonce, HeaderTimestamp, HeaderLegacy, HeaderAlgo}, Parse: parse, ErrHeaderMissing: ErrHeaderMissing, Vendor: "Phala", ProviderRule: `must carry provider exactly {"aci_verified":true,"zdr":true}`}

func parse(get func(name string) string) (chat.E2EE, bool, error) {
	params, sealed, err := ParseHeaders(get)
	return params, sealed, err
}

func ParseHeaders(get func(name string) string) (params Params, sealed bool, err error) {
	if get(HeaderLegacy) != "" {
		return Params{}, true, ErrLegacy
	}
	var values [len(RequestHeaders)]string
	present := 0
	for i, name := range RequestHeaders {
		if values[i] = get(name); values[i] != "" {
			present++
		}
	}
	if present == 0 {
		return Params{}, false, nil
	}
	if present < len(RequestHeaders) {
		return Params{}, true, ErrHeaderMissing
	}
	version, clientKey, modelKey, nonce, timestamp := values[0], values[1], values[2], values[3], values[4]
	if version != Version {
		return Params{}, true, ErrInvalidVersion
	}
	suite, ok := suiteOfKey(modelKey)
	if !ok {
		return Params{}, true, ErrInvalidKey
	}
	if clientSuite, ok := suiteOfKey(clientKey); !ok || clientSuite != suite {
		return Params{}, true, ErrInvalidKey
	}
	if len(nonce) != nonceHexLen || !isHex(nonce) {
		return Params{}, true, ErrInvalidNonce
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Params{}, true, ErrInvalidTimestamp
	}
	return Params{suite: suite, clientKey: clientKey, modelKey: modelKey, nonce: nonce, timestamp: timestamp, ts: ts}, true, nil
}

func (p Params) Forward(set func(name, value string)) {
	set(HeaderVersion, Version)
	set(HeaderClientKey, p.clientKey)
	set(HeaderModelKey, p.modelKey)
	set(HeaderNonce, p.nonce)
	set(HeaderTimestamp, p.timestamp)
}

func (p Params) Confirm(get func(name string) string) error {
	if get(HeaderApplied) != "true" || get(HeaderVersion) != Version || get(HeaderAlgo) != p.suite.Algo() {
		return ErrNotApplied
	}
	return nil
}

func (p Params) WriteApplied(set func(name, value string)) {
	set(HeaderApplied, "true")
	set(HeaderVersion, Version)
	set(HeaderAlgo, p.suite.Algo())
}

func (p Params) IsCiphertext(rawJSON []byte) bool { return p.suite.IsCiphertext(rawJSON) }

func (Params) ConfirmsEncryption() bool { return true }

func decodeKey(value string) ([]byte, error) {
	value = strings.TrimPrefix(value, "0x")
	return hex.DecodeString(value)
}

func suiteOfKey(value string) (Suite, bool) {
	key, err := decodeKey(value)
	if err != nil {
		return 0, false
	}
	for s := X25519; s <= Secp256k1; s++ {
		if slices.Contains(suites[s].keyLens, len(key)) {
			return s, true
		}
	}
	return 0, false
}

func isHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}
