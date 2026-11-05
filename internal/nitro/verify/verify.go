// Package verify checks an AWS Nitro attestation document of the Morse proxy and returns the HPKE key its user_data
// binds. It links no other Morse package, so a client outside the proxy can import it. check-enclave.py in
// github.com/trymorse/morse-enclave is the same check in Python.
package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	UserDataPrefix = "morse-proxy-hpke-v1|"
	MaxAge         = 30 * time.Minute
	MaxAhead       = 5 * time.Minute

	RootFingerprint = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

	keyBytes       = 32
	es384          = -35
	p384Coordinate = 48
)

const rootPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

var Root = mustRoot()

func mustRoot() *x509.Certificate {
	block, _ := pem.Decode([]byte(rootPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	if sum := sha256.Sum256(cert.Raw); hex.EncodeToString(sum[:]) != RootFingerprint {
		panic("verify: the embedded AWS Nitro root does not match its pinned fingerprint")
	}
	return cert
}

var ErrUnpinned = errors.New("verify: no pin names the document's PCRs")

// Image is the enclave image a pin trusts. It is a public release named by its tag, as morse-pins lists them, or a
// private build named by its commit and version, as the private pins do. Tagged and Built make the two shapes.
type Image struct{ tag, commit, version string }

func Tagged(tag string) Image { return Image{tag: tag} }

func Built(commit, version string) Image { return Image{commit: commit, version: version} }

// Tag is a public release's tag, and false for a private build.
func (i Image) Tag() (string, bool) { return i.tag, i.tag != "" }

// Name is a public release's tag or a private build's version.
func (i Image) Name() string {
	if i.tag != "" {
		return i.tag
	}
	return i.version
}

type Pin struct {
	Image       Image
	Environment string
	PCR0        string
	PCR1        string
	PCR2        string
	BuiltAt     string
	Revoked     bool
}

type pinEntry struct {
	Tag         string `json:"tag"`
	Commit      string `json:"commit"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	PCR0        string `json:"pcr0"`
	PCR1        string `json:"pcr1"`
	PCR2        string `json:"pcr2"`
	BuiltAt     string `json:"built_at"`
	Revoked     bool   `json:"revoked"`
}

func (e pinEntry) image() (Image, bool) {
	switch {
	case e.Tag != "" && e.Commit == "" && e.Version == "":
		return Tagged(e.Tag), true
	case e.Tag == "" && e.Commit != "" && e.Version != "":
		return Built(e.Commit, e.Version), true
	}
	return Image{}, false
}

var (
	pcrPattern = regexp.MustCompile(`^[0-9a-f]{96}$`)
	zeroPCR    = strings.Repeat("0", 96)
)

func (p Pin) Name() string { return p.Image.Name() }

func (p Pin) names(pcr0, pcr1, pcr2 string) bool {
	return p.PCR0 == pcr0 && p.PCR1 == pcr1 && p.PCR2 == pcr2
}

func ParsePins(data []byte) ([]Pin, error) {
	var entries []pinEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("verify: pins: %w", err)
	}
	pins := make([]Pin, len(entries))
	seen := map[[4]string]int{}
	for i, e := range entries {
		image, ok := e.image()
		if !ok || e.Environment == "" {
			return nil, fmt.Errorf("verify: pins[%d] needs an environment and either a tag, as morse-pins lists, or a commit and version, as the private pins do", i)
		}
		p := Pin{Image: image, Environment: e.Environment, PCR0: e.PCR0, PCR1: e.PCR1, PCR2: e.PCR2, BuiltAt: e.BuiltAt, Revoked: e.Revoked}
		pins[i] = p
		if _, err := time.Parse(time.RFC3339, p.BuiltAt); err != nil {
			return nil, fmt.Errorf("verify: pins[%d].built_at: %w", i, err)
		}
		for name, pcr := range map[string]string{"pcr0": p.PCR0, "pcr1": p.PCR1, "pcr2": p.PCR2} {
			if !pcrPattern.MatchString(pcr) {
				return nil, fmt.Errorf("verify: pins[%d].%s is not 96 lowercase hex characters", i, name)
			}
		}
		if p.names(zeroPCR, zeroPCR, zeroPCR) {
			return nil, fmt.Errorf("verify: pins[%d] pins all-zero PCRs, which only a debug enclave reports", i)
		}
		pinned := [4]string{p.Environment, p.PCR0, p.PCR1, p.PCR2}
		if first, ok := seen[pinned]; ok {
			return nil, fmt.Errorf("verify: pins[%d] and pins[%d] pin the same %s PCRs", first, i, p.Environment)
		}
		seen[pinned] = i
	}
	return pins, nil
}

type Expectation struct {
	Environment string
	Pins        []Pin
	Root        *x509.Certificate
	Now         time.Time
}

type Key struct {
	PublicKey []byte
	TLS       []byte
	Nonce     []byte
	IssuedAt  time.Time
	Pin       Pin
}

type sign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type protectedHeader struct {
	Alg int64 `cbor:"1,keyasint"`
}

type payload struct {
	ModuleID    string          `cbor:"module_id"`
	Digest      string          `cbor:"digest"`
	Timestamp   int64           `cbor:"timestamp"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	PublicKey   []byte          `cbor:"public_key"`
	UserData    []byte          `cbor:"user_data"`
	Nonce       []byte          `cbor:"nonce"`
}

func Document(document []byte, expect Expectation) (Key, error) {
	var cose sign1
	if err := cbor.Unmarshal(document, &cose); err != nil || cose.Payload == nil {
		return Key{}, errors.New("the document is not a COSE_Sign1")
	}
	var header protectedHeader
	if err := cbor.Unmarshal(cose.Protected, &header); err != nil || header.Alg != es384 {
		return Key{}, errors.New("the document is not signed with ES384")
	}
	var body payload
	if err := cbor.Unmarshal(cose.Payload, &body); err != nil {
		return Key{}, fmt.Errorf("the document's payload does not parse: %w", err)
	}
	if body.Digest != "SHA384" {
		return Key{}, errors.New("the document's digest is not SHA384")
	}
	issuedAt := time.UnixMilli(body.Timestamp).UTC()
	leaf, err := x509.ParseCertificate(body.Certificate)
	if err != nil {
		return Key{}, fmt.Errorf("the signing certificate does not parse: %w", err)
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() || leaf.IsCA {
		return Key{}, errors.New("the signing certificate is not a P-384 leaf")
	}
	if len(body.CABundle) == 0 {
		return Key{}, errors.New("the document's cabundle is empty")
	}
	if err := checkChain(leaf, body.CABundle, expect.Root, issuedAt); err != nil {
		return Key{}, err
	}
	if err := checkSignature(key, cose); err != nil {
		return Key{}, err
	}
	if err := Fresh(issuedAt, expect.Now); err != nil {
		return Key{}, err
	}
	pin, err := checkPCRs(body.PCRs, expect)
	if err != nil {
		return Key{}, err
	}
	publicKey, err := KeyInUserData(body.UserData, expect.Environment)
	if err != nil {
		return Key{}, err
	}
	return Key{PublicKey: publicKey, TLS: body.PublicKey, Nonce: body.Nonce, IssuedAt: issuedAt, Pin: pin}, nil
}

func TimestampUnverified(document []byte) (time.Time, error) {
	var cose sign1
	if err := cbor.Unmarshal(document, &cose); err != nil || cose.Payload == nil {
		return time.Time{}, errors.New("the document is not a COSE_Sign1")
	}
	var body payload
	if err := cbor.Unmarshal(cose.Payload, &body); err != nil || body.Timestamp == 0 {
		return time.Time{}, errors.New("the document's payload carries no timestamp")
	}
	return time.UnixMilli(body.Timestamp).UTC(), nil
}

func checkChain(leaf *x509.Certificate, bundle [][]byte, root *x509.Certificate, at time.Time) error {
	chain := []*x509.Certificate{root}
	for _, der := range bundle[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("a cabundle certificate does not parse: %w", err)
		}
		chain = append(chain, cert)
	}
	chain = append(chain, leaf)
	for i := 1; i < len(chain); i++ {
		issuer, cert := chain[i-1], chain[i]
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || cert.CheckSignatureFrom(issuer) != nil {
			return fmt.Errorf("%s is not signed by %s", cert.Subject, issuer.Subject)
		}
	}
	for _, cert := range chain {
		if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
			return fmt.Errorf("%s was not valid when the document was issued", cert.Subject)
		}
	}
	return nil
}

func checkSignature(key *ecdsa.PublicKey, cose sign1) error {
	signed, err := cbor.Marshal([]any{"Signature1", cose.Protected, []byte{}, cose.Payload})
	if err != nil {
		return err
	}
	if len(cose.Signature) != 2*p384Coordinate {
		return errors.New("the document's signature is not 96 bytes")
	}
	r := new(big.Int).SetBytes(cose.Signature[:p384Coordinate])
	s := new(big.Int).SetBytes(cose.Signature[p384Coordinate:])
	sum := sha512.Sum384(signed)
	if !ecdsa.Verify(key, sum[:], r, s) {
		return errors.New("the document's signature does not verify")
	}
	return nil
}

func Fresh(issuedAt, now time.Time) error {
	if age := now.Sub(issuedAt); age > MaxAge {
		return fmt.Errorf("the document is %.0f minutes old", age.Minutes())
	}
	if ahead := issuedAt.Sub(now); ahead > MaxAhead {
		return fmt.Errorf("the document is %.0f minutes ahead of this clock", ahead.Minutes())
	}
	return nil
}

func checkPCRs(pcrs map[uint][]byte, expect Expectation) (Pin, error) {
	var hexed [3]string
	for i := range hexed {
		value, ok := pcrs[uint(i)]
		if !ok {
			return Pin{}, fmt.Errorf("the document has no PCR%d", i)
		}
		hexed[i] = hex.EncodeToString(value)
	}
	pcr0, pcr1, pcr2 := hexed[0], hexed[1], hexed[2]
	if pcr0 == zeroPCR && pcr1 == zeroPCR && pcr2 == zeroPCR {
		return Pin{}, errors.New("the enclave reports all-zero PCRs, so it runs in debug mode")
	}
	match, matched := Pin{}, false
	for _, pin := range expect.Pins {
		if pin.Environment != expect.Environment || !pin.names(pcr0, pcr1, pcr2) {
			continue
		}
		if pin.Revoked {
			return Pin{}, fmt.Errorf("the %s image %s is revoked", pin.Environment, pin.Name())
		}
		if !matched {
			match, matched = pin, true
		}
	}
	if !matched {
		return Pin{}, fmt.Errorf("%w: no %s pin names PCR0 %s", ErrUnpinned, expect.Environment, pcr0[:16])
	}
	return match, nil
}

func KeyInUserData(userData []byte, environment string) ([]byte, error) {
	prefix := []byte(UserDataPrefix + environment + "|")
	if len(userData) != len(prefix)+keyBytes || !bytes.Equal(userData[:len(prefix)], prefix) {
		return nil, fmt.Errorf("user_data does not name a %s key", environment)
	}
	return bytes.Clone(userData[len(prefix):]), nil
}
