package pinsig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"morse/backend/internal/exactjson"
)

// bundle is a Sigstore bundle v0.3 reduced to what keyless signing with
// Rekor v1 produces: one leaf certificate, one signed content, and one Rekor
// entry of that content's kind with both a signed entry timestamp and an
// inclusion proof. A Rekor v2 bundle shares the first three, and its entry
// is read by rekorv2 (v2.go).
type bundle struct {
	leafDER   []byte
	content   signed
	signature []byte
	entry     logEntry
}

// signed is the bundle's content: a message digest (cosign sign-blob) or a
// DSSE envelope (an in-toto attestation). Each has one Rekor body kind.
type signed interface{ isSigned() }

type messageSignature struct{ digest [32]byte }

type dsseEnvelope struct {
	payloadType string
	payload     []byte
}

func (messageSignature) isSigned() {}
func (dsseEnvelope) isSigned()     {}

type logEntry struct {
	logID          [32]byte
	logIndex       uint64
	integratedTime time.Time
	set            []byte
	proof          inclusionProof
	canonicalBody  []byte
	body           entryBody
}

type inclusionProof struct {
	index, treeSize uint64
	rootHash        [32]byte
	hashes          [][32]byte
	checkpoint      string
}

// entryBody is a parsed Rekor body. matches checks it names the bundle's
// content, signature, and certificate.
type entryBody interface {
	matches(content signed, signature, certDER []byte) error
}

// hashedRekord is the Rekor v1 hashedrekord 0.0.1 body: the blob's digest,
// the signature over it, and the signer's certificate.
type hashedRekord struct {
	digest    [32]byte
	signature []byte
	certDER   []byte
}

func (h hashedRekord) matches(content signed, signature, certDER []byte) error {
	ms, ok := content.(messageSignature)
	switch {
	case !ok || h.digest != ms.digest:
		return fmt.Errorf("%w: names another digest", ErrBody)
	case !bytes.Equal(h.signature, signature):
		return fmt.Errorf("%w: names another signature", ErrBody)
	case !bytes.Equal(h.certDER, certDER):
		return fmt.Errorf("%w: names another certificate", ErrBody)
	}
	return nil
}

// dsseRekord is the Rekor v1 dsse 0.0.1 body: the payload's digest and the
// envelope's one signature with the signer's certificate. Its envelopeHash
// is Rekor's digest of the envelope text as the signer uploaded it, which
// sigstore-go does not check either; the payload hash and the signature
// already bind everything the envelope says.
type dsseRekord struct {
	payloadHash [32]byte
	signature   []byte
	certDER     []byte
}

func (d dsseRekord) matches(content signed, signature, certDER []byte) error {
	env, ok := content.(dsseEnvelope)
	switch {
	case !ok || d.payloadHash != sha256.Sum256(env.payload):
		return fmt.Errorf("%w: names another payload", ErrBody)
	case !bytes.Equal(d.signature, signature):
		return fmt.Errorf("%w: names another signature", ErrBody)
	case !bytes.Equal(d.certDER, certDER):
		return fmt.Errorf("%w: names another certificate", ErrBody)
	}
	return nil
}

// pae is DSSE's pre-authentication encoding, what the leaf signs for an
// envelope.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// The bundle, its Rekor body, and the statement under them are the router's
// text, read through exactjson so the browser's port reads the same values:
// exact keys, null present, no whitespace in base64, and integers in the
// range both sides hold. The browser's regexes below are copied verbatim.
var (
	pemCertificate = regexp.MustCompile(`^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$`)
	lowerHex32     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	bundleV03       = "application/vnd.dev.sigstore.bundle.v0.3+json"
	bundleV03Legacy = "application/vnd.dev.sigstore.bundle+json;version=0.3"
)

func parseBundle(raw []byte) (bundle, error) {
	b, err := readBundle(raw)
	if err != nil {
		return bundle{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	switch b.content.(type) {
	case messageSignature:
		b.entry.body, err = parseHashedRekord(b.entry.canonicalBody)
	case dsseEnvelope:
		b.entry.body, err = parseDSSERekord(b.entry.canonicalBody)
	}
	if err != nil {
		return bundle{}, err
	}
	return b, nil
}

// readBundle reads everything but the Rekor body, whose errors are ErrBody.
func readBundle(raw []byte) (bundle, error) {
	b, e, kind, err := readSigned(raw)
	if err != nil {
		return bundle{}, err
	}
	return readV1Entry(b, e, kind)
}

// readSigned reads what a bundle carries whichever log holds its entry: the
// media type, the leaf, the signed content, and exactly one log entry, which
// it returns unread with the Rekor body kind that content is logged as.
func readSigned(raw []byte) (bundle, exactjson.Value, string, error) {
	j := exactjson.Parse(raw)
	mediaType := j.Key("mediaType").Text()
	vm := j.Key("verificationMaterial")
	hasSignature, hasEnvelope := j.Has("messageSignature"), j.Has("dsseEnvelope")
	if err := j.Err(); err != nil {
		return bundle{}, exactjson.Value{}, "", err
	}
	switch {
	case mediaType != bundleV03 && mediaType != bundleV03Legacy:
		return bundle{}, exactjson.Value{}, "", fmt.Errorf("media type %q is not bundle v0.3", mediaType)
	case !hasSignature && !hasEnvelope:
		return bundle{}, exactjson.Value{}, "", errors.New("neither a message signature nor a DSSE envelope")
	case hasSignature && hasEnvelope:
		return bundle{}, exactjson.Value{}, "", errors.New("both a message signature and a DSSE envelope")
	case !vm.Has("certificate"):
		return bundle{}, exactjson.Value{}, "", errors.New("no leaf certificate")
	}
	var entries []exactjson.Value
	if vm.Has("tlogEntries") {
		entries = vm.Key("tlogEntries").Items()
	}
	if len(entries) != 1 {
		return bundle{}, exactjson.Value{}, "", fmt.Errorf("%d log entries, not one", len(entries))
	}
	b := bundle{leafDER: vm.Key("certificate").Key("rawBytes").Bytes()}
	var kind string
	if hasSignature {
		ms := j.Key("messageSignature")
		digest := ms.Key("messageDigest")
		algorithm, value, signature := digest.Key("algorithm").Text(), digest.Key("digest").Bytes(), ms.Key("signature").Bytes()
		if err := j.Err(); err != nil {
			return bundle{}, exactjson.Value{}, "", err
		}
		if algorithm != "SHA2_256" || len(value) != 32 {
			return bundle{}, exactjson.Value{}, "", errors.New("the message digest is not a SHA2_256 digest")
		}
		b.content, b.signature, kind = messageSignature{digest: [32]byte(value)}, signature, "hashedrekord"
	} else {
		env := j.Key("dsseEnvelope")
		payload, payloadType, signatures := env.Key("payload").Bytes(), env.Key("payloadType").Text(), env.Key("signatures").Items()
		if err := j.Err(); err != nil {
			return bundle{}, exactjson.Value{}, "", err
		}
		if len(signatures) != 1 || payloadType == "" {
			return bundle{}, exactjson.Value{}, "", errors.New("the DSSE envelope does not carry one signature and a payload type")
		}
		b.content, b.signature, kind = dsseEnvelope{payloadType: payloadType, payload: payload}, signatures[0].Key("sig").Bytes(), "dsse"
	}
	if err := j.Err(); err != nil {
		return bundle{}, exactjson.Value{}, "", err
	}
	return b, entries[0], kind, nil
}

// readV1Entry reads a Rekor v1 entry of kind, with both a signed entry
// timestamp and an inclusion proof, into b.
func readV1Entry(b bundle, e exactjson.Value, kind string) (bundle, error) {
	kindVersion := e.Key("kindVersion")
	entryKind, version := kindVersion.Key("kind").Text(), kindVersion.Key("version").Text()
	logID := e.Key("logId").Key("keyId").Bytes()
	logIndex, integratedTime := e.Key("logIndex").Uint(), e.Key("integratedTime").Uint()
	canonical := e.Key("canonicalizedBody").Bytes()
	if err := e.Err(); err != nil {
		return bundle{}, err
	}
	switch {
	case entryKind != kind || version != "0.0.1":
		return bundle{}, fmt.Errorf("entry kind %s %s is not %s 0.0.1", entryKind, version, kind)
	case len(logID) != 32:
		return bundle{}, errors.New("log id is not 32 bytes")
	case !e.Has("inclusionPromise"):
		return bundle{}, errors.New("no signed entry timestamp")
	case !e.Has("inclusionProof"):
		return bundle{}, errors.New("no inclusion proof with a root hash and a checkpoint")
	case integratedTime == 0:
		return bundle{}, errors.New("no integrated time")
	}
	set := e.Key("inclusionPromise").Key("signedEntryTimestamp").Bytes()
	p := e.Key("inclusionProof")
	proof := inclusionProof{
		index:      p.Key("logIndex").Uint(),
		treeSize:   p.Key("treeSize").Uint(),
		checkpoint: p.Key("checkpoint").Key("envelope").Text(),
	}
	rootHash := p.Key("rootHash").Bytes()
	var hashes []exactjson.Value
	if p.Has("hashes") {
		hashes = p.Key("hashes").Items()
	}
	for _, h := range hashes {
		hash := h.Bytes()
		if len(hash) != 32 {
			if err := e.Err(); err != nil {
				return bundle{}, err
			}
			return bundle{}, errors.New("an inclusion proof hash is not 32 bytes")
		}
		proof.hashes = append(proof.hashes, [32]byte(hash))
	}
	if err := e.Err(); err != nil {
		return bundle{}, err
	}
	switch {
	case len(set) == 0:
		return bundle{}, errors.New("no signed entry timestamp")
	case len(rootHash) != 32 || proof.checkpoint == "":
		return bundle{}, errors.New("no inclusion proof with a root hash and a checkpoint")
	}
	proof.rootHash = [32]byte(rootHash)
	b.entry = logEntry{
		logID:          [32]byte(logID),
		logIndex:       logIndex,
		integratedTime: time.Unix(int64(integratedTime), 0).UTC(),
		set:            set,
		proof:          proof,
		canonicalBody:  canonical,
	}
	return b, nil
}

// body starts a read of a Rekor body, which must be UTF-8 JSON of kind 0.0.1.
func body(canonical []byte, kind string) (exactjson.Value, error) {
	if !utf8.Valid(canonical) {
		return exactjson.Value{}, fmt.Errorf("%w: not UTF-8", ErrBody)
	}
	j := exactjson.Parse(canonical)
	bodyKind, version := j.Key("kind").Text(), j.Key("apiVersion").Text()
	if err := j.Err(); err != nil {
		return exactjson.Value{}, fmt.Errorf("%w: %v", ErrBody, err)
	}
	if bodyKind != kind || version != "0.0.1" {
		return exactjson.Value{}, fmt.Errorf("%w: kind %s %s is not %s 0.0.1", ErrBody, bodyKind, version, kind)
	}
	return j, nil
}

func parseHashedRekord(canonical []byte) (hashedRekord, error) {
	j, err := body(canonical, "hashedrekord")
	if err != nil {
		return hashedRekord{}, err
	}
	spec := j.Key("spec")
	digest, err := sha256Hex(spec.Key("data").Key("hash"))
	if err != nil {
		return hashedRekord{}, err
	}
	signature := spec.Key("signature")
	content := signature.Key("content").Bytes()
	certDER, err := onePEMCertificate(signature.Key("publicKey").Key("content"))
	if err != nil {
		return hashedRekord{}, err
	}
	return hashedRekord{digest: digest, signature: content, certDER: certDER}, nil
}

func parseDSSERekord(canonical []byte) (dsseRekord, error) {
	j, err := body(canonical, "dsse")
	if err != nil {
		return dsseRekord{}, err
	}
	spec := j.Key("spec")
	payloadHash, err := sha256Hex(spec.Key("payloadHash"))
	if err != nil {
		return dsseRekord{}, err
	}
	signatures := spec.Key("signatures").Items()
	if err := j.Err(); err != nil {
		return dsseRekord{}, fmt.Errorf("%w: %v", ErrBody, err)
	}
	if len(signatures) != 1 {
		return dsseRekord{}, fmt.Errorf("%w: %d signatures, not one", ErrBody, len(signatures))
	}
	signature := signatures[0].Key("signature").Bytes()
	certDER, err := onePEMCertificate(signatures[0].Key("verifier"))
	if err != nil {
		return dsseRekord{}, err
	}
	return dsseRekord{payloadHash: payloadHash, signature: signature, certDER: certDER}, nil
}

// sha256Hex reads a Rekor hash object: sha256 as 64 lowercase hex digits.
func sha256Hex(h exactjson.Value) ([32]byte, error) {
	algorithm, value := h.Key("algorithm").Text(), h.Key("value").Text()
	if err := h.Err(); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrBody, err)
	}
	if algorithm != "sha256" {
		return [32]byte{}, fmt.Errorf("%w: hash algorithm %q is not sha256", ErrBody, algorithm)
	}
	if !lowerHex32.MatchString(value) {
		return [32]byte{}, fmt.Errorf("%w: hash value is not 64 lowercase hex digits", ErrBody)
	}
	digest, _ := hex.DecodeString(value)
	return [32]byte(digest), nil
}

// onePEMCertificate reads a base64 field holding one PEM certificate, in
// the shape the browser's regex admits: no headers, and \n line ends.
func onePEMCertificate(content exactjson.Value) ([]byte, error) {
	pem := content.Bytes()
	if err := content.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBody, err)
	}
	m := pemCertificate.FindSubmatch(pem)
	if m == nil {
		return nil, fmt.Errorf("%w: the verifier is not one PEM certificate", ErrBody)
	}
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(m[1]), "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("%w: the verifier is not one PEM certificate", ErrBody)
	}
	return der, nil
}
