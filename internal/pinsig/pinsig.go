// Package pinsig verifies, offline, that a blob or a DSSE statement was
// signed by a GitHub Actions workflow through Sigstore keyless signing.
//
// The enclave embeds a Sigstore trusted root and the identity its workflow
// signs with. Verify and VerifyVendor take Morse's statements, which the
// public signer logs in Rekor v2 only, through VerifyBundleV2: the entry is
// in a v2 shard of the root and carries enough witness cosignatures. VerifyDSSE
// takes Tinfoil's router provenance, which Tinfoil logs in Rekor v1, so the
// v1 rule is per signer and not package-wide: there the entry carries both a
// signed entry timestamp and an inclusion proof under a v1 log key in the
// root. Either way the bundle's certificate chains to a Fulcio CA in the
// root, the entry's body names the signed content, the signature, and the
// certificate the bundle carries, and the certificate's Fulcio extensions
// equal the identity.
package pinsig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"time"

	"morse/backend/internal/sigstore/rekorv2"
)

var (
	ErrTrustRoot   = errors.New("pinsig: trust root")
	ErrBundle      = errors.New("pinsig: bundle")
	ErrLog         = errors.New("pinsig: log")
	ErrBody        = errors.New("pinsig: log entry body")
	ErrCertificate = errors.New("pinsig: certificate")
	ErrSignature   = errors.New("pinsig: signature")
	ErrIdentity    = errors.New("pinsig: identity")
	ErrStatement   = errors.New("pinsig: statement")
	ErrAdmit       = errors.New("pinsig: admit")
)

// Identity is what a verifier pins about a GitHub Actions signer. Every
// field is read from the leaf certificate's Fulcio extensions. The source
// ref must satisfy Ref, and the SAN, the build signer URI and the build
// config URI must all equal SourceRepositoryURI + "/" + Workflow + "@" + ref,
// so the workflow that signed is the one that ran, at that ref. The runner
// environment must be github-hosted, the build config digest must equal the
// source repository digest, and the run invocation must be the first attempt
// of a run in the source repository.
type Identity struct {
	Issuer              string
	SourceRepositoryURI string
	SourceRepositoryID  string
	SourceOwnerID       string
	Workflow            string
	Ref                 RefRule
	Triggers            []string
}

// RefRule says which source refs an identity admits. ExactRef and
// SemverTags build the only two.
type RefRule interface{ admits(ref string) bool }

type exactRef string

func (r exactRef) admits(ref string) bool { return ref == string(r) }

type semverTags struct{}

// Each component has at most nine digits, so the browser's port, whose
// numbers lose precision past 2^53, orders tags as this side does.
var semverTag = regexp.MustCompile(`^refs/tags/v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func (semverTags) admits(ref string) bool { return semverTag.MatchString(ref) }

// ExactRef admits one ref, such as refs/heads/main.
func ExactRef(ref string) RefRule { return exactRef(ref) }

// SemverTags admits refs/tags/vMAJOR.MINOR.PATCH with no prerelease or build
// suffix, no leading zero, and at most nine digits per component.
func SemverTags() RefRule { return semverTags{} }

// Record is what a verified bundle proves about its content: when Rekor v1
// logged it (zero for a Rekor v2 entry, which carries no such time), when
// its certificate was issued, which commit of the source repository the
// signing run built from, which run signed it, and at which source ref.
type Record struct {
	IntegratedTime   time.Time
	NotBefore        time.Time
	SourceDigest     string
	RunInvocationURI string
	Ref              string
}

// Envelope is a verified DSSE envelope's content.
type Envelope struct {
	PayloadType string
	Payload     []byte
}

// VerifyBundle checks that bundle is a Sigstore message-signature bundle
// whose certificate, Rekor v1 log entry, and signature all vouch for blob
// under root and id. It refuses a DSSE bundle. Verify and VerifyVendor do
// not call it: Morse's statements are logged in Rekor v2 (VerifyBundleV2).
func VerifyBundle(blob, bundle []byte, root TrustRoot, id Identity) (Record, error) {
	b, err := parseBundle(bundle)
	if err != nil {
		return Record{}, err
	}
	ms, ok := b.content.(messageSignature)
	if !ok {
		return Record{}, fmt.Errorf("%w: a DSSE envelope is not a message signature", ErrBundle)
	}
	digest := sha256.Sum256(blob)
	if ms.digest != digest {
		return Record{}, fmt.Errorf("%w: the message digest is not the blob's", ErrBody)
	}
	return verify(b, root, id, digest)
}

// VerifyDSSE checks that bundle is a Sigstore DSSE bundle whose certificate,
// log entry, and signature all vouch for its envelope under root and id: the
// leaf signed PAE(payloadType, payload), and the Rekor dsse body's payload
// hash is the payload's. It refuses a message-signature bundle.
func VerifyDSSE(bundle []byte, root TrustRoot, id Identity) (Envelope, Record, error) {
	b, err := parseBundle(bundle)
	if err != nil {
		return Envelope{}, Record{}, err
	}
	env, ok := b.content.(dsseEnvelope)
	if !ok {
		return Envelope{}, Record{}, fmt.Errorf("%w: a message signature is not a DSSE envelope", ErrBundle)
	}
	rec, err := verify(b, root, id, sha256.Sum256(pae(env.payloadType, env.payload)))
	if err != nil {
		return Envelope{}, Record{}, err
	}
	return Envelope{PayloadType: env.payloadType, Payload: env.payload}, rec, nil
}

// verify runs the checks both kinds share: the log key, the signed entry
// timestamp, the inclusion proof, the body against the bundle's own content,
// the chain at the integrated time, the leaf's signature over signed, and
// the identity.
func verify(b bundle, root TrustRoot, id Identity, signed [32]byte) (Record, error) {
	key, ok := root.logs[b.entry.logID]
	if !ok || !key.window.contains(b.entry.integratedTime) {
		return Record{}, fmt.Errorf("%w: entry names no log key valid at its integrated time", ErrLog)
	}
	if err := verifySET(b.entry, key.key); err != nil {
		return Record{}, err
	}
	if err := verifyInclusion(b.entry, key.key); err != nil {
		return Record{}, err
	}
	if err := b.entry.body.matches(b.content, b.signature, b.leafDER); err != nil {
		return Record{}, err
	}
	leaf, err := verifyChain(b.leafDER, root, b.entry.integratedTime)
	if err != nil {
		return Record{}, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, signed[:], b.signature) {
		return Record{}, fmt.Errorf("%w: the leaf key did not sign the content", ErrSignature)
	}
	signer, err := checkIdentity(leaf, id)
	if err != nil {
		return Record{}, err
	}
	return Record{IntegratedTime: b.entry.integratedTime, NotBefore: leaf.NotBefore, SourceDigest: signer.sourceDigest, RunInvocationURI: signer.runInvocation, Ref: signer.ref}, nil
}

// Verify checks the Rekor v2 bundle over statement (VerifyBundleV2) and
// parses the statement, which must name the commit the signing run built
// from. The time it returns is the certificate's NotBefore, for Admit.
func Verify(statement, bundle []byte, root TrustRoot, id Identity, witnesses rekorv2.WitnessPolicy) (Statement, time.Time, error) {
	rec, err := VerifyBundleV2(statement, bundle, root, id, witnesses)
	if err != nil {
		return Statement{}, time.Time{}, err
	}
	st, err := ParseStatement(statement)
	if err != nil {
		return Statement{}, time.Time{}, err
	}
	if st.PinsCommit != rec.SourceDigest {
		return Statement{}, time.Time{}, fmt.Errorf("%w: pins_commit %s is not the commit the signer built from, %s", ErrStatement, st.PinsCommit, rec.SourceDigest)
	}
	return st, rec.NotBefore, nil
}

type window struct{ start, end time.Time }

func (w window) contains(t time.Time) bool {
	return !t.Before(w.start) && (w.end.IsZero() || !t.After(w.end))
}
