// Package pinsig verifies, offline, that a pins statement was signed by our
// pins workflow through Sigstore keyless signing and logged in Rekor v1.
//
// The enclave embeds a Sigstore trusted root and the identity its workflow
// signs with. Verify refuses unless the bundle's certificate chains to a
// Fulcio CA in the root, the Rekor entry carries both a signed entry
// timestamp and an inclusion proof under a log key in the root, the entry's
// body names the statement, the signature, and the certificate the bundle
// carries, and the certificate's Fulcio extensions equal the identity.
package pinsig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
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

// Identity is what the enclave pins about the signer. Every field is read
// from the leaf certificate's Fulcio extensions; the SAN must also equal
// BuildSignerURI, the runner environment must be github-hosted, the build
// config digest must equal the source repository digest, and the run
// invocation must be the first attempt of a run in the source repository.
type Identity struct {
	Issuer              string
	BuildSignerURI      string
	BuildConfigURI      string
	SourceRepositoryURI string
	SourceRepositoryID  string
	SourceOwnerID       string
	Ref                 string
	Triggers            []string
}

// Record is what a verified bundle proves about its blob: when Rekor logged
// it, which commit of the source repository the signing run built from, and
// which run signed it.
type Record struct {
	IntegratedTime   time.Time
	SourceDigest     string
	RunInvocationURI string
}

// VerifyBundle checks that bundle is a Sigstore bundle whose certificate,
// log entry, and signature all vouch for blob under root and id.
func VerifyBundle(blob, bundle []byte, root TrustRoot, id Identity) (Record, error) {
	b, err := parseBundle(bundle)
	if err != nil {
		return Record{}, err
	}
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
	digest := sha256.Sum256(blob)
	if err := b.entry.body.matches(digest, b.signature, b.leafDER); err != nil {
		return Record{}, err
	}
	if digest != b.digest {
		return Record{}, fmt.Errorf("%w: the message digest is not the blob's", ErrBody)
	}
	leaf, err := verifyChain(b.leafDER, root, b.entry.integratedTime)
	if err != nil {
		return Record{}, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], b.signature) {
		return Record{}, fmt.Errorf("%w: the leaf key did not sign the blob", ErrSignature)
	}
	sourceDigest, runInvocation, err := checkIdentity(leaf, id)
	if err != nil {
		return Record{}, err
	}
	return Record{IntegratedTime: b.entry.integratedTime, SourceDigest: sourceDigest, RunInvocationURI: runInvocation}, nil
}

// Verify checks the bundle over statement and parses the statement, which
// must name the commit the signing run built from.
func Verify(statement, bundle []byte, root TrustRoot, id Identity) (Statement, time.Time, error) {
	rec, err := VerifyBundle(statement, bundle, root, id)
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
	return st, rec.IntegratedTime, nil
}

type window struct{ start, end time.Time }

func (w window) contains(t time.Time) bool {
	return !t.Before(w.start) && (w.end.IsZero() || !t.After(w.end))
}
