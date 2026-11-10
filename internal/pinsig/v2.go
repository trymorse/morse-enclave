package pinsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"morse/backend/internal/sigstore/rekorv2"
)

// VerifyBundleV2 checks that bundle is a Sigstore message-signature bundle
// over blob whose one log entry is a hashedrekord v0.0.2 entry in a Rekor v2
// shard of root, and that the entry, its certificate and its signature all
// vouch for blob under id. It refuses a Rekor v1 entry with ErrBundle,
// whoever signed it: Rekor v1 has no end date in Sigstore's trusted root, so
// only this refusal keeps a v1 statement out.
//
// rekorv2.Verify checks the shard, the inclusion proof, the shard's
// signature on the checkpoint and at least witnesses.K() cosignatures,
// counted once per witness name and once per operator. Rekor v2 entries
// carry no integrated time, so the certificate gives the time bounds. Its
// chain is verified at its NotBefore. At least K counted cosignatures must be
// at or before its NotAfter, so K witnesses saw the signature inside the
// certificate's window, and one witness's clock cannot move that bound. The
// shard's validFor is read at the K-th earliest counted cosignature. The
// Record's NotBefore, which the signature is never earlier than, is the time
// Admit measures age from.
//
// The identity is read before the log, so a bundle from another signer says
// so whichever log it names, and an old image's statements are refused as
// ErrIdentity.
func VerifyBundleV2(blob, bundle []byte, root TrustRoot, id Identity, witnesses rekorv2.WitnessPolicy) (Record, error) {
	b, entry, kind, err := readSigned(bundle)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	ms, ok := b.content.(messageSignature)
	if !ok {
		return Record{}, fmt.Errorf("%w: a DSSE envelope is not a message signature", ErrBundle)
	}
	digest := sha256.Sum256(blob)
	if ms.digest != digest {
		return Record{}, fmt.Errorf("%w: the message digest is not the blob's", ErrBody)
	}
	leaf, err := x509.ParseCertificate(b.leafDER)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	signer, err := checkIdentity(leaf, id)
	if err != nil {
		return Record{}, err
	}
	kindVersion := entry.Key("kindVersion")
	entryKind, version := kindVersion.Key("kind").Text(), kindVersion.Key("version").Text()
	if err := entry.Err(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if entryKind != kind || version != "0.0.2" {
		return Record{}, fmt.Errorf("%w: entry kind %s %s is not %s 0.0.2 in a Rekor v2 shard", ErrBundle, entryKind, version, kind)
	}
	logged, err := rekorv2.Verify(entry.Raw(), root.shards, witnesses, rekorv2.Witnessed())
	if err != nil {
		var r *rekorv2.Refusal
		if errors.As(err, &r) && r.Reason == rekorv2.NotThisRecord {
			return Record{}, fmt.Errorf("%w: %v", ErrBody, err)
		}
		return Record{}, fmt.Errorf("%w: %v", ErrLog, err)
	}
	body := logged.Body()
	switch {
	case body.Digest != digest:
		return Record{}, fmt.Errorf("%w: names another digest", ErrBody)
	case !bytes.Equal(body.Signature, b.signature):
		return Record{}, fmt.Errorf("%w: names another signature", ErrBody)
	case !bytes.Equal(body.Certificate, b.leafDER):
		return Record{}, fmt.Errorf("%w: names another certificate", ErrBody)
	}
	if _, err := verifyChain(b.leafDER, root, leaf.NotBefore); err != nil {
		return Record{}, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], b.signature) {
		return Record{}, fmt.Errorf("%w: the leaf key did not sign the content", ErrSignature)
	}
	k, cosigners := witnesses.K(), logged.Checkpoint().Cosigners()
	if k < 1 || len(cosigners) < k || cosigners[k-1].Time.After(leaf.NotAfter) {
		return Record{}, fmt.Errorf("%w: fewer than %d counted cosignatures at or before the certificate's NotAfter %s", ErrLog, k, leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return Record{NotBefore: leaf.NotBefore, SourceDigest: signer.sourceDigest, RunInvocationURI: signer.runInvocation, Ref: signer.ref}, nil
}
