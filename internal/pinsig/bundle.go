package pinsig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"
)

// bundle is a Sigstore bundle v0.3 reduced to what a keyless sign-blob with
// Rekor v1 produces: one leaf certificate, one hashedrekord entry with both
// a signed entry timestamp and an inclusion proof, and a message signature.
type bundle struct {
	leafDER   []byte
	digest    [32]byte
	signature []byte
	entry     logEntry
}

type logEntry struct {
	logID          [32]byte
	logIndex       uint64
	integratedTime time.Time
	set            []byte
	proof          inclusionProof
	canonicalBody  []byte
	body           hashedRekord
}

type inclusionProof struct {
	index, treeSize uint64
	rootHash        [32]byte
	hashes          [][32]byte
	checkpoint      string
}

// hashedRekord is the Rekor v1 hashedrekord 0.0.1 body: the blob's digest,
// the signature over it, and the signer's certificate.
type hashedRekord struct {
	digest    [32]byte
	signature []byte
	certDER   []byte
}

func (h hashedRekord) matches(digest [32]byte, signature, certDER []byte) error {
	switch {
	case h.digest != digest:
		return fmt.Errorf("%w: names another digest", ErrBody)
	case !bytes.Equal(h.signature, signature):
		return fmt.Errorf("%w: names another signature", ErrBody)
	case !bytes.Equal(h.certDER, certDER):
		return fmt.Errorf("%w: names another certificate", ErrBody)
	}
	return nil
}

// protoUint is an unsigned integer that protobuf JSON writes as a string.
type protoUint uint64

func (n *protoUint) UnmarshalJSON(b []byte) error {
	s := string(bytes.Trim(b, `"`))
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*n = protoUint(v)
	return nil
}

type bundleJSON struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes []byte `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries []struct {
			LogIndex protoUint `json:"logIndex"`
			LogID    struct {
				KeyID []byte `json:"keyId"`
			} `json:"logId"`
			KindVersion struct {
				Kind    string `json:"kind"`
				Version string `json:"version"`
			} `json:"kindVersion"`
			IntegratedTime   protoUint `json:"integratedTime"`
			InclusionPromise *struct {
				SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
			} `json:"inclusionPromise"`
			InclusionProof *struct {
				LogIndex   protoUint `json:"logIndex"`
				RootHash   []byte    `json:"rootHash"`
				TreeSize   protoUint `json:"treeSize"`
				Hashes     [][]byte  `json:"hashes"`
				Checkpoint struct {
					Envelope string `json:"envelope"`
				} `json:"checkpoint"`
			} `json:"inclusionProof"`
			CanonicalizedBody []byte `json:"canonicalizedBody"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
	DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
}

type hashedRekordJSON struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   []byte `json:"content"`
			PublicKey struct {
				Content []byte `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

func parseBundle(raw []byte) (bundle, error) {
	var j bundleJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return bundle{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if j.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" && j.MediaType != "application/vnd.dev.sigstore.bundle+json;version=0.3" {
		return bundle{}, fmt.Errorf("%w: media type %q is not bundle v0.3", ErrBundle, j.MediaType)
	}
	vm := j.VerificationMaterial
	switch {
	case j.DSSEEnvelope != nil:
		return bundle{}, fmt.Errorf("%w: a DSSE envelope is not a message signature", ErrBundle)
	case j.MessageSignature == nil:
		return bundle{}, fmt.Errorf("%w: no message signature", ErrBundle)
	case vm.Certificate == nil:
		return bundle{}, fmt.Errorf("%w: no leaf certificate", ErrBundle)
	case len(vm.TlogEntries) != 1:
		return bundle{}, fmt.Errorf("%w: %d log entries, not one", ErrBundle, len(vm.TlogEntries))
	}
	ms := j.MessageSignature
	if ms.MessageDigest.Algorithm != "SHA2_256" || len(ms.MessageDigest.Digest) != 32 {
		return bundle{}, fmt.Errorf("%w: the message digest is not a SHA2_256 digest", ErrBundle)
	}
	e := vm.TlogEntries[0]
	switch {
	case e.KindVersion.Kind != "hashedrekord" || e.KindVersion.Version != "0.0.1":
		return bundle{}, fmt.Errorf("%w: entry kind %s %s is not hashedrekord 0.0.1", ErrBundle, e.KindVersion.Kind, e.KindVersion.Version)
	case len(e.LogID.KeyID) != 32:
		return bundle{}, fmt.Errorf("%w: log id is not 32 bytes", ErrBundle)
	case e.InclusionPromise == nil || len(e.InclusionPromise.SignedEntryTimestamp) == 0:
		return bundle{}, fmt.Errorf("%w: no signed entry timestamp", ErrBundle)
	case e.InclusionProof == nil || len(e.InclusionProof.RootHash) != 32 || e.InclusionProof.Checkpoint.Envelope == "":
		return bundle{}, fmt.Errorf("%w: no inclusion proof with a root hash and a checkpoint", ErrBundle)
	case e.IntegratedTime == 0:
		return bundle{}, fmt.Errorf("%w: no integrated time", ErrBundle)
	}
	body, err := parseHashedRekord(e.CanonicalizedBody)
	if err != nil {
		return bundle{}, err
	}
	proof := inclusionProof{
		index:      uint64(e.InclusionProof.LogIndex),
		treeSize:   uint64(e.InclusionProof.TreeSize),
		rootHash:   [32]byte(e.InclusionProof.RootHash),
		checkpoint: e.InclusionProof.Checkpoint.Envelope,
	}
	for _, h := range e.InclusionProof.Hashes {
		if len(h) != 32 {
			return bundle{}, fmt.Errorf("%w: an inclusion proof hash is not 32 bytes", ErrBundle)
		}
		proof.hashes = append(proof.hashes, [32]byte(h))
	}
	return bundle{
		leafDER:   vm.Certificate.RawBytes,
		digest:    [32]byte(ms.MessageDigest.Digest),
		signature: ms.Signature,
		entry: logEntry{
			logID:          [32]byte(e.LogID.KeyID),
			logIndex:       uint64(e.LogIndex),
			integratedTime: time.Unix(int64(e.IntegratedTime), 0).UTC(),
			set:            e.InclusionPromise.SignedEntryTimestamp,
			proof:          proof,
			canonicalBody:  e.CanonicalizedBody,
			body:           body,
		},
	}, nil
}

func parseHashedRekord(canonical []byte) (hashedRekord, error) {
	var j hashedRekordJSON
	if err := json.Unmarshal(canonical, &j); err != nil {
		return hashedRekord{}, fmt.Errorf("%w: %v", ErrBody, err)
	}
	if j.Kind != "hashedrekord" || j.APIVersion != "0.0.1" {
		return hashedRekord{}, fmt.Errorf("%w: kind %s %s is not hashedrekord 0.0.1", ErrBody, j.Kind, j.APIVersion)
	}
	if j.Spec.Data.Hash.Algorithm != "sha256" {
		return hashedRekord{}, fmt.Errorf("%w: hash algorithm %q is not sha256", ErrBody, j.Spec.Data.Hash.Algorithm)
	}
	digest, err := hex.DecodeString(j.Spec.Data.Hash.Value)
	if err != nil || len(digest) != 32 {
		return hashedRekord{}, fmt.Errorf("%w: hash value is not 64 hex digits", ErrBody)
	}
	block, rest := pem.Decode(j.Spec.Signature.PublicKey.Content)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return hashedRekord{}, fmt.Errorf("%w: public key is not one PEM certificate", ErrBody)
	}
	return hashedRekord{digest: [32]byte(digest), signature: j.Spec.Signature.Content, certDER: block.Bytes}, nil
}
