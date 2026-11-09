package door

import (
	"encoding/json"

	"fmt"
	"morse/backend/internal/sigstore/tuf"

	"github.com/fxamacker/cbor/v2"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/seal"
)

const RecordType = "morse-door-boot-v1"

type Record struct {
	Type        string       `json:"type"`
	Environment string       `json:"environment"`
	Document    []byte       `json:"document"`
	SPKISHA256  string       `json:"spki_sha256"`
	Origin      AnswerOrigin `json:"origin"`
}

func (r Record) Boot() (seal.KeyID, error) {
	var cose struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(r.Document, &cose); err != nil {
		return seal.KeyID{}, fmt.Errorf("the document is not a COSE_Sign1: %w", err)
	}
	var body struct {
		UserData []byte `cbor:"user_data"`
	}
	if err := cbor.Unmarshal(cose.Payload, &body); err != nil {
		return seal.KeyID{}, fmt.Errorf("the document's payload does not parse: %w", err)
	}
	key, err := verify.KeyInUserData(body.UserData, r.Environment)
	if err != nil {
		return seal.KeyID{}, err
	}
	return seal.KeyIDOf(key), nil
}

// Logged names one entry in a Rekor v2 shard: a receipt on the wire.
type Logged struct {
	Log   string `json:"log"`
	Index uint64 `json:"index"`
}

// Entry is what POST /door/entry answers, the parts of a hashedrekord
// v0.0.2 request: the record certificate, H, and a fresh signature over H.
type Entry struct {
	Certificate []byte `json:"certificate"`
	Digest      []byte `json:"digest"`
	Signature   []byte `json:"signature"`
}

// Proof is the body of PUT /door/record: Rekor v2's TransparencyLogEntry
// for this custody's entry, and the TUF metadata that names the shard.
type Proof struct {
	Entry json.RawMessage `json:"entry"`
	TUF   tuf.Set         `json:"tuf"`
}
