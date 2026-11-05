package door

import (
	"fmt"

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

func (a Answer) Record() Record {
	return Record{Type: RecordType, Environment: a.Environment, Document: a.Document, SPKISHA256: a.SPKISHA256, Origin: a.Origin}
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
