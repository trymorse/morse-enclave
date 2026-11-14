package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

const VendorPinsNoncePrefix = "morse-vendor-pins-v1|"

// VendorPinsNonce is the nonce of the document GET /v1/attestation?model= carries in vendor_pins.document: the
// caller's nonce and the vendor pin set the worker judged the report by. statementSHA256 is "embedded" for the set
// compiled into the image. The fields are a JSON array after the prefix, so no field's bytes can pass for another's.
func VendorPinsNonce(nonce string, sequence uint64, statementSHA256 string) []byte {
	fields, _ := json.Marshal([]any{nonce, sequence, statementSHA256})
	sum := sha256.Sum256(append([]byte(VendorPinsNoncePrefix), fields...))
	return sum[:]
}

// VendorPins checks document as Document does and that it names the vendor pin set a reply reported for nonce, so
// the attested image held that set when it answered.
func VendorPins(document []byte, expect Expectation, nonce string, sequence uint64, statementSHA256 string) (Key, error) {
	key, err := Document(document, expect)
	if err != nil {
		return Key{}, err
	}
	if !bytes.Equal(key.Nonce, VendorPinsNonce(nonce, sequence, statementSHA256)) {
		return Key{}, errors.New("the document's nonce does not name this nonce and vendor pin set")
	}
	return key, nil
}
