package verify_test

import (
	"strings"
	"testing"
	"time"

	"morse/backend/internal/nitro/verify"
)

func TestVendorPinsAcceptsOnlyTheDocumentThatNamesTheNonceAndTheSetTheReplyReports(t *testing.T) {
	f := newForge(t)
	publicKey := somePublicKey()
	nonce, statement := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	document := f.document(documentOptions{timestamp: f.now, publicKey: publicKey, nonce: verify.VendorPinsNonce(nonce, 326, statement)})
	expect := f.expect(f.now.Add(time.Minute))
	key, err := verify.VendorPins(document, expect, nonce, 326, statement)
	if err != nil || string(key.PublicKey) != string(publicKey) {
		t.Fatalf("the bound document: key %x, %v", key.PublicKey, err)
	}
	for name, claim := range map[string]struct {
		nonce     string
		sequence  uint64
		statement string
	}{
		"an older sequence":       {nonce, 325, statement},
		"another statement":       {nonce, 326, strings.Repeat("ef", 32)},
		"the compiled-in set":     {nonce, 0, "embedded"},
		"a replay to a new nonce": {strings.Repeat("01", 32), 326, statement},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verify.VendorPins(document, expect, claim.nonce, claim.sequence, claim.statement)
			refused(t, err, "does not name this nonce and vendor pin set")
		})
	}
	plain := f.document(documentOptions{timestamp: f.now, publicKey: publicKey})
	_, err = verify.VendorPins(plain, expect, nonce, 326, statement)
	refused(t, err, "does not name this nonce and vendor pin set")
	_, err = verify.VendorPins(document, f.expect(f.now.Add(time.Hour)), nonce, 326, statement)
	refused(t, err, "minutes old")
}

func TestVendorPinsNonceKeepsEachFieldApartWhateverItHolds(t *testing.T) {
	if string(verify.VendorPinsNonce("n|1|x", 2, "h")) == string(verify.VendorPinsNonce("n", 1, `x|2|h`)) {
		t.Error("a nonce holding the separator names the same document as another set")
	}
}
