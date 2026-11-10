package ehbpclient

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Tinfoil's own vector of the reply key schedule (testdata/derive.json, from Tinfoil's EHBP test vectors).
func TestTinfoilsReplyKeySchedule(t *testing.T) {
	raw, err := os.ReadFile("testdata/derive.json")
	if err != nil {
		t.Fatal(err)
	}
	var derive struct{ ExportedSecret, RequestEnc, ResponseNonce, DerivedKey, DerivedNonceBase string }
	if err := json.Unmarshal(raw, &derive); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	_, nbase, err := replyKeys(unhex(derive.ExportedSecret), unhex(derive.RequestEnc), unhex(derive.ResponseNonce))
	if err != nil || hex.EncodeToString(nbase) != derive.DerivedNonceBase {
		t.Fatalf("nonce base %x, err %v", nbase, err)
	}
}
