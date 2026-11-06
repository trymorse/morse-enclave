package receipt_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/jcs"
	"morse/backend/internal/receipt"
)

const (
	probePlaintext    = "Say ok. \u00e9 \"q\" <b>&amp; \u2028 tab\t nl\n \u65e5\u672c"
	probeHead         = `{"model":"moonshotai/kimi-k2.6","messages":[{"role":"user","content":`
	probeBufferedTail = `}],"max_tokens":16,"provider":{"aci_verified":true,"zdr":true}}`
	probeStreamTail   = `}],"max_tokens":16,"provider":{"aci_verified":true,"zdr":true},"stream":true,"stream_options":{"include_usage":true}}`
	liveSigningKey    = "110f3824daeeef29dbeba9677a5794ffed257b1082d9fd4599b3c0819953aa0a"
	liveKeyID         = "dstack-kms-receipt-ed25519-v1"
	liveE2EEKey       = "408e82d159832cfae15007781bcade0badee7d50e9f76d50eaa1777464006537"
	liveE2EEKeyID     = "dstack-kms-e2ee-x25519-v1"
	liveE2EEAlgo      = "x25519-aes-256-gcm-hkdf-sha256"
	liveDigest        = "sha256:ef8a03c0c5e349310394c0d5865f766f8a1258f1acdb5fcb6ed2ebcd757e5f5a"
	liveTLSDomain     = "inference.phala.com"
	liveTLSSPKI       = "8e89a8a01e12098065037be187dcd2f03071dc1e7c9bb8527160f4c56ebc728f"
	liveModel         = "moonshotai/kimi-k2.6"
)

var liveNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

type live struct {
	name     string
	receipt  []byte
	response []byte
	tail     string
	chatID   string
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func liveExchanges(t *testing.T) []live {
	t.Helper()
	return []live{
		{"streamed", fixture(t, "stream-receipt.json"), fixture(t, "stream-body.txt"), probeStreamTail, "req_ea44992ae1ba4774e94a53bdd517299d"},
		{"buffered", fixture(t, "buffered-receipt.json"), fixture(t, "buffered-body.txt"), probeBufferedTail, "req_a6e6797bfa7e32761556a7bb18f1ef16"},
	}
}

func liveKeyset(t *testing.T) aci.Keyset {
	t.Helper()
	ks, err := aci.ParseKeyset(keysetReport(t))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func keysetReport(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "aci", "testdata", "attestation.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (l live) exchange() receipt.Exchange {
	return receipt.Exchange{
		Model:        liveModel,
		RequestBody:  []byte(probeHead + string(jcs.String(probePlaintext)) + l.tail),
		ResponseBody: l.response,
		ResponseID:   l.chatID,
	}
}

func TestLiveReceiptsVerifyUnderTheAttestedKeyAgainstTheRealExchange(t *testing.T) {
	ks := liveKeyset(t)
	for _, l := range liveExchanges(t) {
		t.Run(l.name, func(t *testing.T) {
			rc, err := receipt.Parse(l.receipt)
			if err != nil {
				t.Fatal(err)
			}
			if rc.KeyID != liveKeyID || rc.ChatID != l.chatID || rc.Model != "moonshotai/kimi-k2.6" || rc.Digest.String() != liveDigest || rc.WorkloadID != "" {
				t.Errorf("parsed %+v", rc)
			}
			if rc.Upstream.Result != "verified" || !rc.Upstream.Required || rc.Upstream.ModelID != "moonshotai/Kimi-K2.6-TEE" || rc.Upstream.SessionID == "" {
				t.Errorf("upstream %+v", rc.Upstream)
			}
			if err := rc.Verify(ks, l.exchange(), liveNow); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestEveryCheckNamesItsOwnFailure(t *testing.T) {
	ks := liveKeyset(t)
	l := liveExchanges(t)[0]
	otherPublic, _, _ := ed25519.GenerateKey(nil)
	withKey := func(k aci.Key) aci.Keyset {
		return aci.Keyset{WorkloadID: ks.WorkloadID, Digest: ks.Digest, SigningKeys: []aci.Key{k}}
	}
	flipped := bytes.Clone(l.receipt)
	flipped[bytes.Index(flipped, []byte(`"signature":"`))+len(`"signature":"`)] ^= 1
	cases := []struct {
		name     string
		receipt  []byte
		keyset   aci.Keyset
		exchange func(receipt.Exchange) receipt.Exchange
		want     error
		now      time.Time
	}{
		{"keyset expired", l.receipt, ks, same, receipt.ErrKeysetExpired, ks.NotAfter},
		{"keyset without not_after", l.receipt, aci.Keyset{WorkloadID: ks.WorkloadID, Digest: ks.Digest, SigningKeys: ks.SigningKeys}, same, receipt.ErrKeysetExpired, liveNow},
		{"other model", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange { x.Model = "moonshotai/kimi-k2.5"; return x }, receipt.ErrModel, liveNow},
		{"unknown key id", l.receipt, withKey(aci.Key{ID: "other", Algo: aci.AlgoEd25519, Public: ks.SigningKeys[0].Public}), same, receipt.ErrKeyUnknown, time.Time{}},
		{"secp256k1 key", l.receipt, withKey(aci.Key{ID: liveKeyID, Algo: "ecdsa-secp256k1", Public: ks.SigningKeys[0].Public}), same, receipt.ErrKeyAlgo, time.Time{}},
		{"other public key", l.receipt, withKey(aci.Key{ID: liveKeyID, Algo: aci.AlgoEd25519, Public: otherPublic}), same, receipt.ErrSignature, time.Time{}},
		{"tampered signature", flipped, ks, same, receipt.ErrSignature, time.Time{}},
		{"tampered served_at", bytes.Replace(l.receipt, []byte(`"served_at":1790732265`), []byte(`"served_at":1790732266`), 1), ks, same, receipt.ErrSignature, time.Time{}},
		{"other digest", l.receipt, aci.Keyset{Digest: aci.Hash{}, SigningKeys: ks.SigningKeys}, same, receipt.ErrKeysetDigest, time.Time{}},
		{"attestation names a workload", l.receipt, aci.Keyset{WorkloadID: "wl_1", Digest: ks.Digest, SigningKeys: ks.SigningKeys}, same, receipt.ErrWorkloadID, time.Time{}},
		{"other response id", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange { x.ResponseID = "req_other"; return x }, receipt.ErrChatID, time.Time{}},
		{"other plaintext", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange {
			x.RequestBody = bytes.Replace(x.RequestBody, []byte("Say ok"), []byte("Say no"), 1)
			return x
		}, receipt.ErrRequestHash, time.Time{}},
		{"go escaped plaintext", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange {
			escaped, _ := json.Marshal(probePlaintext)
			x.RequestBody = []byte(probeHead + string(escaped) + l.tail)
			return x
		}, receipt.ErrRequestHash, time.Time{}},
		{"one response byte flipped", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange {
			body := bytes.Clone(x.ResponseBody)
			body[len(body)/2] ^= 1
			x.ResponseBody = body
			return x
		}, receipt.ErrResponseHash, time.Time{}},
		{"truncated response", l.receipt, ks, func(x receipt.Exchange) receipt.Exchange {
			x.ResponseBody = bytes.TrimSuffix(x.ResponseBody, []byte("data: [DONE]\n\n"))
			return x
		}, receipt.ErrResponseHash, time.Time{}},
	}
	for _, tc := range cases {
		rc, err := receipt.Parse(tc.receipt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		now := tc.now
		if now.IsZero() {
			now = liveNow
		}
		if err := rc.Verify(tc.keyset, tc.exchange(l.exchange()), now); !errors.Is(err, tc.want) {
			t.Errorf("%s: Verify = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func same(x receipt.Exchange) receipt.Exchange { return x }

func TestUpstreamVerificationIsCheckedLastAndMustBeVerifiedAndRequired(t *testing.T) {
	ks := liveKeyset(t)
	l := liveExchanges(t)[1]
	for name, edit := range map[string][2]string{
		"unverified":   {`"result":"verified"`, `"result":"unverified"`},
		"not required": {`"required":true`, `"required":false`},
	} {
		tampered := bytes.Replace(l.receipt, []byte(edit[0]), []byte(edit[1]), 1)
		rc, err := receipt.Parse(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if err := rc.Verify(ks, l.exchange(), liveNow); !errors.Is(err, receipt.ErrSignature) {
			t.Errorf("%s: an edited receipt verified past the signature: %v", name, err)
		}
		resigned, public := resign(t, tampered)
		rc, err = receipt.Parse(resigned)
		if err != nil {
			t.Fatal(err)
		}
		keyset := aci.Keyset{Digest: ks.Digest, NotAfter: ks.NotAfter, SigningKeys: []aci.Key{{ID: liveKeyID, Algo: aci.AlgoEd25519, Public: public}}}
		if err := rc.Verify(keyset, l.exchange(), liveNow); !errors.Is(err, receipt.ErrUpstreamUnverified) {
			t.Errorf("%s: %v, want ErrUpstreamUnverified", name, err)
		}
	}
}

func resign(t *testing.T, raw []byte) ([]byte, ed25519.PublicKey) {
	t.Helper()
	decoded, err := jcs.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	object := decoded.(map[string]any)
	delete(object, "signature")
	payload, err := jcs.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	object["signature"] = hex.EncodeToString(ed25519.Sign(private, payload))
	out, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return out, public
}

func TestParseAcceptsWireHashAndRefusesAConflictingPair(t *testing.T) {
	l := liveExchanges(t)[1]
	renamed := bytes.Replace(l.receipt, []byte(`"body_hash":"sha256:b8d127d3`), []byte(`"wire_hash":"sha256:b8d127d3`), 1)
	rc, err := receipt.Parse(renamed)
	if err != nil || rc.ResponseReturned.String() != "sha256:b8d127d3b625fd97426011f6ec20ad8f177949521bf0819e5926e1cb363e3456" {
		t.Errorf("wire_hash: %+v %v", rc.ResponseReturned, err)
	}
	both := bytes.Replace(l.receipt, []byte(`"body_hash":"sha256:b8d127d3`), []byte(`"wire_hash":"sha256:`+strings.Repeat("11", 32)+`","body_hash":"sha256:b8d127d3`), 1)
	if _, err := receipt.Parse(both); !errors.Is(err, receipt.ErrHashConflict) {
		t.Errorf("conflicting hashes parsed: %v", err)
	}
	for name, body := range map[string]string{
		"no events":     `{"receipt_id":"rcpt-1","workload_keyset_digest":"` + liveDigest + `","signature":"` + strings.Repeat("00", 64) + `","event_log":[]}`,
		"short sig":     strings.Replace(string(l.receipt), `"signature":"e5`, `"signature":"`, 1),
		"not an object": `[]`,
		"bad hash":      strings.Replace(string(l.receipt), `sha256:ec3c`, `md5:ec3c`, 1),
	} {
		if _, err := receipt.Parse([]byte(body)); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

func TestParseRefusesAReceiptThatStatesAnEventTwice(t *testing.T) {
	l := liveExchanges(t)[1]
	for _, event := range []string{
		`{"type":"upstream.verified","result":"unverified","required":false}`,
		`{"type":"request.received","body_hash":"sha256:` + strings.Repeat("22", 32) + `"}`,
		`{"type":"response.returned","body_hash":"sha256:` + strings.Repeat("33", 32) + `"}`,
	} {
		twice := bytes.Replace(l.receipt, []byte(`"event_log":[`), []byte(`"event_log":[`+event+`,`), 1)
		if _, err := receipt.Parse(twice); !errors.Is(err, receipt.ErrDuplicateEvent) {
			t.Errorf("a second %s parsed: %v", event, err)
		}
	}
}

func TestLiveReceiptsVerifyTheReplyFromItsHashAloneAndNameEachMismatch(t *testing.T) {
	ks := liveKeyset(t)
	for _, l := range liveExchanges(t) {
		t.Run(l.name, func(t *testing.T) {
			rc, err := receipt.Parse(l.receipt)
			if err != nil {
				t.Fatal(err)
			}
			read := receipt.Response{Model: liveModel, ID: l.chatID, Hash: aci.Sum(l.response)}
			if err := rc.VerifyResponse(ks, read, liveNow); err != nil {
				t.Errorf("VerifyResponse: %v", err)
			}
			forged := append(bytes.Clone(l.response), "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"...)
			for name, tc := range map[string]struct {
				edit func(receipt.Response) receipt.Response
				want error
			}{
				"a forged frame appended": {func(r receipt.Response) receipt.Response { r.Hash = aci.Sum(forged); return r }, receipt.ErrResponseHash},
				"another chat":            {func(r receipt.Response) receipt.Response { r.ID = "req_other"; return r }, receipt.ErrChatID},
				"another model":           {func(r receipt.Response) receipt.Response { r.Model = "moonshotai/kimi-k2.5"; return r }, receipt.ErrModel},
			} {
				if err := rc.VerifyResponse(ks, tc.edit(read), liveNow); !errors.Is(err, tc.want) {
					t.Errorf("%s: VerifyResponse = %v, want %v", name, err, tc.want)
				}
			}
			other := aci.Keyset{Digest: ks.Digest, NotAfter: ks.NotAfter, SigningKeys: []aci.Key{{ID: liveKeyID, Algo: aci.AlgoEd25519, Public: make([]byte, ed25519.PublicKeySize)}}}
			if err := rc.VerifyResponse(other, read, liveNow); !errors.Is(err, receipt.ErrSignature) {
				t.Errorf("under another key: VerifyResponse = %v, want ErrSignature", err)
			}
		})
	}
}
