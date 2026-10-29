package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"reflect"
	"testing"
)

const vectorsFile = "testdata/vectors.json"

var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/vectors.json from the inputs in this test")

type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := hex.DecodeString(s)
	*h = raw
	return err
}

type vectorRecipient struct {
	PrivateKey hexBytes `json:"private_key"`
	PublicKey  hexBytes `json:"public_key"`
	KeyID      hexBytes `json:"key_id"`
}

type vectorRequest struct {
	Name       string     `json:"name"`
	Recipients []int      `json:"recipients"`
	Ephemerals []hexBytes `json:"ephemeral_private_keys"`
	CEK        hexBytes   `json:"cek"`
	Head       wireHead   `json:"head"`
	HeadJSON   hexBytes   `json:"head_json"`
	Body       hexBytes   `json:"body"`
	Inner      hexBytes   `json:"inner"`
	AAD        hexBytes   `json:"aad"`
	Ciphertext hexBytes   `json:"ciphertext"`
	Sealed     hexBytes   `json:"sealed"`
}

type vectorFrame struct {
	Data      hexBytes `json:"data"`
	Final     bool     `json:"final"`
	Nonce     hexBytes `json:"nonce"`
	Plaintext hexBytes `json:"plaintext"`
	Frame     hexBytes `json:"frame"`
}

type vectorReply struct {
	Name      string        `json:"name"`
	CEK       hexBytes      `json:"cek"`
	Salt      hexBytes      `json:"salt"`
	Key       hexBytes      `json:"key"`
	BaseNonce hexBytes      `json:"base_nonce"`
	Head      ReplyHead     `json:"head"`
	Frames    []vectorFrame `json:"frames"`
	Reply     hexBytes      `json:"reply"`
}

type vectors struct {
	Suite      map[string]string `json:"suite"`
	Recipients []vectorRecipient `json:"recipients"`
	Requests   []vectorRequest   `json:"requests"`
	Replies    []vectorReply     `json:"replies"`
	Patterns   []string          `json:"sealable_patterns"`
}

func fixed(label string) []byte {
	sum := sha256.Sum256([]byte("morse seal vectors: " + label))
	return sum[:]
}

func buildVectors(t *testing.T) vectors {
	t.Helper()
	v := vectors{Suite: map[string]string{"kem": "DHKEM(X25519, HKDF-SHA256)", "kdf": "HKDF-SHA256", "aead": "AES-256-GCM", "cek_info": infoCEK, "reply_key_info": infoReplyKey, "reply_nonce_info": infoReplyNonce}, Patterns: storedPatterns(t)}
	var identities []*Identity
	for _, label := range []string{"recipient a", "recipient b"} {
		id, err := IdentityFromKey(fixed(label))
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, id)
		keyID := id.KeyID()
		v.Recipients = append(v.Recipients, vectorRecipient{PrivateKey: fixed(label), PublicKey: id.PublicKey(), KeyID: keyID[:]})
	}
	exact := bytes.Repeat([]byte("x"), Pad-tagSize-4-len(`{"method":"POST","path":"/v1/search","headers":{"Content-Type":"application/json"},"ts":1792216730,"body_len":890}`))
	e2eeHeaders := map[string]string{"Content-Type": "application/json", "X-Client-Pub-Key": "02aa", "X-E2EE-Version": "2", "X-Encryption-Version": "2", "X-Model-Pub-Key": "03bb", "X-Signing-Algo": "ecdsa"}
	requests := []struct {
		name       string
		recipients []int
		head       Head
		body       []byte
	}{
		{"chat to two keys", []int{0, 1}, Head{Method: "POST", Path: "/v1/chat/completions", Headers: map[string]string{"Content-Type": "application/json"}, TS: 1792216730}, []byte(`{"model":"stub","stream":true,"messages":[{"role":"user","content":"hi"}]}`)},
		{"e2ee chat to one key", []int{0}, Head{Method: "POST", Path: "/v1/chat/completions", Headers: e2eeHeaders, TS: 1792216730}, []byte(`{"model":"e2ee","messages":[{"role":"user","content":"ciphertext"}]}`)},
		{"lookup with a query to one key", []int{1}, Head{Method: "GET", Path: "/v1/lookup/coingecko/simple/price?ids=bitcoin&vs_currencies=usd", Headers: map[string]string{}, TS: 1792216730}, nil},
		{"body on the padding boundary", []int{0}, Head{Method: "POST", Path: "/v1/search", Headers: map[string]string{"Content-Type": "application/json"}, TS: 1792216730}, exact},
	}
	for _, r := range requests {
		req := vectorRequest{Name: r.name, Recipients: r.recipients, CEK: fixed("cek " + r.name), Head: wireHead{Head: r.head, BodyLen: len(r.body)}, Body: r.body}
		var keys [][]byte
		for n, at := range r.recipients {
			keys = append(keys, identities[at].PublicKey())
			req.Ephemerals = append(req.Ephemerals, fixed("ephemeral "+r.name+string(rune('a'+n))))
		}
		sealed, err := sealUnder(keys, r.head, r.body, [cekSize]byte(req.CEK), deterministicWrapper(t, req.Ephemerals))
		if err != nil {
			t.Fatal(err)
		}
		req.HeadJSON, _ = json.Marshal(req.Head)
		req.Inner = innerOf(req.HeadJSON, r.body)
		req.AAD = sealed[:prefixSize+len(r.recipients)*entrySize]
		req.Ciphertext = sealed[len(req.AAD):]
		req.Sealed = sealed
		v.Requests = append(v.Requests, req)
	}
	replies := []struct {
		name   string
		head   ReplyHead
		frames []vectorFrame
	}{
		{"one json frame", ReplyHead{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}}}, []vectorFrame{{Data: []byte(`{"object":"list","data":[]}`), Final: true}}},
		{"a stream", ReplyHead{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-cache"}}}, []vectorFrame{{Data: []byte("data: {\"a\":1}\n\ndata: {\"b\":2}\n\n")}, {Data: []byte("data: [DONE]\n\n")}, {Final: true}}},
		{"a worker's refusal", ReplyHead{Status: 400, Headers: http.Header{"Content-Type": {"application/json"}}}, []vectorFrame{{Data: []byte(`{"error":{"message":"This sealed request was opened before.","type":"invalid_request_error","param":null,"code":"sealed_replay"}}`), Final: true}}},
	}
	for _, r := range replies {
		reply := vectorReply{Name: r.name, CEK: fixed("reply cek " + r.name), Salt: fixed("salt " + r.name), Head: r.head}
		reply.Key, _ = hkdf.Key(sha256.New, reply.CEK, reply.Salt, infoReplyKey, cekSize)
		reply.BaseNonce, _ = hkdf.Key(sha256.New, reply.CEK, reply.Salt, infoReplyNonce, nonceSize)
		frames, err := NewFrames([cekSize]byte(reply.CEK), [saltSize]byte(reply.Salt))
		if err != nil {
			t.Fatal(err)
		}
		headJSON, _ := json.Marshal(r.head)
		reply.Reply = bytes.Clone(reply.Salt)
		for i, f := range append([]vectorFrame{{Data: headJSON}}, r.frames...) {
			f.Nonce = bytes.Clone(reply.BaseNonce)
			binary.BigEndian.PutUint32(f.Nonce[nonceSize-4:], binary.BigEndian.Uint32(f.Nonce[nonceSize-4:])^uint32(i))
			f.Plaintext = append([]byte{boolByte(f.Final)}, binary.BigEndian.AppendUint32(nil, uint32(len(f.Data)))...)
			f.Plaintext = append(f.Plaintext, f.Data...)
			f.Plaintext = append(f.Plaintext, make([]byte, padding(len(f.Plaintext)))...)
			f.Frame = frames.Seal(f.Data, f.Final)
			reply.Frames = append(reply.Frames, f)
			reply.Reply = append(reply.Reply, f.Frame...)
		}
		v.Replies = append(v.Replies, reply)
	}
	return v
}

func storedPatterns(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Patterns []string `json:"sealable_patterns"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	return stored.Patterns
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// crypto/hpke draws its own ephemeral key, so this writes out RFC 9180 DHKEM(X25519, HKDF-SHA256) with the keys
// given; Identity.Open proves it against crypto/hpke.
func deterministicWrapper(t *testing.T, ephemerals []hexBytes) wrapper {
	t.Helper()
	n := 0
	return func(publicKey []byte, id KeyID, cek []byte) ([]byte, []byte, error) {
		skE, err := ecdh.X25519().NewPrivateKey(ephemerals[n])
		if err != nil {
			return nil, nil, err
		}
		n++
		pkR, err := ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, nil, err
		}
		dh, err := skE.ECDH(pkR)
		if err != nil {
			return nil, nil, err
		}
		enc := skE.PublicKey().Bytes()
		kemSuite := append([]byte("KEM"), 0x00, 0x20)
		eaePRK := labeledExtract(kemSuite, nil, "eae_prk", dh)
		sharedSecret := labeledExpand(kemSuite, eaePRK, "shared_secret", append(bytes.Clone(enc), publicKey...), 32)
		hpkeSuite := append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x02)
		context := append([]byte{0}, labeledExtract(hpkeSuite, nil, "psk_id_hash", nil)...)
		context = append(context, labeledExtract(hpkeSuite, nil, "info_hash", []byte(infoCEK))...)
		secret := labeledExtract(hpkeSuite, sharedSecret, "secret", nil)
		key := labeledExpand(hpkeSuite, secret, "key", context, 32)
		baseNonce := labeledExpand(hpkeSuite, secret, "base_nonce", context, 12)
		content, err := contentCipher(key)
		if err != nil {
			return nil, nil, err
		}
		return enc, content.Seal(nil, baseNonce, cek, id[:]), nil
	}
}

func labeledExtract(suite, salt []byte, label string, ikm []byte) []byte {
	labeled := append(append(append([]byte("HPKE-v1"), suite...), label...), ikm...)
	prk, err := hkdf.Extract(sha256.New, labeled, salt)
	if err != nil {
		panic(err)
	}
	return prk
}

func labeledExpand(suite, prk []byte, label string, info []byte, length int) []byte {
	labeled := append(append(append(binary.BigEndian.AppendUint16(nil, uint16(length)), []byte("HPKE-v1")...), suite...), label...)
	out, err := hkdf.Expand(sha256.New, prk, string(append(labeled, info...)), length)
	if err != nil {
		panic(err)
	}
	return out
}

func TestTheVectorsAreTheBytesTheseInputsSealToAndTheyOpen(t *testing.T) {
	built := buildVectors(t)
	if *updateVectors {
		out, _ := json.MarshalIndent(built, "", "  ")
		if err := os.WriteFile(vectorsFile, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored vectors
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	rebuilt, _ := json.MarshalIndent(built, "", "  ")
	if !bytes.Equal(bytes.TrimSpace(raw), rebuilt) {
		t.Fatalf("%s differs from what these inputs build; rerun with -update-vectors if the format changed on purpose", vectorsFile)
	}
	for _, r := range stored.Requests {
		for _, at := range r.Recipients {
			id, _ := IdentityFromKey(stored.Recipients[at].PrivateKey)
			opened, err := id.Open(r.Sealed)
			if err != nil {
				t.Errorf("%s: recipient %d: %v", r.Name, at, err)
				continue
			}
			if !reflect.DeepEqual(opened.Head, r.Head.Head) || len(opened.Body) != r.Head.BodyLen || !bytes.Equal(opened.Body, r.Body) || !bytes.Equal(opened.CEK[:], r.CEK) {
				t.Errorf("%s: recipient %d opened %+v %q", r.Name, at, opened.Head, opened.Body)
			}
		}
		if len(r.Ciphertext)%Pad != 0 || !bytes.Equal(r.Sealed, append(bytes.Clone(r.AAD), r.Ciphertext...)) {
			t.Errorf("%s: aad and ciphertext do not make the sealed bytes", r.Name)
		}
	}
	for _, r := range stored.Replies {
		reply, err := OpenReply(bytes.NewReader(r.Reply), [cekSize]byte(r.CEK))
		if err != nil {
			t.Errorf("%s: %v", r.Name, err)
			continue
		}
		var body []byte
		for !reply.done {
			data, final, err := reply.next()
			if err != nil {
				t.Errorf("%s: %v", r.Name, err)
				break
			}
			body, reply.done = append(body, data...), final
		}
		var want []byte
		for _, f := range r.Frames[1:] {
			want = append(want, f.Data...)
		}
		if !reflect.DeepEqual(reply.Head, r.Head) || !bytes.Equal(body, want) {
			t.Errorf("%s: opened %+v %q", r.Name, reply.Head, body)
		}
	}
	boundary := stored.Requests[len(stored.Requests)-1]
	if len(boundary.Inner) != 4+len(boundary.HeadJSON)+len(boundary.Body) {
		t.Errorf("the boundary request's inner has %d bytes of padding, want none", len(boundary.Inner)-4-len(boundary.HeadJSON)-len(boundary.Body))
	}
}
