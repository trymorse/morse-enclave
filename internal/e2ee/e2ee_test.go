package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	vectorModel      = "demo-model"
	vectorNonce      = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorTimestamp  = int64(1750000000)
	vectorResponseID = "chatcmpl-123"
	vectorPublicKey  = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
	vectorRequestAAD = `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}`
	vectorReplyAAD   = `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}`
	otherX25519Key   = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	secp256k1Key     = "04943cea0b4babf60f6e2031e9a00866a37c4ae696fb45895b3a9b38ab8cbb898f42c85b704aceaa0a396cf26f7fdf79d83205be7e11d3a5d70419a68277158c3d"
)

var (
	vectorParams   = Params{suite: X25519, nonce: vectorNonce, ts: vectorTimestamp}
	messageContent = ResponseField{Choice: 0, Part: "message", Name: "content"}
)

func VectorKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAADBytesMatchBothVectorsExactly(t *testing.T) {
	request := vectorParams.RequestAAD(vectorModel, 0)
	reply := vectorParams.ResponseAAD(vectorModel, vectorResponseID, messageContent)
	if got := string(request.Bytes()); got != vectorRequestAAD {
		t.Errorf("request AAD\n%s\nwant\n%s", got, vectorRequestAAD)
	}
	if got := string(reply.Bytes()); got != vectorReplyAAD {
		t.Errorf("response AAD\n%s\nwant\n%s", got, vectorReplyAAD)
	}
}

func TestAADStringsAreNotHTMLOrLineSeparatorEscaped(t *testing.T) {
	aad := vectorParams.RequestAAD("vendor/<m>&co\u2028", 0)
	if got := string(aad.Bytes()); !strings.Contains(got, "\"model\":\"vendor/<m>&co\u2028\"") {
		t.Errorf("AAD escaped the model: %s", got)
	}
}

func TestVectorSeedDerivesTheVectorPublicKey(t *testing.T) {
	if got := hex.EncodeToString(VectorKey(t).PublicKey().Bytes()); got != vectorPublicKey {
		t.Errorf("public key %s, want %s", got, vectorPublicKey)
	}
}

func TestSealOpenRoundTripAndOpenRefusesADifferentAAD(t *testing.T) {
	key := VectorKey(t)
	aad := vectorParams.RequestAAD(vectorModel, 0)
	plaintext := []byte("Say ok")
	sealed, err := Seal(key.PublicKey(), aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !X25519.IsCiphertext([]byte(`"` + sealed + `"`)) {
		t.Errorf("Seal produced something IsCiphertext rejects: %s", sealed)
	}
	again, _ := Seal(key.PublicKey(), aad, plaintext)
	if again == sealed {
		t.Error("two seals of the same plaintext are identical; the ephemeral key or nonce is not fresh")
	}
	opened, err := Open(key, aad, sealed)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open returned %q, %v", opened, err)
	}
	for name, other := range map[string]AAD{
		"other model": vectorParams.RequestAAD("other", 0),
		"other field": vectorParams.RequestAAD(vectorModel, 1),
		"other nonce": Params{suite: X25519, nonce: strings.Repeat("ab", 32), ts: vectorTimestamp}.RequestAAD(vectorModel, 0),
		"other ts":    Params{suite: X25519, nonce: vectorNonce, ts: vectorTimestamp + 1}.RequestAAD(vectorModel, 0),
		"response":    vectorParams.ResponseAAD(vectorModel, "", messageContent),
	} {
		if _, err := Open(key, other, sealed); err == nil {
			t.Errorf("%s: opened under a different AAD", name)
		}
	}
	otherKey, _ := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if _, err := Open(otherKey, aad, sealed); err == nil {
		t.Error("opened with a different private key")
	}
	if _, err := Open(key, aad, sealed[:len(sealed)-2]); err == nil {
		t.Error("opened a truncated ciphertext")
	}
}

func TestSealAndOpenServeOnlyTheX25519Suite(t *testing.T) {
	key := VectorKey(t)
	aad := Params{suite: Secp256k1, nonce: vectorNonce}.RequestAAD(vectorModel, 0)
	if _, err := Seal(key.PublicKey(), aad, []byte("x")); !errors.Is(err, errSuiteNotSealable) {
		t.Errorf("Seal err %v", err)
	}
	if _, err := Open(key, aad, strings.Repeat("00", 60)); !errors.Is(err, errSuiteNotSealable) {
		t.Errorf("Open err %v", err)
	}
}

func headers(pairs ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(name string) string { return m[name] }
}

func validHeaders() []string {
	return []string{HeaderVersion, "2", HeaderClientKey, otherX25519Key, HeaderModelKey, vectorPublicKey, HeaderNonce, vectorNonce, HeaderTimestamp, "1750000000"}
}

func TestParseHeadersRefusesEveryMalformedSeal(t *testing.T) {
	cases := []struct {
		name  string
		pairs []string
		want  *Error
	}{
		{"legacy header alone", []string{HeaderLegacy, "ecdsa"}, ErrLegacy},
		{"legacy header with a full seal", append(validHeaders(), HeaderLegacy, "ecdsa"), ErrLegacy},
		{"four of five", []string{HeaderVersion, "2", HeaderClientKey, otherX25519Key, HeaderModelKey, vectorPublicKey, HeaderNonce, vectorNonce}, ErrHeaderMissing},
		{"only version", []string{HeaderVersion, "2"}, ErrHeaderMissing},
		{"version 1", append(validHeaders(), HeaderVersion, "1"), ErrInvalidVersion},
		{"model key not hex", append(validHeaders(), HeaderModelKey, strings.Repeat("zz", 32)), ErrInvalidKey},
		{"model key wrong length", append(validHeaders(), HeaderModelKey, strings.Repeat("ab", 31)), ErrInvalidKey},
		{"client key of another suite", append(validHeaders(), HeaderClientKey, secp256k1Key), ErrInvalidKey},
		{"nonce 63 hex", append(validHeaders(), HeaderNonce, vectorNonce[:63]), ErrInvalidNonce},
		{"nonce 0x prefixed", append(validHeaders(), HeaderNonce, "0x"+vectorNonce[2:]), ErrInvalidNonce},
		{"nonce not hex", append(validHeaders(), HeaderNonce, strings.Repeat("g", 64)), ErrInvalidNonce},
		{"timestamp not an integer", append(validHeaders(), HeaderTimestamp, "1750000000.5"), ErrInvalidTimestamp},
		{"timestamp empty is missing", append(validHeaders(), HeaderTimestamp, ""), ErrHeaderMissing},
	}
	for _, tc := range cases {
		params, _, err := ParseHeaders(headers(tc.pairs...))
		var got *Error
		if !errors.As(err, &got) || got != tc.want || params != (Params{}) {
			t.Errorf("%s: params %v err %v, want %v", tc.name, params, err, tc.want)
		}
	}
}

func TestParseHeadersReportsAPlainRequestAsUnsealed(t *testing.T) {
	params, sealed, err := ParseHeaders(headers("Content-Type", "application/json"))
	if sealed || params != (Params{}) || err != nil {
		t.Errorf("sealed %t params %v err %v", sealed, params, err)
	}
	if _, sealed, err := ParseHeaders(headers(validHeaders()...)); !sealed || err != nil {
		t.Errorf("five valid headers: sealed %t err %v", sealed, err)
	}
}

func TestParseHeadersKeepsValuesByteExactAndForwardWritesOnlyTheFive(t *testing.T) {
	upperNonce := strings.ToUpper(vectorNonce)
	prefixedKey := "0x" + strings.ToUpper(vectorPublicKey)
	params, _, err := ParseHeaders(headers(HeaderVersion, "2", HeaderClientKey, otherX25519Key, HeaderModelKey, prefixedKey, HeaderNonce, upperNonce, HeaderTimestamp, "1750000000", HeaderLegacy, ""))
	if err != nil {
		t.Fatal(err)
	}
	wantAAD := strings.Replace(vectorRequestAAD, vectorNonce, upperNonce, 1)
	if got := string(params.RequestAAD(vectorModel, 0).Bytes()); params.Suite() != X25519 || got != wantAAD {
		t.Errorf("suite %v AAD\n%s\nwant\n%s", params.Suite(), got, wantAAD)
	}
	if got := string(params.ResponseAAD(vectorModel, vectorResponseID, messageContent).Bytes()); got != strings.Replace(vectorReplyAAD, vectorNonce, upperNonce, 1) {
		t.Errorf("response AAD %s", got)
	}
	modelKey, modelErr := params.ModelX25519()
	clientKey, clientErr := params.ClientX25519()
	if modelErr != nil || clientErr != nil || hex.EncodeToString(modelKey.Bytes()) != vectorPublicKey || hex.EncodeToString(clientKey.Bytes()) != otherX25519Key {
		t.Errorf("decoded keys %v %v, errors %v %v", modelKey, clientKey, modelErr, clientErr)
	}
	forwarded := map[string]string{}
	params.Forward(func(name, value string) { forwarded[name] = value })
	want := map[string]string{HeaderVersion: "2", HeaderClientKey: otherX25519Key, HeaderModelKey: prefixedKey, HeaderNonce: upperNonce, HeaderTimestamp: "1750000000"}
	if len(forwarded) != len(want) {
		t.Errorf("forwarded %v, want exactly %v", forwarded, want)
	}
	for name, value := range want {
		if forwarded[name] != value {
			t.Errorf("%s forwarded as %q, want the client's bytes %q", name, forwarded[name], value)
		}
	}
}

func TestNewParamsForwardsHeadersThatParseBackToTheSameParams(t *testing.T) {
	client, model := VectorKey(t), VectorKey(t).PublicKey()
	params, err := NewParams(client, model, vectorTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := map[string]string{}
	params.Forward(func(name, value string) { forwarded[name] = value })
	parsed, sealed, err := ParseHeaders(func(name string) string { return forwarded[name] })
	if err != nil || !sealed || parsed != params {
		t.Fatalf("forwarded %v parsed back as %+v, %v; want %+v", forwarded, parsed, err, params)
	}
	nonce := forwarded[HeaderNonce]
	if len(nonce) != nonceHexLen || nonce != strings.ToLower(nonce) || forwarded[HeaderModelKey] != vectorPublicKey || forwarded[HeaderTimestamp] != "1750000000" {
		t.Errorf("forwarded %v", forwarded)
	}
	if got := string(params.RequestAAD(vectorModel, 0).Bytes()); got != strings.Replace(vectorRequestAAD, vectorNonce, nonce, 1) {
		t.Errorf("AAD %s", got)
	}
	again, _ := NewParams(client, model, vectorTimestamp)
	if again == params {
		t.Error("two NewParams share a nonce")
	}
	p256, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := NewParams(p256, model, vectorTimestamp); !errors.Is(err, errSuiteNotSealable) {
		t.Errorf("a P-256 client key gave %v", err)
	}
}

func TestSecp256k1KeysParseAsThatSuiteWithOrWithoutThePointPrefix(t *testing.T) {
	for _, key := range []string{secp256k1Key, secp256k1Key[2:]} {
		params, _, err := ParseHeaders(headers(HeaderVersion, "2", HeaderClientKey, key, HeaderModelKey, secp256k1Key, HeaderNonce, vectorNonce, HeaderTimestamp, "1"))
		if err != nil || params.Suite() != Secp256k1 {
			t.Errorf("key of %d hex: params %v err %v", len(key), params, err)
		}
		if _, err := params.ClientX25519(); !errors.Is(err, errSuiteNotSealable) {
			t.Errorf("key of %d hex: ClientX25519 err %v, want the X25519-only refusal", len(key), err)
		}
	}
}

func TestConfirmAcceptsOnlyAppliedVersion2OfTheRequestedSuite(t *testing.T) {
	params, _, err := ParseHeaders(headers(validHeaders()...))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"applied":         {HeaderApplied, "true", HeaderVersion, "2", HeaderAlgo, X25519.Algo()},
		"not applied":     {HeaderApplied, "false", HeaderVersion, "2", HeaderAlgo, X25519.Algo()},
		"no headers":      {},
		"version 1":       {HeaderApplied, "true", HeaderVersion, "1", HeaderAlgo, X25519.Algo()},
		"other suite":     {HeaderApplied, "true", HeaderVersion, "2", HeaderAlgo, Secp256k1.Algo()},
		"applied in caps": {HeaderApplied, "TRUE", HeaderVersion, "2", HeaderAlgo, X25519.Algo()},
	}
	for name, reply := range cases {
		err := params.Confirm(headers(reply...))
		if (name == "applied") != (err == nil) {
			t.Errorf("%s: err %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrNotApplied) {
			t.Errorf("%s: err %v is not ErrNotApplied", name, err)
		}
	}
	written := map[string]string{}
	params.WriteApplied(func(name, value string) { written[name] = value })
	if params.Confirm(headers(written[HeaderApplied], "", HeaderApplied, written[HeaderApplied], HeaderVersion, written[HeaderVersion], HeaderAlgo, written[HeaderAlgo])) != nil || len(written) != 3 {
		t.Errorf("WriteApplied wrote %v, which Confirm does not accept", written)
	}
}

func TestIsCiphertextAcceptsOnlyLongEnoughLowercaseHexStrings(t *testing.T) {
	minHex := X25519.MinCiphertextHex()
	if minHex != 2*(32+12+16) {
		t.Fatalf("X25519 minimum is %d hex characters", minHex)
	}
	cases := map[string]bool{
		`"` + strings.Repeat("ab", minHex/2) + `"`:                          true,
		`"` + strings.Repeat("ab", minHex/2+40) + `"`:                       true,
		`"` + strings.Repeat("ab", minHex/2-1) + `"`:                        false,
		`"` + strings.Repeat("AB", minHex/2) + `"`:                          false,
		`"` + strings.Repeat("ab", minHex/2) + `a"`:                         false,
		`"` + strings.Repeat("ab", minHex/2) + `zz"`:                        false,
		`"hello in the clear"`:                                              false,
		`[{"type":"text","text":"` + strings.Repeat("ab", minHex/2) + `"}]`: false,
		`null`:  false,
		`""`:    false,
		``:      false,
		`12345`: false,
	}
	for raw, want := range cases {
		if got := X25519.IsCiphertext([]byte(raw)); got != want {
			t.Errorf("IsCiphertext(%q) = %t", raw, got)
		}
	}
	if Secp256k1.IsCiphertext([]byte(`"` + strings.Repeat("ab", minHex/2) + `"`)) {
		t.Error("secp256k1 accepted an X25519-length ciphertext")
	}
}

func TestParsedParamsBindEveryFieldPathIntoTheAADExactly(t *testing.T) {
	params, _, err := ParseHeaders(headers(validHeaders()...))
	if err != nil {
		t.Fatal(err)
	}
	head := `{"algo":"x25519-aes-256-gcm-hkdf-sha256",`
	tail := `"model":"vendor/m","nonce":"` + vectorNonce + `",`
	request := `"purpose":"aci.e2ee.request.v2","ts":1750000000}`
	response := `"purpose":"aci.e2ee.response.v2","ts":1750000000}`
	cases := []struct {
		aad  AAD
		want string
	}{
		{params.RequestAAD("vendor/m", 0), head + `"field":"messages.0.content",` + tail + request},
		{params.RequestAAD("vendor/m", 12), head + `"field":"messages.12.content",` + tail + request},
		{params.ResponseAAD("vendor/m", "chatcmpl-9", messageContent), head + `"field":"choices.0.message.content","id":"chatcmpl-9",` + tail + response},
		{params.ResponseAAD("vendor/m", `chatcmpl-"9"`, ResponseField{Choice: 3, Part: "delta", Name: "reasoning_content"}), head + `"field":"choices.3.delta.reasoning_content","id":"chatcmpl-\"9\"",` + tail + response},
		{params.ResponseAAD("vendor/m", "", ResponseField{Choice: 1, Part: "delta", Name: "content"}), head + `"field":"choices.1.delta.content","id":"",` + tail + response},
	}
	for _, c := range cases {
		if got := string(c.aad.Bytes()); got != c.want {
			t.Errorf("AAD\n%s\nwant\n%s", got, c.want)
		}
	}
}
