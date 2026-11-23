package near

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"morse/backend/internal/e2ee"
)

const (
	v3ReplyPublic = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
	v3AAD         = "6e65617261692d653265652d726571756573742d76330266be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a006d657373616765735b5d2e636f6e74656e74"
	v3Plaintext   = "E2EE v3: private prompt"
	v3Sealed      = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" +
		"000102030405060708090a0b0c0d0e0f1011121314151617" +
		"952f1029d9facf0669005cd32fc9f3682f65e17b55d57abc02aeccf35eaabf4b8efe9979121175"
)

func replyKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	key, err := hex.DecodeString(v3ReplyPublic)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func v3Headers(pairs ...string) func(string) string {
	return headers(append(append(validHeaders(), HeaderVersion, "3"), pairs...)...)
}

func TestTheV3RequestAADIsNEARsPublishedVectorByteForByte(t *testing.T) {
	want, _ := hex.DecodeString(v3AAD)
	if got := requestAAD(replyKey(t), LabelContent); !bytes.Equal(got, want) {
		t.Errorf("requestAAD = %x, want %x", got, want)
	}
}

func TestAFieldNEARsVectorSealedOnV3OpensOnlyUnderItsClientKeyAndLabel(t *testing.T) {
	got, err := open(vectorKey(t), v3Sealed, requestAAD(replyKey(t), LabelContent))
	if err != nil || string(got) != v3Plaintext {
		t.Fatalf("open = %q, %v; want %q", got, err, v3Plaintext)
	}
	other, _ := hex.DecodeString(otherPublicKey)
	for name, aad := range map[string][]byte{
		"no aad, as v2 seals":   nil,
		"another field's label": requestAAD(replyKey(t), "tools[].function.name"),
		"another client's key":  requestAAD(other, LabelContent),
	} {
		if got, err := open(vectorKey(t), v3Sealed, aad); err == nil {
			t.Errorf("%s: open = %q, want an error", name, got)
		}
	}
}

func TestParseHeadersReadsVersion3WithOrWithoutAllFields(t *testing.T) {
	for name, get := range map[string]func(string) string{
		"all fields true": v3Headers(),
		"no all fields":   v3Headers(HeaderAllFields, ""),
	} {
		params, sealed, err := ParseHeaders(get)
		if !sealed || err != nil || !params.V3 || !params.SealsTools() {
			t.Errorf("%s: sealed %t v3 %t err %v, want a v3 request that seals tools", name, sealed, params.V3, err)
		}
		sent := map[string]string{}
		params.Forward(func(name, value string) { sent[name] = value })
		if sent[HeaderVersion] != "3" || sent[HeaderAllFields] != "true" {
			t.Errorf("%s: forwards version %q all-fields %q, want 3 and true", name, sent[HeaderVersion], sent[HeaderAllFields])
		}
	}
	v2, _, err := ParseHeaders(headers(validHeaders()...))
	if err != nil || v2.V3 || v2.SealsTools() {
		t.Errorf("version 2: v3 %t err %v, want a v2 request that seals no tools", v2.V3, err)
	}
	sent := map[string]string{}
	Params{}.Forward(func(name, value string) { sent[name] = value })
	if sent[HeaderVersion] != "2" {
		t.Errorf("params with no version forward %q, want 2, which the worker seals on a client's behalf", sent[HeaderVersion])
	}
}

func TestParseHeadersRefusesVersion3WithAllFieldsOffAndAnyLaterVersion(t *testing.T) {
	for name, tc := range map[string]struct {
		get  func(string) string
		want *e2ee.Error
	}{
		"v3 all fields false": {v3Headers(HeaderAllFields, "false"), ErrPartialFields},
		"version 4":           {v3Headers(HeaderVersion, "4"), ErrInvalidVersion},
	} {
		_, sealed, err := ParseHeaders(tc.get)
		var got *e2ee.Error
		if !sealed || !errors.As(err, &got) || got != tc.want {
			t.Errorf("%s: sealed %t err %v, want %v", name, sealed, err, tc.want)
		}
	}
}

func TestParamsSealAFieldUnderTheV3AADOnlyOnVersion3(t *testing.T) {
	key := vectorKey(t)
	model := key.Public().(ed25519.PublicKey)
	v3 := Params{Client: replyKey(t), Model: model, V3: true}
	sealed, err := v3.Seal(LabelContent, []byte("rules"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := open(key, sealed, requestAAD(replyKey(t), LabelContent)); err != nil || string(got) != "rules" {
		t.Errorf("v3 field under its aad: open = %q, %v", got, err)
	}
	if got, err := Open(key, sealed); err == nil {
		t.Errorf("v3 field with no aad: Open = %q, want an error", got)
	}
	sealed, err = Params{Client: replyKey(t), Model: model}.Seal(LabelContent, []byte("rules"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(key, sealed); err != nil || string(got) != "rules" {
		t.Errorf("v2 field: Open = %q, %v", got, err)
	}
}

func TestTheSchemeListsBothVersionsOldestFirst(t *testing.T) {
	if got := Scheme.Protocols; len(got) != 2 || got[0] != Protocol || got[1] != ProtocolV3 {
		t.Errorf("Scheme.Protocols = %v, want [%s %s]", got, Protocol, ProtocolV3)
	}
}
