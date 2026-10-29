package jcs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"morse/backend/internal/jcs"
)

const (
	probePlaintext        = "Say ok. \u00e9 \"q\" <b>&amp; \u2028 tab\t nl\n \u65e5\u672c"
	probeHead             = `{"model":"moonshotai/kimi-k2.6","messages":[{"role":"user","content":`
	probeBufferedTail     = `}],"max_tokens":16,"provider":{"aci_verified":true,"zdr":true}}`
	probeStreamTail       = `}],"max_tokens":16,"provider":{"aci_verified":true,"zdr":true},"stream":true,"stream_options":{"include_usage":true}}`
	phalaBufferedRequest  = "ec3c055607af73155f9f8098e2f8f3dc1c2ddd08f66f30a2088e0447f6b0e6ed"
	phalaStreamedRequest  = "286c960437992111cf2d8963cd878f95942d1b9575677923fe42f8278e7a2a52"
	probeEscapedPlaintext = "\"Say ok. \u00e9 \\\"q\\\" <b>&amp; \u2028 tab\\t nl\\n \u65e5\u672c\""
)

func TestStringEscapesLikeTheGatewayThatHashedTheProbeRequests(t *testing.T) {
	if got := string(jcs.String(probePlaintext)); got != probeEscapedPlaintext {
		t.Errorf("escaped %q, want %q", got, probeEscapedPlaintext)
	}
	for name, tc := range map[string]struct{ tail, want string }{
		"buffered": {probeBufferedTail, phalaBufferedRequest},
		"streamed": {probeStreamTail, phalaStreamedRequest},
	} {
		restored := probeHead + string(jcs.String(probePlaintext)) + tc.tail
		if got := sha256.Sum256([]byte(restored)); hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("%s: sha256 %x, want Phala's request.received %s", name, got, tc.want)
		}
	}
	goDefault, _ := json.Marshal(probePlaintext)
	if bytes.Equal(goDefault, jcs.String(probePlaintext)) {
		t.Error("the vector does not separate JCS escaping from encoding/json")
	}
}

func TestStringEscapesControlsShortFormsAndNothingElse(t *testing.T) {
	cases := map[string]string{
		"":                   `""`,
		"\x00\x01\x1f":       `"\u0000\u0001\u001f"`,
		"\b\f\n\r\t":         `"\b\f\n\r\t"`,
		`"\`:                 `"\"\\"`,
		"\x7f/<>&'":          "\"\x7f/<>&'\"",
		"\u2028\u2029\ufeff": "\"\u2028\u2029\ufeff\"",
		"\U0001F600":         "\"\U0001F600\"",
	}
	for in, want := range cases {
		if got := string(jcs.String(in)); got != want {
			t.Errorf("String(%q) = %s, want %s", in, got, want)
		}
	}
}

func decode(t *testing.T, src string) any {
	t.Helper()
	v, err := jcs.Decode([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMarshalSortsKeysByUTF16CodeUnitsAndKeepsArraysInOrder(t *testing.T) {
	src := `{"\u00e9":1,"b":[3,null,true,"x"],"a":{"z":"","y":-0},"\ud83d\ude00":2,"\ue000":3}`
	want := "{\"a\":{\"y\":0,\"z\":\"\"},\"b\":[3,null,true,\"x\"],\"\u00e9\":1,\"\U0001F600\":2,\"\ue000\":3}"
	got, err := jcs.Marshal(decode(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("Marshal\n%s\nwant\n%s", got, want)
	}
}

func TestMarshalRefusesNumbersItCannotCanonicalize(t *testing.T) {
	for _, src := range []string{`1.5`, `1e2`, `9007199254740993`, `-9007199254740993`, `{"a":[0.0]}`} {
		if out, err := jcs.Marshal(decode(t, src)); !errors.Is(err, jcs.ErrNumber) {
			t.Errorf("Marshal(%s) = %s, %v; want ErrNumber", src, out, err)
		}
	}
	if out, err := jcs.Marshal(decode(t, `9007199254740992`)); err != nil || string(out) != "9007199254740992" {
		t.Errorf("2^53: %s %v", out, err)
	}
	if _, err := jcs.Marshal(float64(1)); err == nil {
		t.Error("a float64 was canonicalized without UseNumber")
	}
}

func TestDecodeKeepsNumbersExactAndRefusesAnythingButOneJSONValue(t *testing.T) {
	v, err := jcs.Decode([]byte(" {\"n\":9007199254740993} \n"))
	if err != nil || v.(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Errorf("Decode kept %#v, %v", v, err)
	}
	for _, src := range []string{``, `{"a":1`, `{"a":1}{}`, `{"a":1}]`, `1 2`, `"x" x`} {
		if v, err := jcs.Decode([]byte(src)); err == nil {
			t.Errorf("Decode(%q) = %#v, want an error", src, v)
		}
	}
}

func TestCanonicalizeDecodesThenMarshalsAndReportsWhyItCannot(t *testing.T) {
	if got, err := jcs.Canonicalize([]byte(`{"b":[1, true],"a":"\u00e9"}`)); err != nil || string(got) != "{\"a\":\"\u00e9\",\"b\":[1,true]}" {
		t.Errorf("Canonicalize = %s, %v", got, err)
	}
	if _, err := jcs.Canonicalize([]byte(`{"a":1.5}`)); !errors.Is(err, jcs.ErrNumber) {
		t.Errorf("a fraction gave %v, want ErrNumber", err)
	}
	if out, err := jcs.Canonicalize([]byte(`{"a":`)); err == nil || out != nil {
		t.Errorf("truncated JSON canonicalized to %s, %v", out, err)
	}
}
