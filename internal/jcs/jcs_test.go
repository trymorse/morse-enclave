package jcs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
