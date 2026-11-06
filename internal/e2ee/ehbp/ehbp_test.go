package ehbp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"testing"

	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
)

const encHex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

func headers(kv ...string) func(string) string {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h.Get
}

func TestParseNamesTheModelAndLimitTheProxyCantReadInsideTheBody(t *testing.T) {
	params, sealed, err := Scheme.Parse(headers(HeaderEncapsulatedKey, encHex, HeaderModel, "glm-5-3", HeaderMaxOutput, "4096"))
	if err != nil || !sealed {
		t.Fatalf("sealed %v, err %v", sealed, err)
	}
	p := params.(chat.BodySealed)
	if p.SealedModel() != "glm-5-3" || p.OutputLimit() != 4096 || p.ModelKey() != nil || p.IsCiphertext([]byte(`"x"`)) || !p.ConfirmsEncryption() {
		t.Fatalf("%+v", p)
	}
	h := http.Header{}
	p.Forward(h.Set)
	if len(h) != 1 || h.Get(HeaderEncapsulatedKey) != encHex {
		t.Fatalf("forwarded %v: the route names the model and limit itself", h)
	}
}

func TestParseRefusesAPartialOrMalformedRequest(t *testing.T) {
	if _, sealed, _ := Scheme.Parse(headers()); sealed {
		t.Fatal("no EHBP header is no EHBP request")
	}
	for name, tc := range map[string]struct {
		get  func(string) string
		want error
	}{
		"no model":         {headers(HeaderEncapsulatedKey, encHex, HeaderMaxOutput, "1"), ErrHeaderMissing},
		"no limit":         {headers(HeaderEncapsulatedKey, encHex, HeaderModel, "glm-5-3"), ErrHeaderMissing},
		"no key":           {headers(HeaderModel, "glm-5-3", HeaderMaxOutput, "1"), ErrHeaderMissing},
		"an uppercase key": {headers(HeaderEncapsulatedKey, strings.ToUpper(encHex), HeaderModel, "m", HeaderMaxOutput, "1"), ErrInvalidKey},
		"a short key":      {headers(HeaderEncapsulatedKey, encHex[:62], HeaderModel, "m", HeaderMaxOutput, "1"), ErrInvalidKey},
		"a zero limit":     {headers(HeaderEncapsulatedKey, encHex, HeaderModel, "m", HeaderMaxOutput, "0"), ErrInvalidLimit},
		"a text limit":     {headers(HeaderEncapsulatedKey, encHex, HeaderModel, "m", HeaderMaxOutput, "lots"), ErrInvalidLimit},
	} {
		t.Run(name, func(t *testing.T) {
			if _, sealed, err := Scheme.Parse(tc.get); !sealed || !errors.Is(err, tc.want) {
				t.Fatalf("sealed %v, err %v, want %v", sealed, err, tc.want)
			}
		})
	}
}

func TestConfirmRequiresTheResponseNonce(t *testing.T) {
	p := Params{}
	if err := p.Confirm(headers(HeaderResponseNonce, strings.Repeat("ab", 32))); err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"", strings.Repeat("ab", 16), strings.Repeat("AB", 32)} {
		if err := p.Confirm(headers(HeaderResponseNonce, nonce)); !errors.Is(err, e2ee.ErrNotApplied) {
			t.Errorf("nonce %q: %v", nonce, err)
		}
	}
}

func TestFramesHandsOnEachFrameWholeAndCountsTheSealedOnes(t *testing.T) {
	body := slicesConcat(frame(bytes.Repeat([]byte{1}, 20)), []byte{0, 0, 0, 0}, frame(bytes.Repeat([]byte{2}, 40)))
	var relayed bytes.Buffer
	n, err := Frames(bytes.NewReader(body), MaxFrame, func(f []byte) error { relayed.Write(f); return nil })
	if err != nil || n != 2 || !bytes.Equal(relayed.Bytes(), body) {
		t.Fatalf("n %d, err %v, relayed %x", n, err, relayed.Bytes())
	}
}

func TestFramesRefusesPlaintextAndTruncation(t *testing.T) {
	for name, tc := range map[string]struct {
		body []byte
		want error
	}{
		"plaintext SSE":       {[]byte("data: {\"choices\":[]}\n\n"), chat.ErrUnsealedReply},
		"plaintext JSON":      {[]byte(`{"error":"x"}`), chat.ErrUnsealedReply},
		"a frame under a tag": {frame([]byte{1, 2, 3}), chat.ErrUnsealedReply},
		"a cut header":        {[]byte{0, 0}, ErrTruncated},
		"a cut frame":         {frame(bytes.Repeat([]byte{1}, 40))[:30], ErrTruncated},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Frames(bytes.NewReader(tc.body), MaxFrame, func([]byte) error { return nil }); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseUsageMetricsReadsNamedFieldsInAnyOrder(t *testing.T) {
	u, model, err := ParseUsageMetrics("completion=30,model=deepseek-v4-1-flash,prompt=2000,total=2030,cached_prompt_tokens=1500,uncached_prompt_tokens=500,cost_usd=0.001")
	if err != nil || model != "deepseek-v4-1-flash" || u != (chat.Usage{PromptTokens: 2000, CompletionTokens: 30, CachedPromptTokens: 1500}) {
		t.Fatalf("%+v %q %v", u, model, err)
	}
	for _, bad := range []string{"", "prompt=1", "completion=1", "prompt=x,completion=1", "prompt=1,completion=-1", "prompt=1;completion=2"} {
		if _, _, err := ParseUsageMetrics(bad); !errors.Is(err, ErrUsage) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func slicesConcat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func frame(sealed []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(sealed))), sealed...)
}

// Frames of GLM 5.3's and DeepSeek V4.1 Flash's live replies through Tinfoil's router (2026-11-03): each
// frame's size, its length header included, and the completion tokens its running usage grew by.
func TestAFramesTokenEstimateIsNeverBelowWhatALiveFrameCarried(t *testing.T) {
	for _, f := range []struct{ size, tokens int }{
		{21, 0}, {33, 0}, {34, 0}, // bare line breaks and the closing [DONE]
		{377, 1}, {387, 2}, {398, 3}, {407, 6}, {412, 6}, {414, 6}, // text and reasoning events
		{479, 7}, {447, 9}, {492, 12}, {735, 93}, // tool-call arguments
	} {
		if got := FrameTokens(f.size); got < f.tokens {
			t.Errorf("a %d-byte frame carried %d tokens, estimated %d", f.size, f.tokens, got)
		}
	}
	if got := FrameTokens(21); got != 0 {
		t.Errorf("a frame of a bare line break is estimated %d tokens, want 0", got)
	}
	if got := FrameTokens(400); got != 6 {
		t.Errorf("an event frame is estimated %d tokens, want 6", got)
	}
}
