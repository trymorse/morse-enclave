package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/e2ee/near"
)

const (
	promptCanary        = "PROMPT-CANARY-4b7e"
	completionCanary    = "COMPLETION-CANARY-91c2"
	contentChunk        = `{"id":"c1","choices":[{"index":0,"delta":{"content":"` + completionCanary + `"}}]}`
	testModelKey        = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
	testClientKey       = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	testNonce           = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testSealedMaxOutput = 64
)

var sealHeaders = map[string]string{
	e2ee.HeaderVersion:   "2",
	e2ee.HeaderClientKey: testClientKey,
	e2ee.HeaderModelKey:  testModelKey,
	e2ee.HeaderNonce:     testNonce,
	e2ee.HeaderTimestamp: "1750000000",
}

var nearHeaders = map[string]string{
	near.HeaderSigningAlgo: "ed25519",
	near.HeaderClientKey:   "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
	near.HeaderModelKey:    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
	near.HeaderVersion:     "2",
	near.HeaderAllFields:   "true",
}

func streamBody(extra string) string {
	return `{"model":"m","stream":true` + extra + `,"messages":[{"role":"user","content":"` + promptCanary + `"}]}`
}

func completeBody(extra string) string {
	return `{"model":"m"` + extra + `,"messages":[{"role":"user","content":"` + promptCanary + `"}]}`
}

func tokenFloorOf(body string) int { return (len(body) + 1) / 2 }

func ciphertextHex() string { return strings.Repeat("ab", e2ee.X25519.MinCiphertextHex()/2+8) }

func sealedBody(extra string) string {
	return `{"model":"kimi-e2ee","max_tokens":64,"stream":true` + extra + `,"messages":[{"role":"user","content":"` + ciphertextHex() + `"}]}`
}

func withHeaders(base map[string]string, changes map[string]string) func(string) string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for k, v := range changes {
		m[k] = v
	}
	return func(name string) string { return m[name] }
}

func sealParams(t *testing.T) e2ee.Params {
	t.Helper()
	params, _, err := e2ee.ParseHeaders(withHeaders(sealHeaders, nil))
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func refusalOf(t *testing.T, err error) apierr.Error {
	t.Helper()
	var refusal apierr.Error
	if err != nil && !errors.As(err, &refusal) {
		t.Fatalf("refused with %v, which carries no apierr.Error", err)
	}
	return refusal
}

func parsed(t *testing.T, body string) *chat.Request {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

type fakeRelayer struct{ err error }

func (f fakeRelayer) Check(*chat.Request) error { return f.err }

func (f fakeRelayer) Relay(context.Context, chat.Call, chat.E2EE, func(chat.Relayed) io.Writer) (chat.Replied, error) {
	panic("admission must not relay")
}

type fakeAttester struct{}

func (fakeAttester) Attest(context.Context, string) (chat.Attestation, error) {
	panic("routes must not attest")
}

type fakeReceipter struct{}

func (fakeReceipter) Receipt(context.Context, string) (json.RawMessage, error) {
	panic("routes must not fetch a receipt")
}

type fakeVerbatimRoute struct {
	chat.Relayer
	chat.Attester
	chat.Receipter
}

func (fakeVerbatimRoute) Speaks() *chat.Scheme { return e2ee.Scheme }

func (fakeVerbatimRoute) SealPrompt(chat.E2EE, string) (string, error) {
	panic("routes must not seal a prompt")
}

type nearVerbatimRoute struct{ fakeVerbatimRoute }

func (nearVerbatimRoute) Speaks() *chat.Scheme { return near.Scheme }

type panickingProvider struct{ chunksBeforePanic int }

func (p panickingProvider) Stream(_ context.Context, _ chat.Call, emit func(chat.Chunk) error) (chat.Usage, error) {
	for range p.chunksBeforePanic {
		emit(chat.NewChunk([]byte(contentChunk)))
	}
	panic("provider bug")
}

func (panickingProvider) Complete(context.Context, chat.Call) (chat.Chunk, chat.Usage, error) {
	panic("provider bug")
}
