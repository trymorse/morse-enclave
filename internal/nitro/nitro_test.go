package nitro

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"

	"morse/backend/internal/nitro/verify"
)

type recordingSession struct {
	sent   []request.Request
	reply  response.Response
	err    error
	closed bool
}

func (s *recordingSession) Send(r request.Request) (response.Response, error) {
	s.sent = append(s.sent, r)
	return s.reply, s.err
}

func (s *recordingSession) Close() error {
	s.closed = true
	return nil
}

func somePublicKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func TestTheDocumentRequestCarriesOnlyThePrefixedEnvironmentAndKeyAndNoCallerBytes(t *testing.T) {
	key := somePublicKey()
	sess := &recordingSession{reply: response.Response{Attestation: &response.Attestation{Document: []byte("cose")}}}
	doc, err := NSM{open: func() (session, error) { return sess, nil }}.Attest(context.Background(), "prod", key)
	if err != nil || string(doc) != "cose" {
		t.Fatalf("document %q, %v", doc, err)
	}
	if len(sess.sent) != 1 || !sess.closed {
		t.Fatalf("%d requests sent, closed %t", len(sess.sent), sess.closed)
	}
	req, ok := sess.sent[0].(*request.Attestation)
	if !ok {
		t.Fatalf("sent %T", sess.sent[0])
	}
	want := append([]byte("morse-proxy-hpke-v1|prod|"), key...)
	if !bytes.Equal(req.UserData, want) {
		t.Errorf("user_data %q, want %q", req.UserData, want)
	}
	if req.Nonce != nil || req.PublicKey != nil {
		t.Errorf("the request carries nonce %x and public_key %x; the document must hold nothing a caller chose", req.Nonce, req.PublicKey)
	}
}

func TestAModuleErrorOrAnEmptyReplyIsAnError(t *testing.T) {
	for name, sess := range map[string]*recordingSession{
		"module error": {reply: response.Response{Error: response.ErrorCode("InvalidArgument")}},
		"no document":  {reply: response.Response{Attestation: &response.Attestation{}}},
		"no field":     {reply: response.Response{}},
		"send failed":  {err: errors.New("ioctl")},
	} {
		_, err := NSM{open: func() (session, error) { return sess, nil }}.Attest(context.Background(), "dev", somePublicKey())
		if err == nil || !strings.HasPrefix(err.Error(), "nitro: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := NSM{open: func() (session, error) { return nil, errors.New("no device") }}.Attest(context.Background(), "dev", somePublicKey())
	if err == nil {
		t.Error("an unopenable module attested")
	}
}

func TestTheStandInNamesItselfAndCarriesTheKeyForADevClient(t *testing.T) {
	key := somePublicKey()
	doc, err := Dev{}.Attest(context.Background(), "dev", key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(doc, []byte(`{"object":"proxy_attestation_stand_in","warning":"not an AWS Nitro attestation`)) {
		t.Errorf("stand-in %s does not announce itself first", doc)
	}
	standIn, err := verify.ParseStandIn(doc)
	if err != nil || standIn.Environment != "dev" || !bytes.Equal(standIn.PublicKey, key) || time.Since(standIn.IssuedAt) > time.Minute {
		t.Errorf("parsed %+v %v", standIn, err)
	}
}

func TestOffAnEnclaveTheAttesterIsTheStandIn(t *testing.T) {
	if _, err := os.Stat(devicePath); err == nil {
		t.Skip("this machine has /dev/nsm")
	}
	if _, ok := Open().(Dev); !ok {
		t.Errorf("Open() is %T, want Dev", Open())
	}
}

func TestTheDevKeyFixesTheKeyOffAnEnclaveAndIsRefusedOnOne(t *testing.T) {
	devKey := strings.Repeat("a1", 32)
	a, err := Key(Dev{}, devKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Key(Dev{}, devKey)
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Error("one dev key gave two keys")
	}
	fresh, _ := Key(Dev{}, "")
	if bytes.Equal(fresh.PublicKey(), a.PublicKey()) {
		t.Error("no dev key gave the dev key's key")
	}
	if _, err := Key(NSM{}, devKey); err == nil || !strings.Contains(err.Error(), "PROXY_HPKE_DEV_KEY") {
		t.Errorf("a dev key on an enclave: %v, want a refusal naming the variable", err)
	}
	if _, err := Key(Dev{}, "abc"); err == nil {
		t.Error("a short dev key was taken")
	}
}
