package near

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/attestation"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	wire "morse/backend/internal/e2ee/near"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	reportPath    = "/v1/attestation/report"
	signaturePath = "/v1/signature/"
	maxReport     = 16 << 20
	maxSignature  = 1 << 20
)

var (
	receiptID         = regexp.MustCompile(`^(?:[0-9a-f]{32}|chatcmpl-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	errInvalidReceipt = &chat.InvalidReceiptID{Form: "32 lowercase hexadecimal characters, or chatcmpl- followed by a lowercase UUID"}
	errKeyRotated     = fmt.Errorf("%w: NEAR no longer holds the pinned model key", apierr.ErrUnattested)
	errInvalidNonce   = &chat.InvalidNonce{Form: "exactly 64 hexadecimal characters for this model, the 32 bytes NEAR binds into its report"}
)

type SigningKey [32]byte

func (k SigningKey) String() string { return hex.EncodeToString(k[:]) }

type Gate interface {
	Ready() bool
	Holds(SigningKey) bool
	// Held is a key a verified report lists now, the least in byte order.
	Held() (SigningKey, bool)
	Forget(SigningKey)
}

// gpuDeadline bounds NVIDIA's judgment, so a slow NRAS withholds the verdicts instead of holding
// back NEAR's report, which the client needs either way.
const gpuDeadline = 10 * time.Second

type GPUVerdicts func(ctx context.Context, report []byte, nonce attestation.Nonce) map[string]attestation.GPUVerdict

type Gateway struct{ upstream.Endpoint }

type Route struct {
	Gateway
	model    string
	gate     Gate
	gpu      GPUVerdicts
	relay    openaicompat.Relay
	onBehalf openaicompat.Provider
}

var (
	_ chat.Attester  = (*Route)(nil)
	_ chat.Relayer   = (*Route)(nil)
	_ chat.Receipter = (*Route)(nil)
)

func NewGateway(baseURL, apiKey string, client *http.Client) Gateway {
	return Gateway{upstream.Objects(baseURL, apiKey, client)}
}

func New(baseURL, upstreamModel, apiKey string, client *http.Client, gate Gate, gpu GPUVerdicts) *Route {
	gateway := NewGateway(baseURL, apiKey, client)
	sealed := gateway.Endpoint
	sealed.Refuse = refuseSealed
	return &Route{
		Gateway:  gateway,
		model:    upstreamModel,
		gate:     gate,
		gpu:      gpu,
		relay:    openaicompat.Relay{Endpoint: sealed, Model: upstreamModel, Receipt: openaicompat.ReceiptFromReplyID},
		onBehalf: openaicompat.Provider{Sender: openaicompat.SealedSender{Endpoint: sealed, Sealer: sealer{gate}}, Model: upstreamModel, LimitField: openaicompat.MaxTokens, KeepEnvelope: true},
	}
}

func (*Route) Speaks() *chat.Scheme { return wire.Scheme }

func (r *Route) Check(req *chat.Request) error { return r.relay.Check(req) }

func (r *Route) heldKey(sealed chat.E2EE) (SigningKey, error) {
	named := sealed.ModelKey()
	if len(named) != len(SigningKey{}) {
		return SigningKey{}, fmt.Errorf("near: the request names a %d-byte model key, not an ed25519 one", len(named))
	}
	key := SigningKey(named)
	if !r.gate.Holds(key) {
		return SigningKey{}, fmt.Errorf("%w: no verified NEAR report lists model key %s", apierr.ErrUnattested, key)
	}
	return key, nil
}

func (r *Route) Relay(ctx context.Context, c chat.Call, sealed chat.E2EE, begin func(chat.Relayed) io.Writer) (chat.Replied, error) {
	key, err := r.heldKey(sealed)
	if err != nil {
		return chat.Replied{}, err
	}
	replied, err := r.relay.Relay(ctx, c, sealed, begin)
	if errors.Is(err, errKeyRotated) {
		r.gate.Forget(key)
	}
	return replied, err
}

func (r *Route) SealPrompt(sealed chat.E2EE, prompt string) (string, error) {
	key, err := r.heldKey(sealed)
	if err != nil {
		return "", err
	}
	return wire.Seal(key[:], []byte(prompt))
}

func (r *Route) OnBehalf() chat.Provider { return &r.onBehalf }

type sealer struct{ gate Gate }

func (s sealer) Seal(call func(openaicompat.Sealing) error) error {
	key, ok := s.gate.Held()
	if !ok {
		return fmt.Errorf("%w: no verified NEAR report lists a model key", apierr.ErrUnattested)
	}
	client, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = call(sealing{Params: wire.Params{Client: client, Model: key[:]}, client: private})
	if errors.Is(err, errKeyRotated) {
		s.gate.Forget(key)
	}
	return err
}

type sealing struct {
	wire.Params
	client ed25519.PrivateKey
}

func (s sealing) SealContent(_ int, plaintext string) (string, error) {
	return wire.Seal(s.Model, []byte(plaintext))
}

func (s sealing) Open(_ string, _ e2ee.ResponseField, sealed string) ([]byte, error) {
	return wire.Open(s.client, sealed)
}

func (r *Route) Attest(ctx context.Context, nonce string) (chat.Attestation, error) {
	bound, err := hex.DecodeString(nonce)
	if err != nil || len(bound) != 32 {
		return chat.Attestation{}, errInvalidNonce
	}
	if !r.gate.Ready() {
		return chat.Attestation{}, apierr.ErrUnattested
	}
	report, err := r.Report(ctx, r.model, hex.EncodeToString(bound))
	if err != nil {
		return chat.Attestation{}, err
	}
	judging, cancel := context.WithTimeout(ctx, gpuDeadline)
	defer cancel()
	verdicts, err := json.Marshal(r.gpu(judging, report, attestation.Nonce(bound)))
	if err != nil {
		return chat.Attestation{}, err
	}
	return chat.Attestation{Report: report, BindModel: r.model, GPUVerdicts: verdicts}, nil
}

func (r *Route) Receipt(ctx context.Context, id string) (json.RawMessage, error) {
	if !receiptID.MatchString(id) {
		return nil, errInvalidReceipt
	}
	if !r.gate.Ready() {
		return nil, apierr.ErrUnattested
	}
	signature, err := r.Object(ctx, signaturePath+id+"?signing_algo=ed25519", maxSignature)
	if errors.Is(err, upstream.ErrNotFound) {
		return nil, chat.ErrReceiptNotFound
	}
	return signature, err
}

func (g Gateway) Report(ctx context.Context, model, nonce string) ([]byte, error) {
	query := url.Values{"model": {model}, "nonce": {nonce}, "signing_algo": {"ed25519"}, "include_tls_fingerprint": {"true"}, "provider": {"near"}}
	return g.Object(ctx, reportPath+"?"+query.Encode(), maxReport)
}

func refuseSealed(reply upstream.Reply) error {
	if reply.Status == http.StatusMisdirectedRequest {
		return errKeyRotated
	}
	return apierr.SanitizedUpstreamError(reply.Status, reply.Body)
}
