package tinfoil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/upstream"
)

const (
	chatCompletionsPath = "/v1/chat/completions"
	// keyConfigProblem is the problem type the router answers a request sealed to a key it no longer holds
	// with, before it reads any of it.
	keyConfigProblem = "urn:ietf:params:ehbp:error:key-config"
	// busyRetries is how often a request the router turned away as busy is sent again: it read none of it,
	// and each reply carries a nonce of its own, so the same ciphertext may go again.
	busyRetries = 2
)

var (
	errKeyStale       = fmt.Errorf("%w: the Tinfoil router no longer holds the key the request was sealed to", apierr.ErrUnattested)
	errNoPrompt       = errors.New("tinfoil: a request sealed whole takes no prompt from the proxy")
	errInvalidNonce   = &chat.InvalidNonce{Form: "64 lowercase hexadecimal characters; Tinfoil's report binds no nonce, so it is not sent on"}
	errInvalidNonceV3 = &chat.InvalidNonce{Form: "64 lowercase hexadecimal characters, the 32 bytes Tinfoil's v3 document binds"}
)

// Gate is the attestation gate the route's client is pinned through: whether it holds a verified report, the
// bundle it verified, and a way to ask it to verify the router again, at most once a minute, keeping the report
// it holds until another verifies. A key-config refusal is no reason to drop the report: the router answers
// any body whose first frame doesn't open under its key so, a stale client's or a forged one alike.
type Gate interface {
	Ready() bool
	Report() json.RawMessage
	Wake()
}

// Route relays requests sealed whole (EHBP) to Tinfoil's router over the gate's pinned client. It reads
// none of a request or a reply: the clear headers name the model and the limit, and the router counts usage
// outside the seal.
type Route struct {
	endpoint  upstream.Endpoint
	wellKnown upstream.Endpoint
	host      string
	model     string
	gate      Gate
	wait      func(context.Context, time.Duration) error
}

var (
	_ chat.VerbatimRoute = (*Route)(nil)
)

func New(baseURL, host, upstreamModel, apiKey string, pinned *http.Client, gate Gate) *Route {
	return &Route{
		endpoint:  upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: pinned, Refuse: refuseSealed},
		wellKnown: upstream.Objects(baseURL, "", pinned),
		host:      host,
		model:     upstreamModel,
		gate:      gate,
		wait:      sleep,
	}
}

func (*Route) Speaks() *chat.Scheme { return ehbp.Scheme }

// Check holds the request to the route's model, which the header names; the router refuses a sealed body that
// names another.
func (r *Route) Check(req *chat.Request) error {
	if req.Model != r.model {
		want, _ := json.Marshal(r.model)
		return &chat.Mismatch{Field: "model", Want: want}
	}
	return nil
}

func (r *Route) Relay(ctx context.Context, c chat.Call, sealed chat.E2EE, begin func(chat.Relayed) io.Writer) (chat.Replied, error) {
	if !r.gate.Ready() {
		return chat.Replied{}, apierr.ErrUnattested
	}
	header := http.Header{
		"Accept":             {"text/event-stream"},
		"Content-Type":       {"application/json"},
		ehbp.HeaderModel:     {r.model},
		ehbp.HeaderMaxOutput: {strconv.Itoa(c.OutputLimit)},
		// One choice: the router writes it over the sealed body's n, so the output limit bounds the reply.
		ehbp.HeaderCompletionCount: {"1"},
		ehbp.HeaderRequestUsage:    {"true"},
	}
	sealed.Forward(header.Set)
	resp, err := r.open(ctx, header, c.Verbatim())
	if errors.Is(err, errKeyStale) {
		r.gate.Wake()
	}
	if err != nil {
		return chat.Replied{}, err
	}
	defer resp.Body.Close()
	if err := sealed.Confirm(resp.Header.Get); err != nil {
		return chat.Replied{}, err
	}
	w := begin(chat.Relayed{
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     []chat.Header{{Name: ehbp.HeaderResponseNonce, Value: resp.Header.Get(ehbp.HeaderResponseNonce)}},
	})
	tokens := 0
	frames, err := ehbp.Frames(resp.Body, ehbp.MaxFrame, func(frame []byte) error {
		tokens += ehbp.FrameTokens(len(frame))
		_, err := w.Write(frame)
		return err
	})
	replied := chat.Replied{Events: frames, Tokens: min(tokens, max(c.OutputLimit, 1))}
	if err == nil {
		replied.Usage = r.usage(resp)
	}
	return replied, err
}

// open sends the sealed body, again when the router turns it away as busy before reading it.
func (r *Route) open(ctx context.Context, header http.Header, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := r.endpoint.Open(ctx, upstream.Request{Method: http.MethodPost, Path: chatCompletionsPath, Header: header, Body: body})
		var refused upstream.Refused
		if attempt == busyRetries || !errors.As(err, &refused) || (refused.Status != http.StatusTooManyRequests && refused.Status != http.StatusServiceUnavailable) {
			return resp, err
		}
		if err := r.wait(ctx, time.Duration(attempt+1)*time.Second); err != nil {
			return nil, err
		}
	}
}

// usage is what the router counted, from the trailer a stream ends with or the header of a reply in one
// piece, unless it is unreadable or names another model.
func (r *Route) usage(resp *http.Response) chat.Usage {
	metrics := resp.Trailer.Get(ehbp.HeaderUsageMetrics)
	if metrics == "" {
		metrics = resp.Header.Get(ehbp.HeaderUsageMetrics)
	}
	usage, model, err := ehbp.ParseUsageMetrics(metrics)
	if err != nil || model != "" && model != r.model {
		return chat.Usage{}
	}
	return usage
}

func refuseSealed(reply upstream.Reply) error {
	if reply.Status == http.StatusUnprocessableEntity && bytes.Contains(reply.Body, []byte(keyConfigProblem)) {
		return errKeyStale
	}
	return apierr.SanitizedUpstreamError(reply.Status, reply.Body)
}

func (r *Route) SealPrompt(chat.E2EE, string) (string, error) { return "", errNoPrompt }

// OnBehalf serves none: sealing a plaintext chat for its client would mean sealing its whole body, which the
// worker doesn't, so a plaintext chat on a Tinfoil model's id runs on its plaintext routes.
func (*Route) OnBehalf() chat.Provider { return nil }

// Attest serves the v2 bundle the gate verified. The bundle binds no nonce, so the nonce is only checked for its
// form, and the bundle is the one whose TLS key the client is pinned to and whose HPKE key the router holds.
func (r *Route) Attest(_ context.Context, nonce string) (chat.Attestation, error) {
	if _, ok := ehbp.LowerHex(nonce, ehbp.NonceLen); !ok {
		return chat.Attestation{}, errInvalidNonce
	}
	report := r.gate.Report()
	if !r.gate.Ready() || report == nil {
		return chat.Attestation{}, apierr.ErrUnattested
	}
	return chat.Attestation{Report: report, BindModel: r.model}, nil
}

// AttestV3 fetches the router's v3 document for nonce over the gate's pinned client, again once if the router
// answered a 5xx: the guest makes each quote in one buffer, so a burst of attestations can find it busy. Any
// other failure fails the attestation; it never falls back to v2.
func (r *Route) AttestV3(ctx context.Context, nonce string) (chat.Attestation, error) {
	if _, ok := ehbp.LowerHex(nonce, ehbp.NonceLen); !ok {
		return chat.Attestation{}, errInvalidNonceV3
	}
	if !r.gate.Ready() {
		return chat.Attestation{}, apierr.ErrUnattested
	}
	report, err := nonced(ctx, r.wellKnown, r.host, nonce)
	var refused upstream.Refused
	if errors.As(err, &refused) && refused.Status >= 500 {
		if err := r.wait(ctx, 50*time.Millisecond+rand.N(100*time.Millisecond)); err != nil {
			return chat.Attestation{}, err
		}
		report, err = nonced(ctx, r.wellKnown, r.host, nonce)
	}
	if err != nil {
		return chat.Attestation{}, err
	}
	return chat.Attestation{Report: report, BindModel: r.model}, nil
}

// Receipt finds none: the router signs no receipt, so a reply's proof is the attested key it opened under.
func (*Route) Receipt(context.Context, string) (json.RawMessage, error) {
	return nil, chat.ErrReceiptNotFound
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
