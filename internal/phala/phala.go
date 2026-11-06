package phala

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/apierr"
	"morse/backend/internal/attestation"
	"morse/backend/internal/capped"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	attestationPath = "/v1/aci/attestation"
	receiptsPath    = "/v1/aci/receipts/"
	sessionsPath    = "/v1/aci/sessions/"
	sessionListPath = "/v1/aci/sessions"
	maxReport       = 4 << 20
	maxReceipt      = 1 << 20
	// A phala-direct record with eight GPUs is about 500 KB. Chutes records run 2.4 MB and up, and no client
	// checks them, so the cap refuses them before they are read whole.
	maxSession = 1 << 20
	// The list carries each session's claims without its evidence, about 1.6 KB a session.
	maxSessionList = 4 << 20
)

var (
	receiptID         = regexp.MustCompile(`^rcpt-[0-9a-f]{24}$`)
	errInvalidReceipt = &chat.InvalidReceiptID{Form: "rcpt- followed by 24 lowercase hexadecimal characters"}
)

const Constraint = `{"aci_verified":true,"zdr":true}`

// MaxPinnedSessions bounds the aci_session_ids a sealed request may pin.
const MaxPinnedSessions = 16

// admitsProvider accepts the constraint with aci_session_ids added: a browser that audited those sessions
// pins its message to them, and the gateway refuses it with 412 session_not_accepted when it cannot keep that.
// The constraint itself still binds, and no other key passes.
func admitsProvider(raw json.RawMessage) bool {
	var p struct {
		ACIVerified *bool    `json:"aci_verified"`
		ZDR         *bool    `json:"zdr"`
		Sessions    []string `json:"aci_session_ids"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.More() || p.ACIVerified == nil || !*p.ACIVerified || p.ZDR == nil || !*p.ZDR {
		return false
	}
	if len(p.Sessions) == 0 || len(p.Sessions) > MaxPinnedSessions {
		return false
	}
	seen := map[string]bool{}
	for _, id := range p.Sessions {
		if !chat.ValidSessionID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

var errSessionNotAccepted = apierr.Error{Status: http.StatusPreconditionFailed, Type: "invalid_request_error", Code: "session_not_accepted", Message: "The gateway would not send the message to a session it pins. Nothing was forwarded."}

// refuseSealed relays the gateway's refusal to keep a request's pinned sessions as itself, since the
// browser answers it by pinning again, and sanitizes every other refusal. A 403 that would stand as
// upstream_refused and whose message opens with Phala's documented "Balance is too low" refuses our
// account, not the request, so it fails over as the 402 of an empty account does. The match anchors at the
// start and yields to any vendor code, so a content refusal that echoes a prompt never fails over.
func refuseSealed(r upstream.Reply) error {
	var body struct {
		Error struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	parsed := json.Unmarshal(r.Body, &body) == nil
	if parsed && r.Status == http.StatusPreconditionFailed && body.Error.Code == errSessionNotAccepted.Code {
		return errSessionNotAccepted
	}
	refusal := apierr.SanitizedUpstreamError(r.Status, r.Body)
	if refusal == apierr.ErrUpstreamRefused && r.Status == http.StatusForbidden && balanceTooLow(body.Error.Message) {
		return apierr.ErrUpstreamUnavailable
	}
	return refusal
}

func balanceTooLow(message string) bool {
	m := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(message)), "your ")
	return strings.HasPrefix(m, "balance is too low")
}

var constraint = map[string]json.RawMessage{"provider": json.RawMessage(Constraint)}

type Gateway struct{ upstream.Endpoint }

type Route struct {
	openaicompat.Provider
	Gateway
	verbatim openaicompat.Relay
	onBehalf openaicompat.Provider
	keys     Keys
}

type Keys interface {
	Holds(key []byte) bool
	HeldX25519() (*ecdh.PublicKey, bool)
	Keyset(digest aci.Hash) (aci.Keyset, bool)
}

var (
	_ chat.Provider  = (*Route)(nil)
	_ chat.Attester  = (*Route)(nil)
	_ chat.Relayer   = (*Route)(nil)
	_ chat.Receipter = (*Route)(nil)
	_ chat.Sessioner = (*Route)(nil)
)

func NewGateway(baseURL, apiKey string, client *http.Client) Gateway {
	return Gateway{upstream.Objects(baseURL, apiKey, client)}
}

// Clients are the two ways a route reaches its gateway. A prompt in the clear travels only on Plaintext.
// Sealed carries what its reader checks against the enclave's quote: a sealed body, the report, a receipt.
type Clients struct {
	Plaintext *http.Client
	Sealed    *http.Client
}

func New(baseURL, upstreamModel, apiKey string, clients Clients, keys Keys) *Route {
	objects := NewGateway(baseURL, apiKey, clients.Sealed)
	sealed := objects.Endpoint
	sealed.Refuse = refuseSealed
	plaintext := sealed
	plaintext.HTTP = clients.Plaintext
	provider := func(sender openaicompat.Sender) openaicompat.Provider {
		return openaicompat.Provider{Sender: sender, Model: upstreamModel, Force: maps.Clone(constraint), LimitField: openaicompat.MaxTokens, KeepEnvelope: true, ContinuousUsage: true}
	}
	return &Route{
		Provider: provider(openaicompat.HTTPSender{Endpoint: plaintext}),
		Gateway:  objects,
		verbatim: openaicompat.Relay{Endpoint: sealed, Model: upstreamModel, Force: maps.Clone(constraint), Admits: map[string]func(json.RawMessage) bool{"provider": admitsProvider}, Receipt: openaicompat.ReceiptHeaders(chat.ReceiptHeaders...), Proves: objects.prover(upstreamModel, keys)},
		onBehalf: provider(openaicompat.SealedSender{Endpoint: plaintext, Sealer: sealer{model: upstreamModel, keys: keys}}),
		keys:     keys,
	}
}

func (*Route) Speaks() *chat.Scheme { return e2ee.Scheme }

func (r *Route) Check(req *chat.Request) error { return r.verbatim.Check(req) }

func (r *Route) Relay(ctx context.Context, c chat.Call, sealed chat.E2EE, begin func(chat.Relayed) io.Writer) (chat.Replied, error) {
	return r.verbatim.Relay(ctx, c, sealed, begin)
}

var errSuiteNotSealable = apierr.Invalid(http.StatusBadRequest, "e2ee_suite_refused", "A launch character's chat on this model takes the X25519 suite alone, the one the proxy seals the character's prompt under.")

// SealPrompt seals prompt as messages.0.content, which the client's own messages follow from messages.1.
func (r *Route) SealPrompt(sealed chat.E2EE, prompt string) (string, error) {
	p, ok := sealed.(e2ee.Params)
	switch {
	case !ok:
		return "", fmt.Errorf("phala: a request sealed under %T", sealed)
	case p.Suite() != e2ee.X25519:
		return "", errSuiteNotSealable
	case r.keys == nil || !r.keys.Holds(p.ModelKey()):
		return "", fmt.Errorf("%w: no verified Phala keyset lists model key %x", apierr.ErrUnattested, p.ModelKey())
	}
	key, err := p.ModelX25519()
	if err != nil {
		return "", err
	}
	return e2ee.Seal(key, p.RequestAAD(r.verbatim.Model, 0), []byte(prompt))
}

func (r *Route) OnBehalf() chat.Provider { return &r.onBehalf }

type sealer struct {
	model string
	keys  Keys
}

func (s sealer) Seal(call func(openaicompat.Sealing) error) error {
	if s.keys == nil {
		return fmt.Errorf("%w: no verified Phala keyset", apierr.ErrUnattested)
	}
	model, ok := s.keys.HeldX25519()
	if !ok {
		return fmt.Errorf("%w: no verified Phala keyset lists an X25519 key", apierr.ErrUnattested)
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	params, err := e2ee.NewParams(client, model, time.Now().Unix())
	if err != nil {
		return err
	}
	return call(sealing{Params: params, client: client, model: model, name: s.model})
}

type sealing struct {
	e2ee.Params
	client *ecdh.PrivateKey
	model  *ecdh.PublicKey
	name   string
}

func (s sealing) SealContent(message int, plaintext string) (string, error) {
	return e2ee.Seal(s.model, s.RequestAAD(s.name, message), []byte(plaintext))
}

func (s sealing) Open(replyID string, f e2ee.ResponseField, sealed string) ([]byte, error) {
	return e2ee.Open(s.client, s.ResponseAAD(s.name, replyID, f), sealed)
}

func (r *Route) Attest(ctx context.Context, nonce string) (chat.Attestation, error) {
	report, err := r.Report(ctx, nonce)
	if err != nil {
		return chat.Attestation{}, err
	}
	return chat.Attestation{Report: report, BindModel: r.Model}, nil
}

func (g Gateway) Report(ctx context.Context, nonce string) ([]byte, error) {
	return g.Object(ctx, attestationPath+"?nonce="+url.QueryEscape(nonce), maxReport)
}

func (g Gateway) Receipt(ctx context.Context, id string) (json.RawMessage, error) {
	if raw, ok := kept.get(id); ok {
		receiptsKept.Add("hits", 1)
		return raw, nil
	}
	receiptsKept.Add("misses", 1)
	return g.fetchReceipt(ctx, id)
}

func (g Gateway) fetchReceipt(ctx context.Context, id string) (json.RawMessage, error) {
	if !receiptID.MatchString(id) {
		return nil, errInvalidReceipt
	}
	receipt, err := g.Object(ctx, receiptsPath+id, maxReceipt)
	if errors.Is(err, upstream.ErrNotFound) {
		return nil, chat.ErrReceiptNotFound
	}
	return receipt, err
}

func (g Gateway) Session(ctx context.Context, id string) (json.RawMessage, error) {
	if !chat.ValidSessionID(id) {
		return nil, chat.ErrInvalidSessionID
	}
	session, err := g.Object(ctx, sessionsPath+id, maxSession)
	switch {
	case errors.Is(err, upstream.ErrNotFound):
		return nil, chat.ErrSessionNotFound
	case errors.Is(err, capped.ErrTooLarge):
		return nil, fmt.Errorf("%w: %w", chat.ErrSessionTooLarge, err)
	}
	return session, err
}

// Listed is one session the gateway lists, with what says whose it is.
type Listed struct {
	chat.ListedSession
	Verifier string
	Model    string
}

// Sessions lists every session the gateway holds now, for every model. A phala-direct one with an id that
// is not a session id fails the list, since a browser could never fetch its record.
func (g Gateway) Sessions(ctx context.Context) ([]Listed, error) {
	raw, err := g.Object(ctx, sessionListPath, maxSessionList)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Sessions []struct {
			ID            string `json:"session_id"`
			VerifierID    string `json:"verifier_id"`
			EstablishedAt int64  `json:"established_at"`
			Claims        struct {
				Extra struct {
					CanonicalModelID string `json:"canonical_model_id"`
				} `json:"extra"`
			} `json:"claims"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("phala: the session list: %w", err)
	}
	listed := make([]Listed, 0, len(wire.Sessions))
	for _, s := range wire.Sessions {
		if s.VerifierID == attestation.PhalaDirectVerifier && !chat.ValidSessionID(s.ID) {
			return nil, fmt.Errorf("phala: the session list names a phala-direct session %q: %w", s.ID, chat.ErrInvalidSessionID)
		}
		listed = append(listed, Listed{ListedSession: chat.ListedSession{ID: s.ID, EstablishedAt: s.EstablishedAt}, Verifier: s.VerifierID, Model: s.Claims.Extra.CanonicalModelID})
	}
	return listed, nil
}

// ListSessions lists the phala-direct sessions the gateway holds for the route's upstream model: the ones a
// browser can audit before it sends.
func (r *Route) ListSessions(ctx context.Context) ([]chat.ListedSession, error) {
	all, err := r.Sessions(ctx)
	if err != nil {
		return nil, err
	}
	mine := []chat.ListedSession{}
	for _, s := range all {
		if s.Verifier == attestation.PhalaDirectVerifier && s.Model == r.Model {
			mine = append(mine, s.ListedSession)
		}
	}
	return mine, nil
}
