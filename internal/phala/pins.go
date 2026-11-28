package phala

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/attestation"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	// why: a kept id only ever names a Phala-run server, so an old list costs one 412 and a fresh read. This also
	// bounds how long a sealed relay can miss that another company's server has joined a model.
	listKept    = time.Minute
	listTimeout = 10 * time.Second
)

var errNoPhalaServer = errors.New("phala: no server Phala runs itself is listed for the model")

type served struct {
	// why: newest first, so the cap on a request's pins drops the oldest attestations.
	own    []string
	others bool
}

type pins struct {
	gateway Gateway
	model   string
	mu      sync.Mutex
	read    time.Time
	last    served
}

func (p *pins) servers(ctx context.Context, fresh bool) (served, error) {
	p.mu.Lock()
	last, read := p.last, p.read
	p.mu.Unlock()
	if !fresh && !read.IsZero() && time.Since(read) < listKept {
		return last, nil
	}
	// why: the call clock times one request, and a list read on it would claim it from the chat.
	listing, done := context.WithTimeout(upstream.WithCallClock(ctx, nil), listTimeout)
	defer done()
	listed, err := p.gateway.list(listing, "?model="+url.QueryEscape(p.model))
	if err != nil {
		return served{}, err
	}
	slices.SortStableFunc(listed, func(a, b Listed) int { return int(b.EstablishedAt - a.EstablishedAt) })
	var now served
	for _, s := range listed {
		if s.Verifier == attestation.PhalaDirectVerifier {
			now.own = append(now.own, s.ID)
		} else {
			now.others = true
		}
	}
	if len(now.own) == 0 {
		return served{}, errNoPhalaServer
	}
	p.mu.Lock()
	p.last, p.read = now, time.Now()
	p.mu.Unlock()
	return now, nil
}

// why: reads as the provider being unavailable, so a model's next endpoint is tried.
func unreachable(ctx context.Context, cause error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", upstream.ErrNotSent, ctx.Err())
	}
	// why: a refusal the transport already named, such as an unattested gateway, stands as itself.
	if errors.As(cause, new(apierr.Error)) {
		return cause
	}
	return fmt.Errorf("%w: %w: %v", upstream.ErrNotSent, apierr.ErrUpstreamUnavailable, cause)
}

type pinnedSender struct {
	next openaicompat.Sender
	pins *pins
}

var _ openaicompat.Sender = pinnedSender{}

// why: tells a caller which client the pinned requests travel on.
func (s pinnedSender) Unwrap() openaicompat.Sender { return s.next }

func (s pinnedSender) Stream(ctx context.Context, body []byte, header http.Header, each func([]byte) (bool, error)) error {
	return s.send(ctx, body, func(pinned []byte) error { return s.next.Stream(ctx, pinned, header, each) })
}

func (s pinnedSender) Complete(ctx context.Context, body []byte, header http.Header) ([]byte, error) {
	var reply []byte
	err := s.send(ctx, body, func(pinned []byte) (err error) {
		reply, err = s.next.Complete(ctx, pinned, header)
		return err
	})
	return reply, err
}

// why: the gateway answers 412 before it forwards anything, so the one retry on a fresh list sends nothing twice.
func (s pinnedSender) send(ctx context.Context, body []byte, call func([]byte) error) error {
	for fresh := false; ; fresh = true {
		now, err := s.pins.servers(ctx, fresh)
		if err != nil {
			return unreachable(ctx, err)
		}
		pinned, err := pin(body, now.own)
		if err != nil {
			return err
		}
		err = call(pinned)
		switch {
		case !errors.Is(err, errSessionNotAccepted):
			return err
		case fresh:
			// why: errSessionNotAccepted tells a client its own pins went stale, and these are not the client's.
			return unreachable(ctx, errors.New("phala: the gateway kept none of the sessions it had just listed"))
		}
	}
}

func pin(body []byte, sessions []string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	provider, err := json.Marshal(struct {
		ACIVerified bool     `json:"aci_verified"`
		ZDR         bool     `json:"zdr"`
		Sessions    []string `json:"aci_session_ids"`
	}{true, true, sessions[:min(len(sessions), MaxPinnedSessions)]})
	if err != nil {
		return nil, err
	}
	fields["provider"] = provider
	var out bytes.Buffer
	// why: the prompt's text must leave as the egress check read it, with no HTML escaping.
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// why: a sealed body cannot be given pins here, since its receipt hashes what the client built. So it goes
// unchanged while only Phala runs the model, and otherwise only if every session it pins is Phala's.
func (p *pins) admitSealed(ctx context.Context, body []byte) error {
	var sent struct {
		Provider struct {
			Sessions []string `json:"aci_session_ids"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		return err
	}
	asked := sent.Provider.Sessions
	for fresh := false; ; fresh = true {
		now, err := p.servers(ctx, fresh)
		if err != nil {
			return unreachable(ctx, err)
		}
		switch {
		case !now.others:
			return nil
		case len(asked) == 0:
			return unreachable(ctx, errors.New("phala: another company's server serves the model and the request pins no session"))
		case !slices.ContainsFunc(asked, func(id string) bool { return !slices.Contains(now.own, id) }):
			return nil
		case fresh:
			return upstream.Refused{Status: errSessionNotAccepted.Status, Err: errSessionNotAccepted}
		}
	}
}

func PinSessions(endpoint upstream.Endpoint, model string, client *http.Client) openaicompat.Sender {
	endpoint.Refuse = refuseSealed
	gateway := NewGateway(endpoint.BaseURL, "", client)
	gateway.Auth = endpoint.Auth
	return pinnedSender{next: openaicompat.HTTPSender{Endpoint: endpoint}, pins: &pins{gateway: gateway, model: model}}
}
