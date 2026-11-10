package worker

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"slices"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/audio"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/health"
	"morse/backend/internal/plugins"
	"morse/backend/internal/research"
	"morse/backend/internal/seal"
	"morse/backend/internal/web"
)

var sealedMethods = []string{http.MethodGet, http.MethodPost, http.MethodDelete}

var SealedBodyCaps = map[string]int{
	SearchPattern: web.MaxRequestBody, FetchPattern: web.MaxRequestBody, ResearchPattern: research.MaxRequestBody, TranscriptionPattern: audio.MaxRequestBody,
	PluginCallPattern: plugins.MaxCallBody, PluginTokenPattern: plugins.MaxTokenBody, PluginRevokePattern: plugins.MaxTokenBody,
}

var (
	ErrSealedKeyUnknown  = apierr.Invalid(http.StatusMisdirectedRequest, "sealed_key_unknown", "No entry is sealed to this instance's key. Seal the request to every key in instances and send it once more.")
	ErrSealedInvalid     = apierr.Invalid(http.StatusBadRequest, "sealed_invalid", "The sealed request does not open, or its inner request is not one the proxy serves sealed.")
	errSealedStale       = apierr.Invalid(http.StatusBadRequest, "sealed_stale", "The sealed request's ts is more than 120 seconds from the proxy's clock, which proxy_time gives, or before the proxy started.")
	errSealedReplay      = apierr.Invalid(http.StatusBadRequest, "sealed_replay", "This sealed request was opened before.")
	errSealedUnavailable = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "sealed_unavailable", Message: "This proxy holds no sealing key."}
)

type Sealing struct {
	Identity *seal.Identity
	Attest   func(ctx context.Context) ([]byte, error)
}

type SealedOpening struct {
	Body []byte
	Cast chat.Cast
	Framing
	KeyCaller   bool
	KeyFloor    catalog.Tier
	PrivacyVeil VeilOpening
}

type SealedAdmission struct {
	Pattern string
	Admission
}

type SealedRefusal struct{ Reply []byte }

func (SealedRefusal) Error() string { return "worker: refused a sealed request" }

type Attested struct {
	Document []byte
	KeyID    seal.KeyID
}

// KeyUnknown is ErrSealedKeyUnknown with Holds, the key the worker opens with now, so the relay can tell a list
// that predates a restart from a client that sealed to a key no instance holds.
type KeyUnknown struct{ Holds seal.KeyID }

func (KeyUnknown) Error() string { return ErrSealedKeyUnknown.Error() }

func (KeyUnknown) Unwrap() error { return ErrSealedKeyUnknown }

type sealedState struct {
	Sealing
	started time.Time
	replays seal.Replays
}

func (w *InProcess) Attestation(ctx context.Context) (Attested, error) {
	if w.sealing.Identity == nil {
		return Attested{}, errSealedUnavailable
	}
	document, err := w.sealing.Attest(ctx)
	if err != nil {
		return Attested{}, err
	}
	return Attested{Document: document, KeyID: w.sealing.Identity.KeyID()}, nil
}

func (w *InProcess) OpenSealed(ctx context.Context, o SealedOpening) (SealedAdmission, error) {
	if w.sealing.Identity == nil {
		return SealedAdmission{}, errSealedUnavailable
	}
	req, err := w.sealing.Identity.Open(o.Body)
	switch {
	case errors.Is(err, seal.ErrKeyUnknown):
		return SealedAdmission{}, KeyUnknown{Holds: w.sealing.Identity.KeyID()}
	case err != nil:
		return SealedAdmission{}, ErrSealedInvalid
	}
	refuse := func(reply []byte, status int) (SealedAdmission, error) {
		return SealedAdmission{}, SealedRefusal{Reply: sealedReplyOf(req.CEK, status, reply)}
	}
	now := w.now()
	if !req.Fresh(now, w.sealing.started) {
		return refuse(errSealedStale.EnvelopeWith("proxy_time", now.Unix()), errSealedStale.Status)
	}
	if !w.sealing.replays.Admit(req.Enc, now) {
		return refuse(errSealedReplay.Envelope(), errSealedReplay.Status)
	}
	pattern, target, ok := sealedRoute(req.Method, req.Path)
	if !ok {
		return refuse(ErrSealedInvalid.Envelope(), ErrSealedInvalid.Status)
	}
	if limit, capped := SealedBodyCaps[pattern]; capped && len(req.Body) > limit {
		return refuse(apierr.ErrRequestTooLarge.Envelope(), apierr.ErrRequestTooLarge.Status)
	}
	header := http.Header{}
	for name, value := range req.Headers {
		header.Set(name, value)
	}
	cek := req.CEK
	admitted, err := w.Open(ctx, Opening{Method: req.Method, Path: target.Path, Query: target.RawQuery, Header: ContentHeaders(header), Body: bytes.NewReader(req.Body), Cast: o.Cast, Framing: o.Framing, KeyCaller: o.KeyCaller, KeyFloor: o.KeyFloor,
		PrivacyVeil: o.PrivacyVeil, cek: &cek, veilHead: req.PrivacyVeil, veilPartition: req.PrivacyVeilPartition})
	if err != nil {
		refusal := refusalWire(contentRefusal(err))
		return refuse(refusal.Envelope(), refusal.Status)
	}
	return SealedAdmission{Pattern: pattern, Admission: admitted}, nil
}

// tidyPath says a path has nothing to clean. A slash at its end isn't noise: a lookup's path is the
// service's own, and Photon's is /api/.
func tidyPath(p string) bool {
	clean := path.Clean(p)
	return p == clean || (clean != "/" && p == clean+"/")
}

func sealedRoute(method, target string) (string, *url.URL, bool) {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Host != "" || !tidyPath(u.Path) || !slices.Contains(sealedMethods, method) {
		return "", nil, false
	}
	_, pattern := mux.Handler(&http.Request{Method: method, URL: u})
	return pattern, u, pattern != ""
}

func sealedReplyOf(cek [32]byte, status int, body []byte) []byte {
	var out bytes.Buffer
	stream, _ := seal.NewStream(&out, func() {}, cek)
	stream.Begin(seal.ReplyHead{Status: status, Headers: http.Header{"Content-Type": {"application/json"}}})
	stream.Write(body)
	stream.Close()
	return out.Bytes()
}

type sealedReply struct {
	outer  http.ResponseWriter
	stream *seal.Stream
	inner  http.Header
	status int
}

func newSealedReply(outer http.ResponseWriter, cek [32]byte) *sealedReply {
	h := outer.Header()
	h.Set("Content-Type", seal.ContentType)
	h.Set("Cache-Control", "no-store")
	rc := http.NewResponseController(outer)
	stream, _ := seal.NewStream(outer, func() { rc.Flush() }, cek)
	return &sealedReply{outer: outer, stream: stream, inner: http.Header{}}
}

func (s *sealedReply) Header() http.Header { return s.inner }

func (s *sealedReply) WriteHeader(code int) {
	if s.status != 0 || code < http.StatusOK {
		return
	}
	s.status = code
	s.stream.Begin(seal.ReplyHead{Status: code, Headers: s.inner.Clone()})
}

func (s *sealedReply) Write(p []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	return s.stream.Write(p)
}

func (s *sealedReply) FlushError() error { return s.stream.Err() }

func (s *sealedReply) Unwrap() http.ResponseWriter { return s.outer }

func (s *sealedReply) close() int {
	s.WriteHeader(http.StatusOK)
	s.stream.Close()
	return s.status
}

func (s *sealedReply) finish(m *Measured) {
	m.SealedStatusClass = s.close() / 100
	m.Refusal = measure.NoRefusal
	if m.Health.Outcome == health.ContentFilter {
		m.Health.Outcome = health.ClientError
	}
}
