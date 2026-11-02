package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

type Server struct {
	inner        *InProcess
	routesDigest string
	mux          *http.ServeMux
	casts        lastCast
}

type lastCast struct {
	mu   sync.Mutex
	cast chat.Cast
}

func (c *lastCast) of(prompts []chat.PromptHash, rules string) chat.Cast {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rules != c.cast.Rules() || !slices.Equal(prompts, c.cast.Prompts()) {
		c.cast = chat.NewCast(prompts, rules)
	}
	return c.cast
}

const (
	maxWireBody   = 1 << 20
	maxSealedWire = 64 << 20
)

func NewServer(inner *InProcess, routesDigest string) *Server {
	s := &Server{inner: inner, routesDigest: routesDigest, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /open", s.open)
	s.mux.HandleFunc("POST /open-sealed", s.openSealed)
	s.mux.HandleFunc("POST /run", s.run)
	s.mux.HandleFunc("POST /submit", s.submit)
	s.mux.HandleFunc("POST /ack", s.ack)
	s.mux.HandleFunc("POST /count", s.count)
	s.mux.HandleFunc("POST /cut", s.cut)
	s.mux.HandleFunc("POST /poll", s.poll)
	s.mux.HandleFunc("GET /routes", s.serveRoutes)
	s.mux.HandleFunc("GET /attestation", s.attestation)
	s.mux.HandleFunc("POST /attest", s.evidence(func(ctx context.Context, req evidenceRequest) (any, error) {
		att, err := s.inner.Attest(ctx, req.Vendor, req.Nonce)
		return attestationWire{Report: att.Report, BindModel: att.BindModel, GPUVerdicts: att.GPUVerdicts}, err
	}))
	s.mux.HandleFunc("POST /receipt", s.evidence(func(ctx context.Context, req evidenceRequest) (any, error) {
		return s.inner.Receipt(ctx, req.Vendor, req.ID)
	}))
	s.mux.HandleFunc("POST /session", s.evidence(func(ctx context.Context, req evidenceRequest) (any, error) {
		return s.inner.Session(ctx, req.Vendor, req.ID)
	}))
	s.mux.HandleFunc("POST /sessions", s.evidence(func(ctx context.Context, req evidenceRequest) (any, error) {
		listed, err := s.inner.Sessions(ctx, req.Vendor)
		return sessionsWire{Sessions: listed}, err
	}))
	return s
}

func (s *Server) evidence(fetch func(ctx context.Context, req evidenceRequest) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req evidenceRequest
		if !decodeWire(w, r, &req) {
			return
		}
		v, err := fetch(r.Context(), req)
		if refusal, known := apierr.Refusal(err, apierr.Error{}); known {
			apierr.WriteError(w, refusal)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if raw, ok := v.(json.RawMessage); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(raw)
			return
		}
		apierr.WriteJSON(w, http.StatusOK, v)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) Drain() { s.inner.Drain() }

func decodeWire(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxWireBody)).Decode(into); err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return false
	}
	return true
}

func (s *Server) opening(header http.Header) (chat.Cast, Framing, error) {
	o, err := openingOf(header)
	if err != nil {
		return chat.Cast{}, Framing{}, err
	}
	return s.casts.of(o.Prompts, o.Rules), Framing{Launch: o.Launch, Own: o.Own, Writing: o.Writing}, nil
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	cast, framing, err := s.opening(r.Header)
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	admitted, err := s.inner.Open(r.Context(), Opening{Method: r.Header.Get(headerMethod), Path: r.Header.Get(headerPath), Query: r.Header.Get(headerQuery), Header: ContentHeaders(r.Header), Body: r.Body, Cast: cast, Framing: framing})
	if err != nil {
		apierr.WriteError(w, refusalWire(err))
		return
	}
	s.writeAdmission(w, admitted, "")
}

func (s *Server) openSealed(w http.ResponseWriter, r *http.Request) {
	cast, framing, err := s.opening(r.Header)
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSealedWire+1))
	if err != nil || len(body) > maxSealedWire {
		apierr.WriteError(w, apierr.ErrRequestTooLarge)
		return
	}
	opened, err := s.inner.OpenSealed(r.Context(), SealedOpening{Body: body, Cast: cast, Framing: framing})
	if refused, ok := errors.AsType[SealedRefusal](err); ok {
		w.Header().Set("Content-Type", SealedContentType)
		w.Write(refused.Reply)
		return
	}
	if unknown, ok := errors.AsType[KeyUnknown](err); ok {
		apierr.WriteEnvelope(w, ErrSealedKeyUnknown.Status, ErrSealedKeyUnknown.EnvelopeWith("key_id", unknown.Holds))
		return
	}
	if err != nil {
		apierr.WriteError(w, refusalWire(err))
		return
	}
	s.writeAdmission(w, opened.Admission, opened.Pattern)
}

func (s *Server) writeAdmission(w http.ResponseWriter, admitted Admission, pattern string) {
	data, err := admissionWire(admitted, pattern)
	if err != nil {
		s.inner.Cut(admitted.Handle(), measure.CutByProxy)
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// A run answers with the reply itself and the measurement as a trailer, so the reply is chunked and a length the
// worker set travels as Worker-Content-Length.
func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWireBody))
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	h, g, err := grantOf(body)
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	s.serve(w, r, h, func(reply http.ResponseWriter) Measured { return s.inner.Run(r.Context(), h, g, reply) })
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if !decodeWire(w, r, &req) {
		return
	}
	s.serve(w, r, req.Handle, func(reply http.ResponseWriter) Measured {
		return s.inner.Submit(r.Context(), req.Handle, req.Grant, reply, func(sub media.Submitted) { s.awaitAck(w, r, req.Handle, sub) })
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, h Handle, run func(reply http.ResponseWriter) Measured) {
	w.Header().Set("Trailer", headerMeasured)
	defer context.AfterFunc(r.Context(), func() { s.inner.Cut(h, measure.CutByProxy) })()
	m := run(&chunkedReply{ResponseWriter: w})
	measured, _ := json.Marshal(m)
	w.Header().Set(headerMeasured, string(measured))
}

func (s *Server) awaitAck(w http.ResponseWriter, r *http.Request, h Handle, sub media.Submitted) {
	var acked <-chan struct{}
	if e := s.inner.entry(h); e != nil {
		acked = e.acked
	}
	w.Header().Set(headerVendorID, sub.VendorID)
	w.WriteHeader(http.StatusEarlyHints)
	w.Header().Del(headerVendorID)
	select {
	case <-acked:
	case <-r.Context().Done():
	case <-time.After(OpenedFor):
	}
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request) {
	var req handleRequest
	if !decodeWire(w, r, &req) {
		return
	}
	if !s.inner.ack(req.Handle) {
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) count(w http.ResponseWriter, r *http.Request) {
	var req handleRequest
	if !decodeWire(w, r, &req) {
		return
	}
	counted := s.inner.takeCount(req.Handle)
	if counted == nil {
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	select {
	case c, ok := <-counted:
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		apierr.WriteJSON(w, http.StatusOK, c)
	case <-r.Context().Done():
	}
}

func (s *Server) cut(w http.ResponseWriter, r *http.Request) {
	var req cutRequest
	if !decodeWire(w, r, &req) {
		return
	}
	s.inner.Cut(req.Handle, req.Reason)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	var req pollRequest
	if !decodeWire(w, r, &req) {
		return
	}
	ctx := r.Context()
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}
	p, err := s.inner.Poll(ctx, req.Route, req.VendorID)
	if err != nil {
		refusal, _ := apierr.Refusal(err, apierr.ErrUpstream)
		if vendor, refused := errors.AsType[upstream.Refused](err); refused {
			w.Header().Set(headerVendorStatus, strconv.Itoa(vendor.Status))
		}
		apierr.WriteError(w, refusal)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, p)
}

func (s *Server) serveRoutes(w http.ResponseWriter, r *http.Request) {
	apierr.WriteJSON(w, http.StatusOK, routesReply{Digest: s.routesDigest})
}

func (s *Server) attestation(w http.ResponseWriter, r *http.Request) {
	attested, err := s.inner.Attestation(r.Context())
	if err != nil {
		refusal, _ := apierr.Refusal(err, apierr.ErrUnavailable)
		apierr.WriteError(w, refusal)
		return
	}
	keyID, _ := attested.KeyID.MarshalText()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set(headerKeyID, string(keyID))
	w.Write(attested.Document)
}

type chunkedReply struct {
	http.ResponseWriter
	mu          sync.Mutex
	wroteHeader bool
	left        bool
}

var errClientLeft = errors.New("worker: the relay's client left")

func (c *chunkedReply) leave() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.left = true
}

func (c *chunkedReply) WriteHeader(code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeHeaderLocked(code)
}

func (c *chunkedReply) writeHeaderLocked(code int) {
	if code >= 100 && code < 200 {
		c.ResponseWriter.WriteHeader(code)
		return
	}
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	h := c.Header()
	if length := h.Get("Content-Length"); length != "" {
		h.Del("Content-Length")
		h.Set(headerContentLength, length)
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *chunkedReply) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.left {
		return 0, errClientLeft
	}
	c.writeHeaderLocked(http.StatusOK)
	return c.ResponseWriter.Write(p)
}

func (c *chunkedReply) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *chunkedReply) FlushError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.left {
		return errClientLeft
	}
	c.writeHeaderLocked(http.StatusOK)
	return http.NewResponseController(c.ResponseWriter).Flush()
}
