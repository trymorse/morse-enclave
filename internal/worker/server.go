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
	"morse/backend/internal/seal"
	"morse/backend/internal/upstream"
	"morse/backend/internal/worker/taskrun"
)

type Server struct {
	inner        *InProcess
	routesDigest string
	mux          *http.ServeMux
	casts        lastCast
	// lingering holds each run's Late until the relay asks for it, for OpenedFor at most.
	lingering sync.Map
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
	s.mux.HandleFunc("POST /late", s.late)
	s.mux.HandleFunc("POST /cut", s.cut)
	s.mux.HandleFunc("POST /poll", s.poll)
	s.mux.HandleFunc("POST "+taskAdoptPath, s.taskAdopt)
	s.mux.HandleFunc("POST "+taskOpenPath, s.taskOpen)
	s.mux.HandleFunc("POST "+taskNextPath, s.taskNext)
	s.mux.HandleFunc("POST "+taskFinishPath, s.taskFinish)
	s.mux.HandleFunc("GET /routes", s.serveRoutes)
	s.mux.HandleFunc("GET /attestation", s.attestation)
	s.mux.HandleFunc("GET /unpinned", s.serveUnpinned)
	s.mux.HandleFunc("POST /attest", s.evidence(func(ctx context.Context, req evidenceRequest) (any, error) {
		att, err := s.inner.Attest(ctx, req.Vendor, req.Nonce, req.format())
		return attestationWire{Report: att.Report, BindModel: att.BindModel, GPUVerdicts: att.GPUVerdicts, VendorPins: att.VendorPins}, err
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

func (s *Server) opening(header http.Header) (Opening, error) {
	o, err := openingOf(header)
	if err != nil {
		return Opening{}, err
	}
	return Opening{Cast: s.casts.of(o.Prompts, o.Rules), Framing: Framing{Launch: o.Launch, Own: o.Own, Writing: o.Writing}, KeyCaller: o.KeyCaller, KeyFloor: o.keyFloor, KeySettings: o.KeySettings, PrivacyVeil: o.Veil}, nil
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	o, err := s.opening(r.Header)
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	o.Method, o.Path, o.Query, o.Header, o.Body = r.Header.Get(headerMethod), r.Header.Get(headerPath), r.Header.Get(headerQuery), ContentHeaders(r.Header), r.Body
	admitted, err := s.inner.Open(r.Context(), o)
	if err != nil {
		apierr.WriteError(w, refusalWire(err))
		return
	}
	s.writeAdmission(w, admitted, "")
}

func (s *Server) openSealed(w http.ResponseWriter, r *http.Request) {
	o, err := s.opening(r.Header)
	if err != nil {
		apierr.WriteError(w, apierr.ErrInvalidBody)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSealedWire+1))
	if err != nil || len(body) > maxSealedWire {
		apierr.WriteError(w, apierr.ErrRequestTooLarge)
		return
	}
	opened, err := s.inner.OpenSealed(r.Context(), SealedOpening{Body: body, Cast: o.Cast, Framing: o.Framing, KeyCaller: o.KeyCaller, KeyFloor: o.KeyFloor, KeySettings: o.KeySettings, PrivacyVeil: o.PrivacyVeil})
	if refused, ok := errors.AsType[SealedRefusal](err); ok {
		w.Header().Set("Content-Type", seal.ContentType)
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
	if late := m.Late; late != nil {
		s.lingering.Store(h, late)
		time.AfterFunc(OpenedFor, func() { s.lingering.CompareAndDelete(h, late) })
	}
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

func (s *Server) late(w http.ResponseWriter, r *http.Request) {
	var req handleRequest
	if !decodeWire(w, r, &req) {
		return
	}
	held, ok := s.lingering.LoadAndDelete(req.Handle)
	if !ok {
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	tries := []Try{}
	for late := held.(<-chan Try); ; {
		select {
		case try, open := <-late:
			if !open {
				apierr.WriteJSON(w, http.StatusOK, tries)
				return
			}
			tries = append(tries, try)
		case <-r.Context().Done():
			return
		}
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
	apierr.WriteJSON(w, http.StatusOK, Served{Digest: s.routesDigest, Wire: WireVersion})
}

func (s *Server) serveUnpinned(w http.ResponseWriter, r *http.Request) {
	releases, err := s.inner.Unpinned(r.Context())
	if err != nil {
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, unpinnedWire{Releases: releases})
}

func (s *Server) attestation(w http.ResponseWriter, r *http.Request) {
	attested, err := s.inner.Attestation(r.Context())
	if err != nil {
		refusal, _ := apierr.Refusal(err, apierr.ErrUnavailable)
		apierr.WriteError(w, refusal)
		return
	}
	keyID, _ := attested.KeyID.MarshalText()
	epoch, _ := attested.TaskEpoch.MarshalText()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set(headerKeyID, string(keyID))
	w.Header().Set(headerTaskEpoch, string(epoch))
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

func (s *Server) taskAdopt(w http.ResponseWriter, r *http.Request) {
	var req taskAdoptRequest
	if !decodeWire(w, r, &req) {
		return
	}
	adopted, err := s.inner.TaskAdopt(r.Context(), req.Handle, req.Revision)
	if err != nil {
		writeTaskRefusal(w, err)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, adopted)
}

func (s *Server) taskOpen(w http.ResponseWriter, r *http.Request) {
	var req TaskOpening
	if !decodeWire(w, r, &req) {
		return
	}
	opened, err := s.inner.TaskOpen(r.Context(), req)
	if err != nil {
		writeTaskRefusal(w, err)
		return
	}
	step, err := stepWire(opened.Step)
	if err != nil {
		s.inner.Cut(opened.Run, measure.CutByProxy)
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, taskOpenedWire{Run: opened.Run, taskStepWire: step})
}

func (s *Server) taskNext(w http.ResponseWriter, r *http.Request) {
	var req taskRunRequest
	if !decodeWire(w, r, &req) {
		return
	}
	stepped, err := s.inner.TaskNext(r.Context(), req.Run)
	if err != nil {
		writeTaskRefusal(w, err)
		return
	}
	if stepped.Done {
		apierr.WriteJSON(w, http.StatusOK, taskSteppedWire{Done: true})
		return
	}
	step, err := stepWire(stepped.Step)
	if err != nil {
		s.inner.Cut(req.Run, measure.CutByProxy)
		apierr.WriteError(w, apierr.ErrUnavailable)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, taskSteppedWire{Kind: &step.Kind, Admission: step.Admission})
}

func (s *Server) taskFinish(w http.ResponseWriter, r *http.Request) {
	var req taskRunRequest
	if !decodeWire(w, r, &req) {
		return
	}
	finished, err := s.inner.TaskFinish(r.Context(), req.Run)
	if err != nil {
		writeTaskRefusal(w, err)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, finished)
}

func stepWire(step TaskStep) (taskStepWire, error) {
	admission, err := admissionWire(step.Admission, "")
	return taskStepWire{Kind: step.Kind, Admission: admission}, err
}

// writeTaskRefusal answers a task endpoint's refusal: task_epoch_unknown names the epoch the worker holds, as
// sealed_key_unknown names its key, and anything that carries no refusal of its own is the worker being unable to.
func writeTaskRefusal(w http.ResponseWriter, err error) {
	if unknown, ok := errors.AsType[taskrun.EpochUnknown](err); ok {
		apierr.WriteEnvelope(w, taskrun.ErrEpochUnknown.Status, taskrun.ErrEpochUnknown.EnvelopeWith("epoch", unknown.Holds))
		return
	}
	refusal, _ := apierr.Refusal(err, apierr.ErrUnavailable)
	apierr.WriteError(w, refusal)
}
