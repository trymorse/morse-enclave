package door

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/dialect"
	"morse/backend/internal/enum"
	"morse/backend/internal/seal"
	"morse/backend/internal/upstream"
	"morse/backend/internal/worker"
)

type Config struct {
	Door           *Door
	SealTo         []byte
	Relay          *url.URL
	RequireProxyV2 bool
	ProxyPeers     []netip.Prefix
	Reports        Reporter
}

type Reporter interface {
	Listening()
	ConnectionRefused(ConnectionRefusal)
	RelayFailed(pattern string, f Failure)
}

type NopReporter struct{}

func (NopReporter) Listening()                          {}
func (NopReporter) ConnectionRefused(ConnectionRefusal) {}
func (NopReporter) RelayFailed(string, Failure)         {}

type Failure uint8

const (
	RelayUnreachable Failure = iota + 1
	ReplyUnsealed
	ReplyInvalid
	ReplyCut
)

var failureNames = enum.Names[Failure]{RelayUnreachable: "relay_unreachable", ReplyUnsealed: "reply_unsealed", ReplyInvalid: "reply_invalid", ReplyCut: "reply_cut"}

func (f Failure) String() string { return failureNames.String(f) }

type passage uint8

const (
	sealedPassage passage = iota + 1
	plainPassage
	carriedPassage
)

type route struct {
	passage passage
	limit   int64
}

func passages() (map[string]route, error) {
	table := map[string]route{seal.Endpoint: {carriedPassage, seal.MaxBody + seal.Overhead}}
	for _, rt := range seal.Routes {
		switch {
		case rt.Sealed:
			table[rt.Pattern] = route{sealedPassage, sealedLimit(rt.Pattern)}
		case strings.HasPrefix(rt.Pattern, http.MethodGet+" "):
			table[rt.Pattern] = route{passage: plainPassage}
		default:
			return nil, fmt.Errorf("door: the plain route %q may carry a body, which the door forwards only inside a seal", rt.Pattern)
		}
	}
	return table, nil
}

func sealedLimit(pattern string) int64 {
	if inner, capped := worker.SealedBodyCaps[pattern]; capped {
		return min(int64(inner), seal.MaxBody)
	}
	return seal.MaxBody
}

var sealedMethod, sealedPath, _ = strings.Cut(seal.Endpoint, " ")

type limits struct {
	proxyHeader time.Duration
	holdSeconds int
	header      time.Duration
	bodyGrace   time.Duration
	bodyRamp    time.Duration
	bodyRate    int64
	idle        time.Duration
	bodyBytes   int64
	clientBytes int64
	smallBody   int64
	smallBytes  int64
	smallClient int64
	conns       int
	line        int
	clientConns int
	replyStall  time.Duration
	relayIdle   time.Duration
	relayAnswer time.Duration
}

const (
	maxBodyBytesInFlight = 8 * seal.MaxBody
	maxClientBodyBytes   = maxBodyBytesInFlight / 4
	maxSmallBody         = 1 << 20
	maxSmallBytes        = 64 * maxSmallBody
	maxClientSmallBytes  = 2 * maxSmallBody
	minBodyRate          = 16 << 10
	maxConnections       = 512
	maxUnnamed           = 1024
	maxClientConnections = 16
)

var defaultLimits = limits{proxyHeader: 5 * time.Second, holdSeconds: 1, header: 10 * time.Second, bodyGrace: 5 * time.Second, bodyRamp: 3 * time.Second, bodyRate: minBodyRate, idle: 15 * time.Second, bodyBytes: maxBodyBytesInFlight, clientBytes: maxClientBodyBytes, smallBody: maxSmallBody, smallBytes: maxSmallBytes, smallClient: maxClientSmallBytes, conns: maxConnections, line: maxUnnamed, clientConns: maxClientConnections, replyStall: 10 * time.Second, relayIdle: 30 * time.Second, relayAnswer: 31 * time.Minute}

const (
	maxHeaderBytes = 16 << 10
	replyChunk     = 8 << 10
)

var errBudgetSpent = errors.New("door: the budget of request body bytes in flight is spent")

type pool struct {
	mu      sync.Mutex
	most    int64
	held    int64
	total   int64
	share   int64
	clients map[netip.Prefix]int64
}

type budget struct{ small, large pool }

func (b *budget) pools() [2]*pool { return [2]*pool{&b.small, &b.large} }

func (p *pool) take(client netip.Prefix, n int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held+n > p.total || p.clients[client]+n > p.share {
		return false
	}
	if p.clients == nil {
		p.clients = map[netip.Prefix]int64{}
	}
	p.held += n
	p.clients[client] += n
	return true
}

func (p *pool) give(client netip.Prefix, n int64) {
	if n == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held -= n
	if p.clients[client] -= n; p.clients[client] == 0 {
		delete(p.clients, client)
	}
}

func clientOf(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 64
	if addr.Is4() {
		bits = 32
	}
	client, _ := addr.Prefix(bits)
	return client
}

type flight struct {
	budget *budget
	client netip.Prefix
	pool   *pool
	n      int64
}

func (f *flight) cover(n int64) bool {
	if n <= f.n {
		return true
	}
	if f.pool != nil && n <= f.pool.most && f.pool.take(f.client, n-f.n) {
		f.n = n
		return true
	}
	f.release()
	for _, p := range f.budget.pools() {
		if n <= p.most && p.take(f.client, n) {
			f.pool, f.n = p, n
			return true
		}
	}
	return false
}

func (f *flight) handoff() flight {
	held := *f
	f.pool, f.n = nil, 0
	return held
}

func (f *flight) release() {
	if f.pool != nil {
		f.pool.give(f.client, f.n)
	}
	f.pool, f.n = nil, 0
}

var (
	errNoBearer         = apierr.Invalid(http.StatusUnauthorized, "invalid_api_key", "Incorrect API key provided.")
	errBodiesInFlight   = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "server_busy", Message: "The door is reading as many request bodies as it can hold, from this address or from all. Retry after the time in the Retry-After header."}
	errNotFound         = apierr.Invalid(http.StatusNotFound, "not_found", "The door serves only the routes a sealing client uses.")
	errClientUnknown    = apierr.Error{Status: http.StatusInternalServerError, Type: "server_error", Code: "door_client_unknown", Message: "The door could not tell which address the request came from."}
	errBodyUnread       = apierr.Invalid(http.StatusBadRequest, "invalid_request_body", "The request body could not be read.")
	errPlainBody        = apierr.Invalid(http.StatusBadRequest, "invalid_request_body", "The door forwards a GET only without a body.")
	errBodyTimeout      = apierr.Invalid(http.StatusRequestTimeout, "request_timeout", "The request body arrived slower than the door's floor rate.")
	errRelayUnreachable = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "upstream_unreachable", Message: "The relay behind the door could not be reached."}
	errReplyUnsealed    = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "sealed_reply_missing", Message: "The relay answered without sealing its reply."}
	errHeadTooLarge     = apierr.Invalid(http.StatusRequestURITooLong, "request_head_too_large", "The request's path and content headers are too long to seal.")
	errReplyInvalid     = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "sealed_reply_invalid", Message: "The relay's sealed reply does not open."}
)

type Server struct {
	door     *Door
	sealTo   []byte
	relay    string
	proxyV2  bool
	peers    []netip.Prefix
	reports  Reporter
	client   *http.Client
	server   *http.Server
	limits   limits
	budget   budget
	entrance *entrance
	closed   chan struct{}
	once     sync.Once
}

func NewServer(c Config) (*Server, error) {
	switch {
	case c.Door == nil:
		return nil, errors.New("door: a server needs the Door that holds its key")
	case len(c.SealTo) == 0:
		return nil, errors.New("door: a server needs the key it seals each request to")
	case c.Relay == nil:
		return nil, errors.New("door: a server needs the relay it hands each request to")
	}
	table, err := passages()
	if err != nil {
		return nil, err
	}
	s := &Server{door: c.Door, sealTo: bytes.Clone(c.SealTo), relay: strings.TrimSuffix(c.Relay.String(), "/"), proxyV2: c.RequireProxyV2, peers: slices.Clone(c.ProxyPeers), reports: c.Reports, limits: defaultLimits, entrance: &entrance{}, closed: make(chan struct{})}
	if s.reports == nil {
		s.reports = NopReporter{}
	}
	s.client = &http.Client{Transport: &http.Transport{
		DialContext:        (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression: true,
	}}
	mux := http.NewServeMux()
	for pattern, rt := range table {
		mux.HandleFunc(pattern, s.pass(pattern, rt))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { apierr.WriteError(w, errNotFound) })
	s.server = &http.Server{Handler: mux, TLSConfig: &tls.Config{GetCertificate: c.Door.certificate, MinVersion: tls.VersionTLS12}, MaxHeaderBytes: maxHeaderBytes, Protocols: new(http.Protocols)}
	s.server.Protocols.SetHTTP1(true)
	return s, nil
}

// ListenAndServe binds addr only once the door has a certificate to serve,
// which is never before the log is proven to hold the boot's record. Until
// then nothing listens, so a client's connection is refused by the kernel.
func (s *Server) ListenAndServe(addr string) error {
	select {
	case <-s.door.Ready():
	case <-s.closed:
		return http.ErrServerClosed
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.reports.Listening()
	return s.serve(ln)
}

func (s *Server) serve(ln net.Listener) error {
	if s.limits.holdSeconds > 0 {
		if err := holdUntilData(ln, s.limits.holdSeconds); err != nil {
			ln.Close()
			return fmt.Errorf("door: TCP_DEFER_ACCEPT on the listener: %w", err)
		}
	}
	e := s.entrance
	e.proxyV2, e.peers, e.timeout, e.handshake, e.report = s.proxyV2, s.peers, s.limits.proxyHeader, s.limits.header, s.reports.ConnectionRefused
	e.most, e.line, e.share = s.limits.conns, s.limits.line, s.limits.clientConns
	s.server.ConnState, s.server.ConnContext = s.entrance.track, withConn
	s.server.ReadHeaderTimeout, s.server.ReadTimeout, s.server.IdleTimeout = s.limits.header, s.limits.header, s.limits.idle
	relay := s.client.Transport.(*http.Transport)
	relay.IdleConnTimeout, relay.ResponseHeaderTimeout = s.limits.relayIdle, s.limits.relayAnswer
	s.budget.small.most, s.budget.small.total, s.budget.small.share = s.limits.smallBody, s.limits.smallBytes, s.limits.smallClient
	s.budget.large.most, s.budget.large.total, s.budget.large.share = s.limits.bodyBytes, s.limits.bodyBytes, s.limits.clientBytes
	return s.server.ServeTLS(gate{Listener: ln, e: s.entrance}, "", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.once.Do(func() { close(s.closed) })
	return s.server.Shutdown(ctx)
}

func (s *Server) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.server.Close()
}

func (s *Server) pass(pattern string, rt route) http.HandlerFunc {
	d := worker.Dialects[pattern]
	return func(w http.ResponseWriter, r *http.Request) {
		w = d.Errors(w)
		apiKeyAsBearer(r.Header)
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			apierr.WriteError(w, errClientUnknown)
			return
		}
		var body seal.Inner
		f := &flight{budget: &s.budget, client: clientOf(peer.Addr())}
		defer f.release()
		if rt.passage == plainPassage && r.ContentLength != 0 {
			apierr.WriteError(w, errPlainBody)
			return
		}
		if rt.passage != plainPassage {
			if !bearerShaped(r.Header) {
				apierr.WriteError(w, errNoBearer)
				return
			}
			if body, err = s.readBody(w, r, rt.limit, f); err != nil {
				apierr.WriteError(w, bodyRefusal(w, err))
				return
			}
		}
		s.entrance.markBusy(r.Context())
		resp, cek, err := s.send(r, rt.passage, peer.Addr(), body, f)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			if errors.Is(err, seal.ErrHeadTooLarge) {
				apierr.WriteError(w, errHeadTooLarge)
				return
			}
			if errors.Is(err, upstream.ErrUnreachable) {
				s.reports.RelayFailed(pattern, RelayUnreachable)
			}
			apierr.WriteError(w, errRelayUnreachable)
			return
		}
		defer resp.Body.Close()
		s.answer(w, r, resp, cek, pattern)
	}
}

type flooredBody struct {
	io.Reader
	rc    *http.ResponseController
	first time.Time
	ramp  time.Duration
	rate  int64
	read  int64
}

func (b *flooredBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if b.read == 0 && n > 0 {
		b.first = time.Now()
	}
	b.read += int64(n)
	switch {
	case err == io.EOF:
		b.rc.SetReadDeadline(time.Time{})
	case n > 0:
		b.rc.SetReadDeadline(b.first.Add(b.ramp + time.Duration(b.read)*time.Second/time.Duration(b.rate)))
	}
	return n, err
}

func apiKeyAsBearer(h http.Header) {
	if key := strings.TrimSpace(h.Get(dialect.HeaderAPIKey)); key != "" && h.Get("Authorization") == "" {
		h.Set("Authorization", "Bearer "+key)
	}
}

func bearerShaped(h http.Header) bool {
	scheme, token, ok := strings.Cut(h.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(token) != ""
}

const firstRoom = 32 << 10

func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64, f *flight) (seal.Inner, error) {
	var body seal.Inner
	if r.ContentLength > limit {
		return body, &http.MaxBytesError{Limit: limit}
	}
	declared := r.ContentLength >= 0
	if declared {
		limit = r.ContentLength
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(s.limits.bodyGrace))
	var in io.Reader = &flooredBody{Reader: http.MaxBytesReader(w, r.Body, limit), rc: rc, ramp: s.limits.bodyRamp, rate: s.limits.bodyRate}
	if limit > 0 {
		var first [1]byte
		switch _, err := io.ReadFull(in, first[:]); {
		case !declared && errors.Is(err, io.EOF):
			body.Grow(0)
			return body, nil
		case err != nil:
			return body, err
		}
		in = io.MultiReader(bytes.NewReader(first[:]), in)
	}
	s.entrance.markBusy(r.Context())
	for {
		room := limit
		if !declared {
			room = min(limit, max(2*int64(body.Room()), firstRoom))
			if int64(body.Room()) < s.limits.smallBody {
				room = min(room, s.limits.smallBody)
			}
		}
		if !f.cover(room) {
			return body, errBudgetSpent
		}
		body.Grow(int(room))
		err := body.Fill(in)
		switch {
		case errors.Is(err, io.EOF):
			return body, nil
		case err != nil:
			return body, err
		case room == limit:
			var probe [1]byte
			if _, err := in.Read(probe[:]); !errors.Is(err, io.EOF) {
				return body, cmp.Or(err, error(&http.MaxBytesError{Limit: limit}))
			}
			return body, nil
		case room == s.limits.smallBody:
			var probe [1]byte
			switch _, err := io.ReadFull(in, probe[:]); {
			case errors.Is(err, io.EOF):
				return body, nil
			case err != nil:
				return body, err
			}
			in = io.MultiReader(bytes.NewReader(probe[:]), in)
		}
	}
}

func bodyRefusal(w http.ResponseWriter, err error) apierr.Error {
	var tooLarge *http.MaxBytesError
	var timeout net.Error
	switch {
	case errors.Is(err, errBudgetSpent):
		apierr.SetRetryAfter(w, time.Second)
		return errBodiesInFlight
	case errors.As(err, &tooLarge):
		return apierr.ErrRequestTooLarge
	case errors.As(err, &timeout) && timeout.Timeout():
		return errBodyTimeout
	}
	return errBodyUnread
}

func (s *Server) send(r *http.Request, p passage, client netip.Addr, inner seal.Inner, f *flight) (*http.Response, *[32]byte, error) {
	method, target, body := r.Method, r.URL.RequestURI(), inner.Body()
	var cek *[32]byte
	if p == sealedPassage {
		head := seal.Head{Method: r.Method, Path: target, Headers: flatten(worker.ContentHeaders(r.Header)), TS: time.Now().Unix()}
		sealed, key, err := inner.Seal([][]byte{s.sealTo}, head)
		if err != nil {
			return nil, nil, err
		}
		body, cek, method, target = sealed, &key, sealedMethod, sealedPath
	}
	req, err := http.NewRequestWithContext(r.Context(), method, s.relay+target, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	if len(body) > 0 {
		req.Body, req.ContentLength = &sentBody{buf: body, flight: f.handoff()}, int64(len(body))
	}
	req.Header = outerHeader(r.Header, p, client)
	resp, err := upstream.Do(s.client, req)
	if err != nil {
		return nil, nil, err
	}
	return resp, cek, nil
}

type sentBody struct {
	mu     sync.Mutex
	buf    []byte
	off    int
	flight flight
}

func (b *sentBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.off >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

func (b *sentBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf, b.off = nil, 0
	b.flight.release()
	return nil
}

func flatten(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for name, values := range h {
		flat[name] = values[0]
	}
	return flat
}

func outerHeader(in http.Header, p passage, client netip.Addr) http.Header {
	out := http.Header{}
	copyHeader(out, in, "Authorization")
	switch p {
	case plainPassage:
		copyHeader(out, in, "Accept")
	case carriedPassage:
		copyHeader(out, in, "Content-Type")
	case sealedPassage:
		out.Set("Content-Type", seal.ContentType)
	}
	out.Set(seal.DoorClientAddress, client.Unmap().WithZone("").String())
	return out
}

func copyHeader(dst, src http.Header, name string) {
	if values := src.Values(name); len(values) > 0 {
		dst[name] = slices.Clone(values)
	}
}

var hopByHop = []string{"Content-Length", "Transfer-Encoding", "Connection"}

func (s *Server) answer(w http.ResponseWriter, r *http.Request, resp *http.Response, cek *[32]byte, pattern string) {
	sealed := resp.Header.Get("Content-Type") == seal.ContentType
	status, body, skip := resp.StatusCode, io.Reader(resp.Body), hopByHop
	var inner http.Header
	switch {
	case cek != nil && !sealed && status < http.StatusBadRequest:
		s.reports.RelayFailed(pattern, ReplyUnsealed)
		apierr.WriteError(w, errReplyUnsealed)
		return
	case cek != nil && sealed:
		reply, err := seal.OpenReply(resp.Body, *cek)
		if err != nil {
			s.reports.RelayFailed(pattern, ReplyInvalid)
			apierr.WriteError(w, errReplyInvalid)
			return
		}
		status, body, inner, skip = reply.Head.Status, reply, reply.Head.Headers, append([]string{"Content-Type"}, hopByHop...)
	}
	for name, values := range resp.Header {
		if !slices.Contains(skip, name) {
			w.Header()[name] = values
		}
	}
	for name, values := range inner {
		w.Header()[http.CanonicalHeaderKey(name)] = values
	}
	w.WriteHeader(status)
	if err := stream(w, body, s.limits.replyStall); err != nil && r.Context().Err() == nil {
		s.reports.RelayFailed(pattern, ReplyCut)
		panic(http.ErrAbortHandler)
	}
}

func stream(w http.ResponseWriter, r io.Reader, stall time.Duration) error {
	rc := http.NewResponseController(w)
	buf := make([]byte, replyChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			rc.SetWriteDeadline(time.Now().Add(stall))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return nil
			}
			rc.Flush()
		}
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
	}
}
