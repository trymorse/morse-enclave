package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const (
	// MaxReply is the most of a server's reply the worker reads, and of an answer it sends back.
	MaxReply     = 2 << 20
	maxTokenBody = 64 << 10
	callTimeout  = 60 * time.Second
	tokenTimeout = 15 * time.Second
	remembered   = 10 * time.Minute
	rememberedAt = 1 << 16
)

var (
	ErrUnknownServer = apierr.Invalid(http.StatusNotFound, "plugin_not_found", "Morse offers no plugin with this id.")
	ErrOff           = apierr.Invalid(http.StatusForbidden, "plugin_off", "This plugin is switched off for now.")
	ErrBusy          = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "plugin_busy", Message: "This plugin is taking more calls than it allows. Try again shortly."}
	ErrRepeat        = apierr.Invalid(http.StatusConflict, "plugin_request_repeat", "This request was answered once already.")
)

// Kind is which of the plugin routes a request came to.
type Kind uint8

const (
	KindCall Kind = iota
	KindToken
	KindRevoke
)

// Request is a checked plugin request, ready to run.
type Request interface {
	serverID() string
	run(ctx context.Context, r *Relay, s Server) ([]byte, error)
}

// Relay sends checked requests to their servers. It keeps, for ten minutes, the write ids it ran and the token
// requests it answered, so neither runs twice on this instance, and nothing else.
type Relay struct {
	servers map[string]Server
	secrets map[string]string
	// unset holds the servers whose secret the host didn't supply, which are off.
	unset       map[string]bool
	environment string
	client      *http.Client
	now         func() time.Time
	writes      *seen
	requests    *seen
	mu          sync.Mutex
	buckets     map[string]*bucket
}

// New builds a relay for servers in environment, reading each confidential client's secret with getenv.
func New(servers []Server, getenv func(string) string, environment string, client *http.Client, now func() time.Time) (*Relay, error) {
	if _, known := Origins[environment]; !known {
		return nil, errors.New("plugins: environment must be dev or prod")
	}
	r := &Relay{
		servers: map[string]Server{}, secrets: map[string]string{}, unset: map[string]bool{}, environment: environment, client: client, now: now,
		writes: newSeen(now), requests: newSeen(now), buckets: map[string]*bucket{},
	}
	for _, s := range servers {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		if _, twice := r.servers[s.ID]; twice {
			return nil, errors.New("plugins: two servers are " + s.ID)
		}
		if s.SecretEnv != "" {
			// One plugin's missing secret switches it off, and leaves the worker and every other plugin serving.
			if r.secrets[s.ID] = getenv(s.SecretEnv); r.secrets[s.ID] == "" {
				r.unset[s.ID] = true
			}
		}
		r.servers[s.ID] = s
		r.buckets[s.ID] = &bucket{rpm: s.RPM, tokens: float64(s.RPM), at: now()}
	}
	return r, nil
}

// Open checks a request to a plugin route before the relay paces it.
func (r *Relay) Open(kind Kind, body io.Reader) (Request, error) {
	var req Request
	var err error
	switch kind {
	case KindCall:
		var c *Call
		if c, err = ParseCall(body); err == nil {
			req = c
		}
	case KindToken:
		var t *TokenRequest
		if t, err = ParseToken(body); err == nil {
			req = t
		}
	case KindRevoke:
		var rv *RevokeRequest
		if rv, err = ParseRevoke(body); err == nil {
			req = rv
		}
	}
	if err != nil {
		return nil, err
	}
	s, known := r.servers[req.serverID()]
	if !known {
		return nil, ErrUnknownServer
	}
	if c, ok := req.(*Call); ok {
		if _, _, err := c.encode(s.Protocol); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// Run sends req to its server and returns the answer the device reads, unless the server is among off, which the
// relay switched off. A revocation goes even to a server that is off.
func (r *Relay) Run(ctx context.Context, req Request, off []string) ([]byte, error) {
	s := r.servers[req.serverID()]
	if _, revoking := req.(*RevokeRequest); !revoking && (slices.Contains(off, s.ID) || r.unset[s.ID]) {
		return nil, ErrOff
	}
	return req.run(ctx, r, s)
}

type callAnswer struct {
	VendorStatus int             `json:"vendor_status"`
	Session      *string         `json:"session"`
	AuthError    *string         `json:"auth_error"`
	Scope        *string         `json:"scope"`
	Response     json.RawMessage `json:"response"`
	Repeat       bool            `json:"repeat"`
}

func (c *Call) serverID() string { return c.server }

func (c *Call) run(ctx context.Context, r *Relay, s Server) ([]byte, error) {
	if c.write != "" && !r.writes.admit(c.write) {
		return json.Marshal(callAnswer{Repeat: true})
	}
	if !r.take(s.ID) {
		if c.write != "" {
			r.writes.forget(c.write)
		}
		return nil, ErrBusy
	}
	body, mirrored, err := c.encode(s.Protocol)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.MCP, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"Authorization": {"Bearer " + c.token},
		"Content-Type":  {"application/json"},
		"Accept":        {"application/json, text/event-stream"},
	}
	for name, values := range mirrored {
		req.Header[name] = values
	}
	if c.method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", string(s.Protocol))
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := upstream.Do(r.client, req)
	if err != nil {
		if c.write != "" && errors.Is(err, upstream.ErrNotSent) {
			r.writes.forget(c.write)
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return json.Marshal(callAnswer{})
	}
	defer resp.Body.Close()
	a := callAnswer{VendorStatus: resp.StatusCode}
	stateless := s.Protocol.stateless()
	if session := resp.Header.Get("Mcp-Session-Id"); !stateless && session != "" && len(session) <= maxSession && visible(session) {
		a.Session = &session
	} else if c.session != "" {
		a.Session = &c.session
	}
	notification := methods[c.method].notification
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		a.AuthError, a.Scope = challenge(resp.StatusCode, resp.Header.Values("WWW-Authenticate"))
	case resp.StatusCode == http.StatusOK && !notification:
		if a.Response, err = response(resp, c.id); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			a.VendorStatus = 0
		}
		if stateless && a.Response != nil {
			if a.Response, err = complete(a.Response, c.id); err != nil {
				a.VendorStatus = 0
			}
		}
	case stateless && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound):
		// A stateless server refuses a revision, a method, or a header it doesn't take with one of these and a
		// JSON-RPC error, whose code is all that comes back.
		if found, err := response(resp, c.id); err == nil && bytes.Contains(found, []byte(`"error"`)) {
			a.Response = found
		} else if errors.Is(err, context.Canceled) {
			return nil, err
		}
	}
	return json.Marshal(a)
}

// errMissingCapability is MCP's MissingRequiredClientCapabilityError, what the device gets in place of a result
// that asks the client for input: the worker declares no capability, so it answers no such request.
const errMissingCapability = -32021

var errUnknownResultType = errors.New("plugins: a result of a type the worker doesn't know")

// complete passes a stateless server's result on only when it is complete. One that asks for input becomes the
// missing capability's error, and one of any other type is no answer at all.
func complete(found json.RawMessage, id int64) (json.RawMessage, error) {
	var m struct {
		Result *struct {
			ResultType *string `json:"resultType"`
		} `json:"result"`
	}
	if json.Unmarshal(found, &m) != nil || m.Result == nil || m.Result.ResultType == nil {
		return found, nil
	}
	switch *m.Result.ResultType {
	case "complete":
		return found, nil
	case "input_required":
		return json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]int64{"code": errMissingCapability}})
	}
	return nil, errUnknownResultType
}

var (
	challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)
	scopeList      = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$`)
)

// challenge reads a refusal's WWW-Authenticate for the two errors the device acts on, and the scopes an
// insufficient_scope names. Nothing else of it goes back: no address, no description.
func challenge(status int, headers []string) (authError, scope *string) {
	params := map[string]string{}
	for _, h := range headers {
		for _, m := range challengeParam.FindAllStringSubmatch(h, -1) {
			params[strings.ToLower(m[1])] = m[2]
		}
	}
	switch e := params["error"]; {
	case status == http.StatusForbidden && e == "insufficient_scope":
		if named := params["scope"]; len(named) <= 1024 && scopeList.MatchString(named) {
			scope = &named
		}
		return &e, scope
	case status == http.StatusUnauthorized && (e == "" || e == "invalid_token"):
		invalid := "invalid_token"
		return &invalid, nil
	}
	return nil, nil
}

// response reads the JSON-RPC response with the call's id from a server's reply, JSON or an event stream,
// skipping whatever else the server sends, and returns only its result, or its error's code.
func response(resp *http.Response, id int64) (json.RawMessage, error) {
	body := io.LimitReader(resp.Body, MaxReply+1)
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var found json.RawMessage
	switch mediaType {
	case "application/json":
		raw, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxReply {
			return nil, errTooLarge
		}
		var batch []json.RawMessage
		if json.Unmarshal(raw, &batch) != nil {
			batch = []json.RawMessage{raw}
		}
		for _, m := range batch {
			if found = matching(m, id); found != nil {
				break
			}
		}
	case "text/event-stream":
		err := sse.Each(body, MaxReply, sse.Refuse, func(data []byte) (bool, error) {
			found = matching(data, id)
			return found != nil, nil
		})
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, errNoResponse
	}
	return found, nil
}

var (
	errTooLarge   = errors.New("plugins: the server's reply is too large")
	errNoResponse = errors.New("plugins: the server's reply holds no response to the call")
)

func matching(raw []byte, id int64) json.RawMessage {
	var m struct {
		ID     *json.Number    `json:"id"`
		Method *string         `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &m) != nil || m.ID == nil || m.Method != nil || m.ID.String() != strconv.FormatInt(id, 10) {
		return nil
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	switch {
	case m.Error != nil:
		out["error"] = map[string]int64{"code": m.Error.Code}
	case m.Result != nil:
		out["result"] = m.Result
	default:
		return nil
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return encoded
}

type tokenAnswer struct {
	VendorStatus int    `json:"vendor_status"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	OAuthError   string `json:"oauth_error,omitempty"`
}

var oauthError = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (t *TokenRequest) serverID() string { return t.server }

func (t *TokenRequest) run(ctx context.Context, r *Relay, s Server) ([]byte, error) {
	if !r.requests.admit(t.request) {
		return nil, ErrRepeat
	}
	if !r.take(s.ID) {
		r.requests.forget(t.request)
		return nil, ErrBusy
	}
	form := url.Values{"client_id": {s.Clients[r.environment]}, "resource": {s.TokenResource()}}
	switch t.grant {
	case "authorization_code":
		form.Set("grant_type", "authorization_code")
		form.Set("code", t.code)
		form.Set("code_verifier", t.verifier)
		form.Set("redirect_uri", s.callback(r.environment))
	case "refresh_token":
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", t.refresh)
	}
	resp, err := r.post(ctx, s, s.Token, form)
	if err != nil {
		if errors.Is(err, upstream.ErrNotSent) {
			r.requests.forget(t.request)
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return json.Marshal(tokenAnswer{})
	}
	defer resp.Body.Close()
	a := tokenAnswer{VendorStatus: resp.StatusCode}
	var got map[string]json.RawMessage
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody))
	if json.Unmarshal(raw, &got) != nil {
		return json.Marshal(a)
	}
	read := func(name string, limit int, ok func(string) bool) string {
		var v string
		if json.Unmarshal(got[name], &v) != nil || v == "" || len(v) > limit || !ok(v) {
			return ""
		}
		return v
	}
	if resp.StatusCode == http.StatusOK {
		a.AccessToken = read("access_token", maxToken, visible)
		a.RefreshToken = read("refresh_token", maxToken, visible)
		a.Scope = read("scope", 1024, scopeList.MatchString)
		a.TokenType = read("token_type", 32, visible)
		var expires json.Number
		if json.Unmarshal(got["expires_in"], &expires) == nil {
			if n, err := expires.Int64(); err == nil && n > 0 && n <= 10*365*24*3600 {
				a.ExpiresIn = n
			}
		}
	} else {
		a.OAuthError = read("error", 64, oauthError.MatchString)
	}
	return json.Marshal(a)
}

type revokeAnswer struct {
	VendorStatus int `json:"vendor_status"`
}

func (rv *RevokeRequest) serverID() string { return rv.server }

func (rv *RevokeRequest) run(ctx context.Context, r *Relay, s Server) ([]byte, error) {
	if s.Revoke == "" {
		return json.Marshal(revokeAnswer{})
	}
	form := url.Values{"token": {rv.token}, "token_type_hint": {rv.hint}, "client_id": {s.Clients[r.environment]}}
	resp, err := r.post(ctx, s, s.Revoke, form)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return json.Marshal(revokeAnswer{})
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxTokenBody))
	return json.Marshal(revokeAnswer{VendorStatus: resp.StatusCode})
}

// post sends form to a server's pinned endpoint, authenticated as Morse's client there.
func (r *Relay) post(ctx context.Context, s Server, endpoint string, form url.Values) (*http.Response, error) {
	if s.Auth == SecretPost {
		form.Set("client_secret", r.secrets[s.ID])
	}
	ctx, cancel := context.WithTimeout(ctx, tokenTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}
	if s.Auth == SecretBasic {
		pair := url.QueryEscape(s.Clients[r.environment]) + ":" + url.QueryEscape(r.secrets[s.ID])
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pair)))
	}
	resp, err := upstream.Do(r.client, req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelling{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelling struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelling) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

func (r *Relay) take(server string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buckets[server].take(r.now())
}

type bucket struct {
	rpm    int
	tokens float64
	at     time.Time
}

func (b *bucket) take(now time.Time) bool {
	b.tokens = min(float64(b.rpm), b.tokens+now.Sub(b.at).Minutes()*float64(b.rpm))
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// seen remembers ids for ten minutes, at most rememberedAt of them, the oldest going first.
type seen struct {
	mu    sync.Mutex
	now   func() time.Time
	at    map[string]time.Time
	order []string
}

func newSeen(now func() time.Time) *seen { return &seen{now: now, at: map[string]time.Time{}} }

// admit reports whether id is new, and remembers it.
func (s *seen) admit(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for len(s.order) > 0 && (now.Sub(s.at[s.order[0]]) >= remembered || len(s.order) >= rememberedAt) {
		delete(s.at, s.order[0])
		s.order = s.order[1:]
	}
	if _, known := s.at[id]; known {
		return false
	}
	s.at[id] = now
	s.order = append(s.order, id)
	return true
}

// forget lets id in again, for a run that sent nothing: refused for the rate, or failed before its headers went out.
func (s *seen) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.at[id]; !known {
		return
	}
	delete(s.at, id)
	s.order = slices.DeleteFunc(s.order, func(o string) bool { return o == id })
}
