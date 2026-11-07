package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"morse/backend/internal/strictjson"
)

const (
	// MaxCallBody is the most a sealed call may hold; MaxTokenBody is the most a token or revocation request may.
	MaxCallBody  = 256 << 10
	MaxTokenBody = 16 << 10

	maxToken    = 8 << 10
	maxSession  = 512
	maxToolName = 128
	maxCursor   = 1 << 10
	maxCode     = 4 << 10
	maxID       = 1 << 53
	maxHeaders  = 16
	maxPath     = 8
	maxSafeInt  = 1<<53 - 1
)

var (
	idOfARequest = regexp.MustCompile(`^[A-Za-z0-9-]{16,64}$`)
	verifier     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	toolName     = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	headerName   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
)

// Call is one MCP message for a server, sent under the user's token. What the vendor gets is the worker's own
// encoding of what it checked, so nothing the check didn't read reaches it.
type Call struct {
	server  string
	token   string
	session string
	write   string
	method  string
	id      int64
	params  json.RawMessage
	headers []paramHeader
}

// paramHeader is a tool parameter a stateless server's inputSchema marks with x-mcp-header: the device names the
// header and where the parameter sits in the arguments, and the worker reads the value from the arguments itself.
type paramHeader struct {
	name string
	path []string
}

func (c *Call) String() string   { return "plugins.Call(" + c.method + ")" }
func (c *Call) GoString() string { return c.String() }

// TokenRequest exchanges a code for tokens or refreshes them, at a server's pinned token endpoint.
type TokenRequest struct {
	server   string
	request  string
	grant    string
	code     string
	verifier string
	refresh  string
}

func (t *TokenRequest) String() string   { return "plugins.TokenRequest(" + t.grant + ")" }
func (t *TokenRequest) GoString() string { return t.String() }

// RevokeRequest asks a server to forget a token (RFC 7009).
type RevokeRequest struct {
	server string
	token  string
	hint   string
}

func (r *RevokeRequest) String() string   { return "plugins.RevokeRequest" }
func (r *RevokeRequest) GoString() string { return r.String() }

type method struct {
	notification bool
	// legacy is whether the revisions with a handshake have the method, and stateless whether July2026 does.
	legacy, stateless bool
	params            func(raw json.RawMessage, s Revision) (map[string]any, error)
}

var methods = map[string]method{
	"initialize":                {legacy: true, params: initializeParams},
	"notifications/initialized": {legacy: true, notification: true, params: noParams},
	"ping":                      {legacy: true, params: noParams},
	"server/discover":           {stateless: true, params: noParams},
	"tools/list":                {legacy: true, stateless: true, params: listParams},
	"tools/call":                {legacy: true, stateless: true, params: callParams},
}

func (m method) in(s Revision) bool {
	if s.stateless() {
		return m.stateless
	}
	return m.legacy
}

// clientInfo is how the worker names itself to a server, the same whatever the device sends.
var clientInfo = map[string]string{"name": "Morse", "version": "1"}

func invalid(message string) error { return strictjson.Invalid(message) }

func object(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, error) {
	return strictjson.Object(bytes.NewReader(raw), allowed...)
}

func text(raw json.RawMessage, name string, limit int) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" || len(s) > limit || !utf8.ValidString(s) {
		return "", invalid(name + " must be a string of at most " + itoa(limit) + " bytes.")
	}
	return s, nil
}

// visible reports whether s is all visible ASCII, as a token or session id sent in a header must be.
func visible(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseCall reads a sealed call: the server, the user's token for it, the session a legacy server gave the
// connection, a change's write id, one MCP message of a method the worker allows, and, for a stateless server, the
// tool parameters to mirror into headers.
func ParseCall(body io.Reader) (*Call, error) {
	raw, err := io.ReadAll(io.LimitReader(body, MaxCallBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxCallBody {
		return nil, invalid("The call may hold at most " + itoa(MaxCallBody) + " bytes.")
	}
	fields, err := object(raw, "server", "token", "session", "write", "message", "headers")
	if err != nil {
		return nil, err
	}
	c := &Call{}
	if c.server, err = text(fields["server"], "server", 32); err != nil {
		return nil, err
	}
	if c.token, err = text(fields["token"], "token", maxToken); err != nil || !visible(c.token) {
		return nil, invalid("token must be the access token, as the vendor gave it.")
	}
	if c.session, err = optional(fields["session"], "session", maxSession); err != nil || !visible(c.session) && c.session != "" {
		return nil, invalid("session must be the id the server gave, or null.")
	}
	if c.write, err = optional(fields["write"], "write", 64); err != nil || c.write != "" && !idOfARequest.MatchString(c.write) {
		return nil, invalid("write must be a press of Allow's id, or null.")
	}
	if c.method, c.id, c.params, err = message(fields["message"]); err != nil {
		return nil, err
	}
	if c.headers, err = paramHeaders(fields["headers"]); err != nil {
		return nil, err
	}
	if c.headers != nil && c.method != "tools/call" {
		return nil, invalid("Only a tools/call mirrors parameters into headers.")
	}
	return c, nil
}

// paramHeaders reads the x-mcp-header marks of the tool a call names: each a header name, unique whatever its
// case, and the chain of property names that leads from the arguments to the parameter.
func paramHeaders(raw json.RawMessage) ([]paramHeader, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	refused := invalid("headers must be at most " + itoa(maxHeaders) + " of {name, path}: an x-mcp-header name and the property names that lead to its parameter.")
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 || len(items) > maxHeaders {
		return nil, refused
	}
	seen := map[string]bool{}
	out := make([]paramHeader, 0, len(items))
	for _, item := range items {
		fields, err := object(item, "name", "path")
		if err != nil {
			return nil, err
		}
		var h paramHeader
		if json.Unmarshal(fields["name"], &h.name) != nil || !headerName.MatchString(h.name) || seen[strings.ToLower(h.name)] {
			return nil, refused
		}
		seen[strings.ToLower(h.name)] = true
		if json.Unmarshal(fields["path"], &h.path) != nil || len(h.path) == 0 || len(h.path) > maxPath {
			return nil, refused
		}
		for _, step := range h.path {
			if step == "" || len(step) > maxToolName || !utf8.ValidString(step) {
				return nil, refused
			}
		}
		out = append(out, h)
	}
	return out, nil
}

func optional(raw json.RawMessage, name string, limit int) (string, error) {
	if raw == nil || string(raw) == "null" {
		return "", nil
	}
	return text(raw, name, limit)
}

// message checks a JSON-RPC message and returns its method, its id, and its params, which are checked once the
// server is known, against its revision.
func message(raw json.RawMessage) (string, int64, json.RawMessage, error) {
	fields, err := object(raw, "jsonrpc", "id", "method", "params")
	if err != nil {
		return "", 0, nil, err
	}
	if string(fields["jsonrpc"]) != `"2.0"` {
		return "", 0, nil, invalid(`message.jsonrpc must be "2.0".`)
	}
	name, err := text(fields["method"], "message.method", 64)
	if err != nil {
		return "", 0, nil, err
	}
	m, allowed := methods[name]
	if !allowed {
		return "", 0, nil, invalid("message.method must be one the worker sends: initialize, notifications/initialized, ping, server/discover, tools/list, or tools/call.")
	}
	var id int64
	switch rawID, has := fields["id"]; {
	case m.notification && has:
		return "", 0, nil, invalid("A notification has no id.")
	case !m.notification && (json.Unmarshal(rawID, &id) != nil || id < 1 || id > maxID):
		return "", 0, nil, invalid("message.id must be a positive integer.")
	}
	params := fields["params"]
	if params == nil {
		params = json.RawMessage("{}")
	}
	return name, id, params, nil
}

func quote(s string) json.RawMessage { b, _ := json.Marshal(s); return b }

// encode checks the call against revision s and returns the message the vendor gets, and for a stateless server
// the headers that mirror it.
func (c *Call) encode(s Revision) ([]byte, http.Header, error) {
	m := methods[c.method]
	if !m.in(s) {
		return nil, nil, invalid(c.method + " is not a method of " + string(s) + ", the revision the server is pinned to.")
	}
	if s.stateless() && c.session != "" {
		return nil, nil, invalid(string(s) + " has no session, so a call to this server sends session null.")
	}
	if !s.stateless() && c.headers != nil {
		return nil, nil, invalid("Only a server on " + string(July2026) + " or later takes parameters as headers.")
	}
	params, err := m.params(c.params, s)
	if err != nil {
		return nil, nil, err
	}
	var headers http.Header
	if s.stateless() {
		if params == nil {
			params = map[string]any{}
		}
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    s,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         clientInfo,
		}
		if headers, err = c.mirrored(params); err != nil {
			return nil, nil, err
		}
	}
	out := map[string]any{"jsonrpc": "2.0", "method": c.method}
	if !m.notification {
		out["id"] = c.id
	}
	if len(params) > 0 {
		out["params"] = params
	}
	body, err := json.Marshal(out)
	return body, headers, err
}

// mirrored are the headers a stateless request carries beside its body: Mcp-Method, Mcp-Name for a tools/call,
// and an Mcp-Param- header for each marked parameter the arguments hold, all read from what the worker encodes.
func (c *Call) mirrored(params map[string]any) (http.Header, error) {
	h := http.Header{"Mcp-Method": {c.method}}
	if c.method != "tools/call" {
		return h, nil
	}
	h.Set("Mcp-Name", headerValue(params["name"].(string)))
	args := params["arguments"].(map[string]any)
	for _, p := range c.headers {
		v, present := at(args, p.path)
		if !present {
			continue
		}
		var text string
		switch v := v.(type) {
		case string:
			text = v
		case bool:
			text = strconv.FormatBool(v)
		case json.Number:
			n, err := v.Int64()
			if err != nil || n > maxSafeInt || n < -maxSafeInt {
				return nil, invalid("The parameter for header " + p.name + " must be a string, a boolean, or a safe integer.")
			}
			text = strconv.FormatInt(n, 10)
		default:
			return nil, invalid("The parameter for header " + p.name + " must be a string, a boolean, or a safe integer.")
		}
		h.Set("Mcp-Param-"+p.name, headerValue(text))
	}
	return h, nil
}

// at reads the value at path in args, reporting false where nothing, or null, is there.
func at(args map[string]any, path []string) (any, bool) {
	var v any = args
	for _, step := range path {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = obj[step]; !ok {
			return nil, false
		}
	}
	return v, v != nil
}

// headerValue is s as a header carries it: as it is when it is plain ASCII with no space at either end, else in
// the =?base64?...?= form, which a plain value of that shape takes too.
func headerValue(s string) string {
	plain := !strings.HasPrefix(s, "=?base64?") || !strings.HasSuffix(s, "?=")
	if s != strings.Trim(s, " \t") {
		plain = false
	}
	for i := 0; plain && i < len(s); i++ {
		plain = s[i] == '\t' || s[i] >= 0x20 && s[i] <= 0x7e
	}
	if plain {
		return s
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

func noParams(raw json.RawMessage, _ Revision) (map[string]any, error) {
	if _, err := object(raw); err != nil {
		return nil, invalid("This method takes no params.")
	}
	return nil, nil
}

// initializeParams are always the worker's own: the pinned revision, no capabilities, so a server asks nothing of
// the client, and Morse's name. The device's must say the same revision.
func initializeParams(raw json.RawMessage, s Revision) (map[string]any, error) {
	fields, err := object(raw, "protocolVersion", "capabilities", "clientInfo")
	if err != nil {
		return nil, err
	}
	if string(fields["protocolVersion"]) != string(quote(string(s))) {
		return nil, invalid("initialize must ask for the revision the server is pinned to.")
	}
	return map[string]any{
		"protocolVersion": s,
		"capabilities":    map[string]any{},
		"clientInfo":      clientInfo,
	}, nil
}

func listParams(raw json.RawMessage, _ Revision) (map[string]any, error) {
	fields, err := object(raw, "cursor")
	if err != nil {
		return nil, err
	}
	if fields["cursor"] == nil {
		return nil, nil
	}
	cursor, err := text(fields["cursor"], "params.cursor", maxCursor)
	if err != nil {
		return nil, err
	}
	return map[string]any{"cursor": cursor}, nil
}

func callParams(raw json.RawMessage, _ Revision) (map[string]any, error) {
	fields, err := object(raw, "name", "arguments")
	if err != nil {
		return nil, err
	}
	name, err := text(fields["name"], "params.name", maxToolName)
	if err != nil || !toolName.MatchString(name) {
		return nil, invalid("params.name must be a tool's name.")
	}
	args := map[string]any{}
	if fields["arguments"] != nil {
		dec := json.NewDecoder(bytes.NewReader(fields["arguments"]))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil || args == nil || dec.More() {
			return nil, invalid("params.arguments must be one JSON object.")
		}
	}
	return map[string]any{"name": name, "arguments": args}, nil
}

// ParseToken reads a sealed token request: a code with its PKCE verifier, or a refresh token, for one server,
// under an id of its own the worker answers once.
func ParseToken(body io.Reader) (*TokenRequest, error) {
	raw, err := io.ReadAll(io.LimitReader(body, MaxTokenBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxTokenBody {
		return nil, invalid("The request may hold at most " + itoa(MaxTokenBody) + " bytes.")
	}
	fields, err := object(raw, "server", "request", "grant", "code", "verifier", "refresh_token")
	if err != nil {
		return nil, err
	}
	t := &TokenRequest{}
	if t.server, err = text(fields["server"], "server", 32); err != nil {
		return nil, err
	}
	if t.request, err = text(fields["request"], "request", 64); err != nil || !idOfARequest.MatchString(t.request) {
		return nil, invalid("request must be an id of the request's own.")
	}
	if t.grant, err = text(fields["grant"], "grant", 32); err != nil {
		return nil, err
	}
	switch t.grant {
	case "authorization_code":
		if fields["refresh_token"] != nil {
			return nil, invalid("A code's exchange sends no refresh_token.")
		}
		if t.code, err = text(fields["code"], "code", maxCode); err != nil || !visible(t.code) {
			return nil, invalid("code must be the code the vendor sent back.")
		}
		if t.verifier, err = text(fields["verifier"], "verifier", 128); err != nil || !verifier.MatchString(t.verifier) {
			return nil, invalid("verifier must be the flow's PKCE verifier (RFC 7636).")
		}
	case "refresh_token":
		if fields["code"] != nil || fields["verifier"] != nil {
			return nil, invalid("A refresh sends no code or verifier.")
		}
		if t.refresh, err = text(fields["refresh_token"], "refresh_token", maxToken); err != nil || !visible(t.refresh) {
			return nil, invalid("refresh_token must be the refresh token, as the vendor gave it.")
		}
	default:
		return nil, invalid(`grant must be "authorization_code" or "refresh_token".`)
	}
	return t, nil
}

// ParseRevoke reads a sealed revocation: a token of one server and what it is.
func ParseRevoke(body io.Reader) (*RevokeRequest, error) {
	raw, err := io.ReadAll(io.LimitReader(body, MaxTokenBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxTokenBody {
		return nil, invalid("The request may hold at most " + itoa(MaxTokenBody) + " bytes.")
	}
	fields, err := object(raw, "server", "token", "hint")
	if err != nil {
		return nil, err
	}
	r := &RevokeRequest{}
	if r.server, err = text(fields["server"], "server", 32); err != nil {
		return nil, err
	}
	if r.token, err = text(fields["token"], "token", maxToken); err != nil || !visible(r.token) {
		return nil, invalid("token must be the token, as the vendor gave it.")
	}
	if r.hint, err = text(fields["hint"], "hint", 32); err != nil || r.hint != "access_token" && r.hint != "refresh_token" {
		return nil, invalid(`hint must be "access_token" or "refresh_token".`)
	}
	return r, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
