package phala

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/capped"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/upstream"
)

const (
	upstreamModel = "moonshotai/kimi-k3"
	completion    = `{"id":"c1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`
)

type captured struct {
	body   map[string]json.RawMessage
	header http.Header
	path   string
}

func gateway(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) (*Route, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.header = r.Header.Clone()
		got.path = r.URL.RequestURI()
		if r.URL.Path == "/v1/chat/completions" {
			if err := json.NewDecoder(r.Body).Decode(&got.body); err != nil {
				http.Error(w, "bad body", http.StatusTeapot)
				return
			}
		}
		reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, upstreamModel, "sk-phala", Clients{Plaintext: srv.Client(), Sealed: srv.Client()}, nil), got
}

func parse(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req}
}

func TestEveryForwardedRequestCarriesTheAttestedZeroRetentionConstraintOverTheClients(t *testing.T) {
	const relaxed = `,"provider":{"aci_verified":false,"zdr":false,"aci_session_ids":["as_1"]}`
	for name, tc := range map[string]struct {
		body string
		call func(r *Route, req chat.Call) error
	}{
		"stream with client provider": {`{"model":"kimi-k3-tee","stream":true` + relaxed + `,"messages":[]}`, func(r *Route, req chat.Call) error {
			_, err := r.Stream(context.Background(), req, func(chat.Chunk) error { return nil })
			return err
		}},
		"complete with client provider": {`{"model":"kimi-k3-tee"` + relaxed + `,"messages":[]}`, func(r *Route, req chat.Call) error {
			_, _, err := r.Complete(context.Background(), req)
			return err
		}},
		"complete without provider": {`{"model":"kimi-k3-tee","messages":[]}`, func(r *Route, req chat.Call) error {
			_, _, err := r.Complete(context.Background(), req)
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			route, got := gateway(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.Header.Get("Accept"), "event-stream") {
					w.Header().Set("Content-Type", "text/event-stream")
					io.WriteString(w, "data: [DONE]\n\n")
					return
				}
				io.WriteString(w, completion)
			})
			if err := tc.call(route, parse(t, tc.body)); err != nil {
				t.Fatal(err)
			}
			if string(got.body["provider"]) != `{"aci_verified":true,"zdr":true}` {
				t.Errorf("forwarded provider %s", got.body["provider"])
			}
			if string(got.body["model"]) != `"`+upstreamModel+`"` || got.header.Get("Authorization") != "Bearer sk-phala" {
				t.Errorf("forwarded model %s auth %q", got.body["model"], got.header.Get("Authorization"))
			}
		})
	}
}

func TestAttestRelaysTheReportByteExactAndBindsTheForwardedModel(t *testing.T) {
	const report = "{\n  \"api_version\": \"aci/1\",\n  \"vendor\": \"<fake> & co\",\n  \"attestation\": {\"report_data\": \"ab+cd\"}\n}\n"
	route, got := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, report)
	})
	att, err := route.Attest(context.Background(), "ab+cd")
	if err != nil {
		t.Fatal(err)
	}
	if string(att.Report) != report {
		t.Errorf("report\n%q\nwant the gateway's bytes\n%q", att.Report, report)
	}
	if att.BindModel != upstreamModel {
		t.Errorf("BindModel %q, want the forwarded model %q", att.BindModel, upstreamModel)
	}
	if got.path != "/v1/aci/attestation?nonce=ab%2Bcd" || got.header.Get("Authorization") != "Bearer sk-phala" {
		t.Errorf("attestation request %s auth %q", got.path, got.header.Get("Authorization"))
	}
}

func TestAttestRefusesFailuresAndNonObjectReports(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"gateway 500": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"x"}`)
		},
		"not json":   func(w http.ResponseWriter) { io.WriteString(w, "<html>") },
		"json array": func(w http.ResponseWriter) { io.WriteString(w, `[]`) },
		"too large":  func(w http.ResponseWriter) { io.WriteString(w, `{"pad":"`+strings.Repeat("x", maxReport)+`"}`) },
	}
	for name, reply := range cases {
		route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { reply(w) })
		if att, err := route.Attest(context.Background(), "00"); err == nil || att.Report != nil {
			t.Errorf("%s: att %v err %v", name, att, err)
		}
	}
}

func TestGatewayRefusalsReachTheCallerAsUpstreamErrors(t *testing.T) {
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":{"message":"no attested upstream","type":"service_unavailable"}}`)
	})
	_, _, err := route.Complete(context.Background(), parse(t, `{"model":"kimi-k3-tee","messages":[]}`))
	var refusal apierr.Error
	if !errors.As(err, &refusal) || refusal.Status != http.StatusServiceUnavailable {
		t.Errorf("err %v, want a relayed 503", err)
	}
}

func TestReceiptIsFetchedWithOurKeyAndRelayedByteExact(t *testing.T) {
	const receipt = "{\n  \"receipt_id\": \"rcpt-2296f2fb214028509622d0d9\",\n  \"vendor\": \"<x> & y\",\n  \"served_at\": 1790732265\n}\n"
	route, got := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, receipt)
	})
	body, err := route.Receipt(context.Background(), "rcpt-2296f2fb214028509622d0d9")
	if err != nil || string(body) != receipt {
		t.Errorf("receipt %q err %v, want the gateway's bytes", body, err)
	}
	if got.path != "/v1/aci/receipts/rcpt-2296f2fb214028509622d0d9" || got.header.Get("Authorization") != "Bearer sk-phala" {
		t.Errorf("receipt request %s auth %q", got.path, got.header.Get("Authorization"))
	}
}

func TestAReceiptIDOutsideRcptPlus24LowercaseHexIsRefusedBeforeTheGateway(t *testing.T) {
	calls := 0
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	for _, bad := range []string{"", "rcpt-", "rcpt-2296F2FB214028509622D0D9", "rcpt-2296f2fb214028509622d0d", "rcpt-2296f2fb214028509622d0d9a", "chatcmpl-047346ea58694a589185856879eef398", "../v1/aci/attestation", "rcpt-2296f2fb214028509622d0d9\n"} {
		_, err := route.Receipt(context.Background(), bad)
		var invalid *chat.InvalidReceiptID
		if !errors.As(err, &invalid) || invalid.Form != "rcpt- followed by 24 lowercase hexadecimal characters" {
			t.Errorf("Receipt(%q) = %v", bad, err)
		}
	}
	if calls != 0 {
		t.Errorf("the gateway saw %d receipt fetches for ids outside the grammar", calls)
	}
}

func TestReceiptMapsAGateway404ToNotFoundAndRefusesOtherFailures(t *testing.T) {
	cases := map[string]struct {
		reply func(w http.ResponseWriter)
		want  error
	}{
		"gateway 404": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no receipt"}`)
		}, chat.ErrReceiptNotFound},
		"gateway 500": {func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, nil},
		"not json":    {func(w http.ResponseWriter) { io.WriteString(w, "<html>") }, upstream.ErrNotObject},
		"json array":  {func(w http.ResponseWriter) { io.WriteString(w, `[]`) }, upstream.ErrNotObject},
		"too large":   {func(w http.ResponseWriter) { io.WriteString(w, `{"pad":"`+strings.Repeat("x", maxReceipt)+`"}`) }, capped.ErrTooLarge},
	}
	for name, tc := range cases {
		route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { tc.reply(w) })
		body, err := route.Receipt(context.Background(), "rcpt-2296f2fb214028509622d0d9")
		switch {
		case body != nil || err == nil:
			t.Errorf("%s: body %s err %v", name, body, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnlyAPromptInTheClearTravelsOnThePlaintextClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != "/v1/chat/completions":
			io.WriteString(w, `{}`)
		case strings.Contains(r.Header.Get("Accept"), "event-stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: [DONE]\n\n")
		case r.Header.Get(e2ee.HeaderVersion) != "":
			w.Header().Set(e2ee.HeaderApplied, "true")
			w.Header().Set(e2ee.HeaderVersion, "2")
			w.Header().Set(e2ee.HeaderAlgo, e2ee.X25519.Algo())
			io.WriteString(w, `{"id":"c1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":null}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`)
		default:
			io.WriteString(w, completion)
		}
	}))
	t.Cleanup(srv.Close)
	var plaintext, sealed []string
	recording := func(seen *[]string) *http.Client {
		return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			*seen = append(*seen, r.Method+" "+r.URL.Path)
			return srv.Client().Transport.RoundTrip(r)
		})}
	}
	route := New(srv.URL, upstreamModel, "sk-phala", Clients{Plaintext: recording(&plaintext), Sealed: recording(&sealed)}, nil)
	ctx := context.Background()

	if _, _, err := route.Complete(ctx, parse(t, `{"model":"kimi-k3-tee","messages":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := route.Stream(ctx, parse(t, `{"model":"kimi-k3-tee","stream":true,"messages":[]}`), func(chat.Chunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /v1/chat/completions", "POST /v1/chat/completions"}; !slices.Equal(plaintext, want) || len(sealed) != 0 {
		t.Fatalf("plain chat went out as plaintext %v sealed %v, want %v on the plaintext client alone", plaintext, sealed, want)
	}

	params, _, err := e2ee.ParseHeaders(func(name string) string {
		return map[string]string{
			e2ee.HeaderVersion:   "2",
			e2ee.HeaderClientKey: sealKey,
			e2ee.HeaderModelKey:  "0x" + sealKey,
			e2ee.HeaderNonce:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			e2ee.HeaderTimestamp: "1750000000",
		}[name]
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Relay(ctx, parse(t, `{"model":"`+upstreamModel+`","messages":[]}`), params, func(chat.Relayed) io.Writer { return io.Discard }); err != nil {
		t.Fatal(err)
	}
	if _, err := route.Attest(ctx, "ab"); err != nil {
		t.Fatal(err)
	}
	if _, err := route.Receipt(ctx, "rcpt-2296f2fb214028509622d0d9"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /v1/chat/completions", "GET /v1/aci/attestation", "GET /v1/aci/receipts/rcpt-2296f2fb214028509622d0d9"}; !slices.Equal(sealed, want) || len(plaintext) != 2 {
		t.Errorf("the relay, the report and the receipt went out as sealed %v plaintext %v, want %v on the sealed client alone", sealed, plaintext, want)
	}
}

const sessionID = "10e5d4f1ed7b7ef05f286ac2580d1caa7375c48ff2830e923ae550e3c53d6866"

func TestSessionIsFetchedWithOurKeyAndRelayedByteExact(t *testing.T) {
	const record = "{\"api_version\":\"aci/1\",\"upstream_name\":\"phala-270\",\"note\":\"<x> & y\"}"
	route, got := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, record)
	})
	body, err := route.Session(context.Background(), sessionID)
	if err != nil || string(body) != record {
		t.Errorf("session %q err %v, want the gateway's bytes", body, err)
	}
	if got.path != "/v1/aci/sessions/"+sessionID || got.header.Get("Authorization") != "Bearer sk-phala" {
		t.Errorf("session request %s auth %q", got.path, got.header.Get("Authorization"))
	}
}

func TestASessionIDOutside64LowercaseHexIsRefusedBeforeTheGateway(t *testing.T) {
	calls := 0
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	for _, bad := range []string{"", strings.ToUpper(sessionID), sessionID[1:], sessionID + "0", "sha256:" + sessionID, "../attestation?nonce=" + sessionID[:43], sessionID[:63] + "\n", sessionID[:63] + "g"} {
		if _, err := route.Session(context.Background(), bad); !errors.Is(err, chat.ErrInvalidSessionID) {
			t.Errorf("Session(%q) = %v, want ErrInvalidSessionID", bad, err)
		}
	}
	if calls != 0 {
		t.Errorf("the gateway saw %d session fetches for ids outside the grammar", calls)
	}
}

func TestSessionMapsAGateway404ToNotFoundARecordOverOneMiBToTooLargeAndRefusesOtherFailures(t *testing.T) {
	cases := map[string]struct {
		reply func(w http.ResponseWriter)
		want  error
	}{
		"gateway 404": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"code":"not_found","message":"attested session not found or expired"}}`)
		}, chat.ErrSessionNotFound},
		"over 1 MiB":  {func(w http.ResponseWriter) { io.WriteString(w, `{"pad":"`+strings.Repeat("x", 1<<20)+`"}`) }, chat.ErrSessionTooLarge},
		"gateway 500": {func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, nil},
		"not json":    {func(w http.ResponseWriter) { io.WriteString(w, "<html>") }, upstream.ErrNotObject},
	}
	for name, tc := range cases {
		route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { tc.reply(w) })
		body, err := route.Session(context.Background(), sessionID)
		switch {
		case body != nil || err == nil:
			t.Errorf("%s: body %.40s err %v", name, body, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		case tc.want == nil && (errors.Is(err, chat.ErrSessionNotFound) || errors.Is(err, chat.ErrSessionTooLarge)):
			t.Errorf("%s: err %v, want a plain gateway failure", name, err)
		}
	}
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"pad":"`+strings.Repeat("x", 1<<20-len(`{"pad":""}`))+`"}`)
	})
	if body, err := route.Session(context.Background(), sessionID); err != nil || len(body) != 1<<20 {
		t.Errorf("a record of exactly 1 MiB: %d bytes, err %v", len(body), err)
	}
}

func listedSession(id, verifier, model string, at int64) string {
	return fmt.Sprintf(`{"api_version":"aci/1","session_id":%q,"verifier_id":%q,"established_at":%d,"evidence":{"digest":"sha256:00"},"claims":{"extra":{"canonical_model_id":%q}}}`, id, verifier, at, model)
}

func TestListSessionsKeepsOnlyThePhalaDirectSessionsForTheRoutesModel(t *testing.T) {
	other := strings.Repeat("b", 64)
	list := `{"api_version":"aci/1","sessions":[` + strings.Join([]string{
		listedSession(sessionID, "private-ai-verifier/phala-direct/v1", upstreamModel, 1792179406),
		listedSession(other, "private-ai-verifier/phala-direct/v1", "z-ai/glm-5.3", 1792179407),
		listedSession(strings.Repeat("c", 64), "private-ai-verifier/chutes/v1", upstreamModel, 1792179408),
		listedSession("not-an-id", "private-ai-verifier/tinfoil/v1", "", 1792179409),
	}, ",") + `]}`
	route, got := gateway(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, list) })
	listed, err := route.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []chat.ListedSession{{ID: sessionID, EstablishedAt: 1792179406}}; !slices.Equal(listed, want) {
		t.Errorf("listed %+v, want %+v", listed, want)
	}
	if got.path != "/v1/aci/sessions" || got.header.Get("Authorization") != "Bearer sk-phala" {
		t.Errorf("list request %s auth %q", got.path, got.header.Get("Authorization"))
	}
	all, err := route.Sessions(context.Background())
	if err != nil || len(all) != 4 || all[1].Model != "z-ai/glm-5.3" || all[2].Verifier != "private-ai-verifier/chutes/v1" {
		t.Errorf("every listed session %+v err %v, want all four with their verifier and model", all, err)
	}
}

func TestAnEmptyListIsNoSessionsAndAMalformedOneIsAFailure(t *testing.T) {
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"api_version":"aci/1","sessions":[]}`)
	})
	if listed, err := route.ListSessions(context.Background()); err != nil || listed == nil || len(listed) != 0 {
		t.Errorf("an empty list: %#v err %v, want an empty, non-nil list", listed, err)
	}
	for name, body := range map[string]string{
		"a phala-direct session with no id": `{"sessions":[` + listedSession("", "private-ai-verifier/phala-direct/v1", upstreamModel, 1) + `]}`,
		"an uppercase id":                   `{"sessions":[` + listedSession(strings.ToUpper(sessionID), "private-ai-verifier/phala-direct/v1", upstreamModel, 1) + `]}`,
		"sessions that are not a list":      `{"sessions":{}}`,
		"not json":                          `<html>`,
	} {
		route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		if listed, err := route.ListSessions(context.Background()); err == nil {
			t.Errorf("%s: listed %+v, want a failure", name, listed)
		}
	}
	route, _ = gateway(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	if _, err := route.ListSessions(context.Background()); err == nil {
		t.Error("a gateway 500 listed sessions")
	}
}

const sealKey = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"

func sealedParams(t *testing.T) chat.E2EE {
	t.Helper()
	params, _, err := e2ee.ParseHeaders(func(name string) string {
		return map[string]string{
			e2ee.HeaderVersion:   "2",
			e2ee.HeaderClientKey: sealKey,
			e2ee.HeaderModelKey:  "0x" + sealKey,
			e2ee.HeaderNonce:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			e2ee.HeaderTimestamp: "1750000000",
		}[name]
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func pinnedTo(ids ...string) string {
	quoted, _ := json.Marshal(ids)
	return `{"aci_verified":true,"zdr":true,"aci_session_ids":` + string(quoted) + `}`
}

func TestASealedRequestMayPinDistinctSessionIDsUnderTheConstraintAndNothingElse(t *testing.T) {
	route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) {})
	other := strings.Repeat("b", 64)
	many := make([]string, MaxPinnedSessions+1)
	for i := range many {
		many[i] = fmt.Sprintf("%064x", i)
	}
	check := func(provider string) error {
		return route.Check(parse(t, `{"model":"`+upstreamModel+`","provider":`+provider+`,"messages":[]}`).Request)
	}
	for _, ok := range []string{Constraint, `{"zdr":true,"aci_verified":true}`, pinnedTo(sessionID), pinnedTo(sessionID, other), pinnedTo(many[:MaxPinnedSessions]...), `{"aci_session_ids":["` + sessionID + `"],"zdr":true,"aci_verified":true}`} {
		if err := check(ok); err != nil {
			t.Errorf("provider %s refused: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"no ids":              pinnedTo(),
		"null ids":            `{"aci_verified":true,"zdr":true,"aci_session_ids":null}`,
		"too many":            pinnedTo(many...),
		"a repeated id":       pinnedTo(sessionID, sessionID),
		"an uppercase id":     pinnedTo(strings.ToUpper(sessionID)),
		"a short id":          pinnedTo(sessionID[1:]),
		"a number for an id":  `{"aci_verified":true,"zdr":true,"aci_session_ids":[1]}`,
		"aci_verified false":  `{"aci_verified":false,"zdr":true,"aci_session_ids":["` + sessionID + `"]}`,
		"no zdr":              `{"aci_verified":true,"aci_session_ids":["` + sessionID + `"]}`,
		"zdr false":           `{"aci_verified":true,"zdr":false,"aci_session_ids":["` + sessionID + `"]}`,
		"another key":         `{"aci_verified":true,"zdr":true,"aci_session_ids":["` + sessionID + `"],"order":["x"]}`,
		"the constraint only": `{"aci_verified":true}`,
		"not an object":       `"` + sessionID + `"`,
	} {
		var mismatch *chat.Mismatch
		if err := check(bad); !errors.As(err, &mismatch) || mismatch.Field != "provider" {
			t.Errorf("%s: provider %s: err %v, want a provider mismatch", name, bad, err)
		}
	}
	if err := route.Check(parse(t, `{"model":"`+upstreamModel+`","messages":[]}`).Request); err == nil {
		t.Error("a sealed request with no provider passed")
	}
}

func TestAGateway412SessionNotAcceptedIsRelayedAsItselfAndAnyOther412IsSanitized(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"session_not_accepted": {`{"error":{"message":"none of aci_session_ids is live","type":"invalid_request_error","code":"session_not_accepted"}}`, http.StatusPreconditionFailed, "session_not_accepted"},
		"another 412":          {`{"error":{"message":"x","code":"something_else"}}`, http.StatusBadRequest, apierr.ErrInvalidRequest.Code},
	} {
		route, _ := gateway(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, tc.body)
		})
		_, err := route.Relay(context.Background(), parse(t, `{"model":"`+upstreamModel+`","provider":`+pinnedTo(sessionID)+`,"messages":[]}`), sealedParams(t), func(chat.Relayed) io.Writer { return io.Discard })
		var refusal apierr.Error
		if !errors.As(err, &refusal) || refusal.Status != tc.status || refusal.Code != tc.code || strings.Contains(refusal.Message, "none of") {
			t.Errorf("%s: err %v (%+v), want %d %s", name, err, refusal, tc.status, tc.code)
		}
	}
}
