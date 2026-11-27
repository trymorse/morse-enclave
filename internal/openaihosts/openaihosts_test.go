package openaihosts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/phala"
	"morse/backend/internal/upstream"
)

const (
	whole  = `{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`
	stream = `data: {"id":"x","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}` + "\n\n" + `data: {"id":"x","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}` + "\n\ndata: [DONE]\n\n"
)

type sent struct {
	path   string
	header http.Header
	body   string
}

type hostStub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []sent
	fail func(w http.ResponseWriter) bool
}

func stub(t *testing.T) *hostStub {
	t.Helper()
	s := &hostStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, sent{r.URL.Path, r.Header.Clone(), string(raw)})
		fail := s.fail
		s.mu.Unlock()
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			http.NotFound(w, r)
			return
		}
		if fail != nil && fail(w) {
			return
		}
		if strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, stream)
			return
		}
		io.WriteString(w, whole)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *hostStub) requests() []sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sent(nil), s.seen...)
}

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func zdrHosts(t *testing.T) []Host {
	t.Helper()
	var hs []Host
	for _, h := range Hosts() {
		if h.ZDRHeader != "" {
			hs = append(hs, h)
		}
	}
	if Wafer.ZDRHeader != "Wafer-ZDR" || Isoquant.ZDRHeader != "Isoquant-ZDR" {
		t.Fatalf("Wafer sends %q and Isoquant %q, want Wafer-ZDR and Isoquant-ZDR", Wafer.ZDRHeader, Isoquant.ZDRHeader)
	}
	return hs
}

func TestEveryBodySentToPhalaCarriesItsZeroRetentionConstraintWhateverTheCallerSent(t *testing.T) {
	msgs := `"messages":[{"role":"user","content":"hello"}]`
	for name, body := range map[string]string{
		"a plain call":              `{"model":"m",` + msgs + `}`,
		"a caller's own provider":   `{"model":"m","provider":{"zdr":false,"aci_verified":false},` + msgs + `}`,
		"a caller's provider order": `{"model":"m","provider":{"order":["someone-else"]},` + msgs + `}`,
	} {
		s := stub(t)
		c := PhalaZDR.NewChat(s.srv.URL, "k", "phala/m", catalog.Fixes{}, s.srv.Client())
		if _, _, err := c.Complete(context.Background(), call(t, body)); err != nil {
			t.Fatalf("%s, whole: %v", name, err)
		}
		if _, err := c.Stream(context.Background(), call(t, strings.Replace(body, `{"model"`, `{"stream":true,"model"`, 1)), func(chat.Chunk) error { return nil }); err != nil {
			t.Fatalf("%s, streamed: %v", name, err)
		}
		reqs := s.requests()
		if len(reqs) != 2 {
			t.Fatalf("%s: %d requests reached the host, want 2", name, len(reqs))
		}
		for _, r := range reqs {
			var sent struct {
				Provider json.RawMessage `json:"provider"`
			}
			if err := json.Unmarshal([]byte(r.body), &sent); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if string(sent.Provider) != phala.Constraint || strings.Count(r.body, `"provider"`) != 1 {
				t.Errorf("%s: the host was sent %s, want its one provider field to be %s", name, r.body, phala.Constraint)
			}
		}
		if !strings.Contains(reqs[1].body, `"continuous_usage_stats":true`) {
			t.Errorf("%s: the stream was sent %s, want usage asked for on every chunk", name, reqs[1].body)
		}
	}
}

func TestEveryRequestToAZDRHeaderHostCarriesTheHeaderWhateverTheCall(t *testing.T) {
	msgs := `"messages":[{"role":"user","content":"hello"}]`
	for _, h := range zdrHosts(t) {
		s := stub(t)
		c := h.NewChat(s.srv.URL, "k", "m", catalog.Fixes{}, s.srv.Client())
		ctx := context.Background()
		if _, err := c.Stream(ctx, call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},`+msgs+`}`), func(chat.Chunk) error { return nil }); err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		if _, _, err := c.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		s.fail = func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusServiceUnavailable); return true }
		for range 3 {
			if _, _, err := c.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err == nil {
				t.Fatalf("%s: a 503 reply was no error", h.Name)
			}
		}
		s.fail = nil
		if _, _, err := c.Complete(ctx, call(t, `{"model":"m",`+msgs+`}`)); err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		got := s.requests()
		if len(got) != 6 {
			t.Fatalf("%s saw %d requests, want 6", h.Name, len(got))
		}
		for i, r := range got {
			if values := r.header.Values(h.ZDRHeader); len(values) != 1 || values[0] != ZDRValue {
				t.Errorf("%s: request %d carried %s %q, want exactly one %q", h.Name, i+1, h.ZDRHeader, values, ZDRValue)
			}
		}
	}
}

func TestNoHeaderOfARequestOrAKeyOverridesTheZDRHeader(t *testing.T) {
	for _, h := range zdrHosts(t) {
		name := h.ZDRHeader
		s := stub(t)
		e := h.Endpoint(s.srv.URL, "k", s.srv.Client())
		for _, header := range []http.Header{{name: {"optional"}}, {name: {""}}, {strings.ToLower(name): {"optional"}}, nil} {
			resp, err := e.Open(context.Background(), upstream.Request{Method: http.MethodPost, Path: "/v1/chat/completions", Header: header, Body: []byte(`{}`)})
			if err != nil {
				t.Fatalf("%s %v: %v", h.Name, header, err)
			}
			resp.Body.Close()
		}
		got := s.requests()
		if len(got) != 4 {
			t.Fatalf("%s saw %d requests, want 4", h.Name, len(got))
		}
		for i, r := range got {
			if values := r.header.Values(name); len(values) != 1 || values[0] != ZDRValue {
				t.Errorf("%s: request %d carried %s %q, want exactly %q", h.Name, i+1, name, values, ZDRValue)
			}
		}
	}
}

func TestAnEndpointWithoutAKeyStillSendsTheZDRHeader(t *testing.T) {
	for _, h := range zdrHosts(t) {
		if got := h.Endpoint("https://example.test", "", nil).Auth.Get(h.ZDRHeader); got != ZDRValue {
			t.Errorf("a keyless %s endpoint sends %s %q, want %q", h.Name, h.ZDRHeader, got, ZDRValue)
		}
	}
}

var limitFields = map[string]string{"wafer": "max_tokens", "isoquant": "max_tokens", "novita": "max_completion_tokens", "morph": "max_tokens", "deepinfra": "max_tokens", "phala-zdr": "max_tokens", "heabsy": "max_tokens", "silk": "max_tokens", "abliteration": "max_tokens"}

func TestAHostWithNoZDRHeaderIsSentTheKeyAloneAndEveryHostItsOwnModelAndLimitField(t *testing.T) {
	for _, h := range Hosts() {
		field, ok := limitFields[h.Name]
		if !ok {
			t.Fatalf("%s has no limit field in limitFields", h.Name)
		}
		s := stub(t)
		reply, _, err := h.NewChat(s.srv.URL, "k", "upstream-model-1017", catalog.Fixes{}, s.srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		if err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		var out bytes.Buffer
		reply.WriteTo(&out)
		r := s.requests()[0]
		if !strings.Contains(r.body, `"model":"upstream-model-1017"`) || !strings.Contains(r.body, `"`+field+`":64`) {
			t.Errorf("%s was sent %s, want its own model id and %s", h.Name, r.body, field)
		}
		if !strings.Contains(out.String(), `"hi"`) {
			t.Errorf("%s: reply %s lost the content", h.Name, out.String())
		}
		if h.ZDRHeader != "" {
			continue
		}
		for name := range r.header {
			if strings.HasSuffix(strings.ToLower(name), "-zdr") {
				t.Errorf("%s, which has no ZDR header, was sent %s", h.Name, name)
			}
		}
	}
}

func TestNovitaIsSentTheCapAsMaxCompletionTokensAndNeverMaxTokensWhateverTheCallerSent(t *testing.T) {
	msgs := `"messages":[{"role":"user","content":"hello"}]`
	for _, limit := range []string{``, `"max_tokens":999,`, `"max_completion_tokens":999,`, `"max_tokens":999,"max_completion_tokens":999,`} {
		s := stub(t)
		c := Novita.NewChat(s.srv.URL, "k", "qwen/qwen3.5-397b-a17b", catalog.Fixes{}, s.srv.Client())
		ctx := context.Background()
		if _, err := c.Stream(ctx, call(t, `{"model":"m","stream":true,`+limit+msgs+`}`), func(chat.Chunk) error { return nil }); err != nil {
			t.Fatalf("%s stream: %v", limit, err)
		}
		if _, _, err := c.Complete(ctx, call(t, `{"model":"m",`+limit+msgs+`}`)); err != nil {
			t.Fatalf("%s complete: %v", limit, err)
		}
		for i, r := range s.requests() {
			if strings.Count(r.body, `"max_completion_tokens":64`) != 1 || strings.Contains(r.body, `"max_tokens"`) || strings.Contains(r.body, `999`) {
				t.Errorf("caller sent %q; request %d was %s, want one max_completion_tokens of 64 and no max_tokens", limit, i+1, r.body)
			}
		}
	}
}

func TestAModelWaferCannotServeUnderZDRIsAHostRefusalAndAnInvalidZDRHeaderIsNot(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   apierr.Error
	}{
		"422 model_zdr_not_supported": {http.StatusUnprocessableEntity, `{"error":{"code":"model_zdr_not_supported","message":"vendor text"}}`, apierr.ErrUpstreamUnavailable},
		"400 invalid_zdr_header":      {http.StatusBadRequest, `{"error":{"code":"invalid_zdr_header","message":"vendor text"}}`, apierr.ErrInvalidRequest},
	} {
		s := stub(t)
		s.fail = refuseWith(tc.status, tc.body)
		_, _, err := Wafer.NewChat(s.srv.URL, "k", "GLM-5.3-Flash", catalog.Fixes{}, s.srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		var got apierr.Error
		if !errors.As(err, &got) || got.Code != tc.want.Code || strings.Contains(got.Message, "vendor text") {
			t.Errorf("%s: %v, want %s with no vendor text", name, err, tc.want.Code)
		}
	}
}

func TestAnIsoquantAccountRefusalIsNotARequestRefusalThatStands(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   apierr.Error
	}{
		"402 of a dry account":             {http.StatusPaymentRequired, `{"error":{"code":"insufficient_credits","message":"vendor text","type":"gateway_error"}}`, apierr.ErrUpstreamUnavailable},
		"403 model_forbidden":              {http.StatusForbidden, `{"error":{"code":"model_forbidden","message":"Model is not available to this credential","type":"gateway_error"},"request_id":"iqr_1"}`, apierr.ErrUpstreamUnavailable},
		"403 of another kind":              {http.StatusForbidden, `{"error":{"code":"forbidden","message":"vendor text","type":"gateway_error"}}`, apierr.ErrUpstreamRefused},
		"400 unsupported_reasoning_effort": {http.StatusBadRequest, `{"error":{"code":"unsupported_reasoning_effort","message":"vendor text","type":"gateway_error"}}`, apierr.ErrInvalidRequest},
	} {
		s := stub(t)
		s.fail = refuseWith(tc.status, tc.body)
		_, _, err := Isoquant.NewChat(s.srv.URL, "k", "glm-5.3-flash", catalog.Fixes{}, s.srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		var got apierr.Error
		if !errors.As(err, &got) || got.Code != tc.want.Code || strings.Contains(got.Message, "vendor text") {
			t.Errorf("%s: %v, want %s with no vendor text", name, err, tc.want.Code)
		}
	}
}

func refuseWith(status int, body string) func(w http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
		return true
	}
}

func TestAReplyNovitaStreamedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"*She smiles.* "}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"","reasoning":"\"Follow me.\""}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`+"\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	var content string
	var finished bool
	_, err := Novita.NewChat(srv.URL, "sk-nv", "inclusionai/ling-3.0-flash", catalog.Fixes{AnswersInReasoning: true}, srv.Client()).Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(ch chat.Chunk) error {
		d := ch.Delta()
		if finished && d.Content != "" {
			t.Errorf("content %q arrived after the finishing chunk", d.Content)
		}
		content += d.Content
		finished = finished || d.Finish == chat.FinishStop
		return nil
	})
	if err != nil || content != `*She smiles.* "Follow me."` || !finished {
		t.Fatalf("content %q finished %t err %v, want the reasoning as content before the finish", content, finished, err)
	}
}

func TestAReplyNovitaCompletedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `{"id":"gen-1","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning":"*She smiles.* \"Follow me.\""},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`)
	}))
	t.Cleanup(srv.Close)
	chunk, _, err := Novita.NewChat(srv.URL, "sk-nv", "inclusionai/ling-3.0-flash", catalog.Fixes{AnswersInReasoning: true}, srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if d := chunk.Delta(); err != nil || d.Content != `*She smiles.* "Follow me."` || d.Finish != chat.FinishStop {
		t.Fatalf("content %q finish %s err %v, want the reasoning as content", d.Content, d.Finish, err)
	}
}

func TestOnlyDeepInfraAndAbliterationAreSentTheCallsCacheKeyInTheBodyMorphInItsHeaderAndNoHostTheClients(t *testing.T) {
	for _, h := range Hosts() {
		for _, stream := range []bool{false, true} {
			s := stub(t)
			c := call(t, `{"model":"m","stream":`+strconv.FormatBool(stream)+`,"prompt_cache_key":"pk-client","messages":[{"role":"user","content":"hello"}]}`)
			c.CacheKey = "0123456789abcdef0123456789abcdef"
			p := h.NewChat(s.srv.URL, "k", "m", catalog.Fixes{}, s.srv.Client())
			var err error
			if stream {
				_, err = p.Stream(context.Background(), c, func(chat.Chunk) error { return nil })
			} else {
				_, _, err = p.Complete(context.Background(), c)
			}
			if err != nil {
				t.Fatalf("%s: %v", h.Name, err)
			}
			body := s.requests()[0].body
			if strings.Contains(body, "pk-client") {
				t.Errorf("%s was sent the client's prompt_cache_key: %s", h.Name, body)
			}
			sentKey := strings.Contains(body, `"prompt_cache_key":"0123456789abcdef0123456789abcdef"`)
			if want := h.Name == DeepInfra.Name || h.Name == Abliteration.Name; sentKey != want || strings.Count(body, "prompt_cache_key") > 1 {
				t.Errorf("%s (stream %t) was sent %s, want the call's cache key %t", h.Name, stream, body, want)
			}
			header := s.requests()[0].header
			if got, want := header.Values("X-Session-Id"), h.Name == Morph.Name; want != slices.Equal(got, []string{c.CacheKey}) || !want && len(got) != 0 {
				t.Errorf("%s (stream %t) was sent X-Session-Id %v, want the call's cache key %t", h.Name, stream, got, want)
			}
			for name, values := range header {
				if slices.ContainsFunc(values, func(v string) bool { return strings.Contains(v, "pk-client") }) {
					t.Errorf("%s was sent the client's prompt_cache_key in %s", h.Name, name)
				}
			}
		}
	}
	for _, h := range Hosts() {
		s := stub(t)
		if _, _, err := h.NewChat(s.srv.URL, "k", "m", catalog.Fixes{}, s.srv.Client()).Complete(context.Background(), call(t, `{"model":"m","session_id":"end-user-42","messages":[{"role":"user","content":"hello"}]}`)); err != nil {
			t.Fatal(err)
		}
		if r := s.requests()[0]; strings.Contains(r.body, "end-user-42") || r.header.Get("X-Session-Id") != "" {
			t.Errorf("%s was sent %v %s for a call with no cache key, want no session id", h.Name, r.header, r.body)
		}
	}
	s := stub(t)
	if _, _, err := DeepInfra.NewChat(s.srv.URL, "k", "m", catalog.Fixes{}, s.srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`)); err != nil {
		t.Fatal(err)
	}
	if body := s.requests()[0].body; strings.Contains(body, "prompt_cache_key") {
		t.Errorf("DeepInfra was sent %s for a call with no cache key, want no prompt_cache_key", body)
	}
}

func TestEveryHostIsSentAnAssistantsReplayedReasoningUnderTheKeysItsTemplateReads(t *testing.T) {
	for _, h := range Hosts() {
		s := stub(t)
		c := h.NewChat(s.srv.URL, "k", "m", catalog.Fixes{}, s.srv.Client())
		if _, _, err := c.Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"a","reasoning":"plan"},{"role":"user","content":"go on"}]}`)); err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		var sent struct{ Messages []map[string]any }
		if err := json.Unmarshal([]byte(s.requests()[0].body), &sent); err != nil {
			t.Fatal(err)
		}
		_, underReasoning := sent.Messages[1]["reasoning"]
		if sent.Messages[1]["reasoning_content"] != "plan" || underReasoning != (h.Name == "wafer") {
			t.Errorf("%s was sent the assistant message %v, want the reasoning as reasoning_content, and as reasoning too only on wafer", h.Name, sent.Messages[1])
		}
	}
}
