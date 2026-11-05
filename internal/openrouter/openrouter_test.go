package openrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
)

const reply = `{"id":"gen-1","provider":"DeepInfra","model":"deepseek/deepseek-v4.1-flash-1017","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],` +
	`"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"cost":0.0004,"is_byok":false,"cost_details":{"upstream_inference_cost":0.0004},"prompt_tokens_details":{"cached_tokens":1},"completion_tokens_details":{"reasoning_tokens":1}}}`

type recorder struct {
	srv      *httptest.Server
	sent     []map[string]json.RawMessage
	refusals []refusal
}

type refusal struct {
	status int
	body   string
}

func record(t *testing.T, refusals ...refusal) *recorder {
	t.Helper()
	r := &recorder{refusals: refusals}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]json.RawMessage
		json.NewDecoder(req.Body).Decode(&body)
		r.sent = append(r.sent, body)
		if req.URL.Path != "/api/v1/chat/completions" {
			http.NotFound(w, req)
			return
		}
		if len(r.refusals) > 0 {
			next := r.refusals[0]
			r.refusals = r.refusals[1:]
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(next.status)
			io.WriteString(w, next.body)
			return
		}
		if string(body["stream"]) == "true" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, ": OPENROUTER PROCESSING\n\n")
			io.WriteString(w, `data: {"id":"gen-1","provider":"DeepInfra","choices":[{"index":0,"delta":{"content":"hi"}}]}`+"\n\n")
			io.WriteString(w, `data: {"id":"gen-1","provider":"DeepInfra","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"cost":0.0004,"is_byok":false}}`+"\n\n")
			io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		io.WriteString(w, reply)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

var price = money.Price{PromptPerMTok: 300_000, CachedPromptPerMTok: 8_000, CompletionPerMTok: 1_200_000}

func (r *recorder) chat() *Chat {
	return NewChat(r.srv.URL+"/api", "sk-or", "deepseek/deepseek-v4.1-flash-1017", price, r.srv.Client())
}

func call(t *testing.T, body string) chat.Call {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return chat.Call{Request: req, OutputLimit: 64}
}

func TestEveryRequestIsHeldToZeroDataRetentionAndTheRoutesPriceWhateverTheClientSends(t *testing.T) {
	r := record(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` +
		`"provider":{"zdr":false,"data_collection":"allow","only":["deepseek"]},"plugins":[{"id":"web"}],"models":["openai/gpt-6"],"web_search_options":{},"transforms":["middle-out"]}`
	if _, _, err := r.chat().Complete(context.Background(), call(t, body)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.chat().Stream(context.Background(), call(t, body), func(chat.Chunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := `{"zdr":true,"data_collection":"deny","max_price":{"prompt":0.3,"completion":1.2}}`
	for i, sent := range r.sent {
		if string(sent["provider"]) != want {
			t.Errorf("request %d sent provider %s, want %s", i, sent["provider"], want)
		}
		for _, field := range []string{"plugins", "models", "web_search_options", "transforms"} {
			if _, ok := sent[field]; ok {
				t.Errorf("request %d forwarded the client's %s", i, field)
			}
		}
		if string(sent["model"]) != `"deepseek/deepseek-v4.1-flash-1017"` || string(sent["max_tokens"]) != "64" {
			t.Errorf("request %d sent model %s max_tokens %s", i, sent["model"], sent["max_tokens"])
		}
	}
	if len(r.sent) != 2 {
		t.Errorf("sent %d requests, want 2", len(r.sent))
	}
}

func TestTheMaxPriceIsTheRoutesRateInDollarsPerMillionTokens(t *testing.T) {
	for _, c := range []struct {
		price money.Price
		want  string
	}{
		{money.Price{PromptPerMTok: 2_000_000, CompletionPerMTok: 10_000_000}, `{"prompt":2,"completion":10}`},
		{money.Price{PromptPerMTok: 60_000, CompletionPerMTok: 180_000}, `{"prompt":0.06,"completion":0.18}`},
		{money.Price{PromptPerMTok: 1, CompletionPerMTok: 1_234_567}, `{"prompt":0.000001,"completion":1.234567}`},
	} {
		var got struct {
			MaxPrice json.RawMessage `json:"max_price"`
		}
		if err := json.Unmarshal(Constraint(c.price), &got); err != nil || string(got.MaxPrice) != c.want {
			t.Errorf("%+v: max_price %s (%v), want %s", c.price, got.MaxPrice, err, c.want)
		}
	}
}

func TestAServerToolOpenRouterWouldRunItselfIsRefusedBeforeItIsSent(t *testing.T) {
	r := record(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"openrouter:web_search"}]}`
	if _, _, err := r.chat().Complete(context.Background(), call(t, body)); !errors.Is(err, apierr.ErrMalformedRequest) {
		t.Errorf("Complete gave %v, want it refused as malformed", err)
	}
	if _, err := r.chat().Stream(context.Background(), call(t, body), func(chat.Chunk) error { return nil }); !errors.Is(err, apierr.ErrMalformedRequest) {
		t.Errorf("Stream gave %v, want it refused as malformed", err)
	}
	if len(r.sent) != 0 {
		t.Errorf("sent %d refused requests upstream", len(r.sent))
	}
}

func TestTheClientIsNotShownWhatOpenRouterChargedUsAndTheRelayIs(t *testing.T) {
	r := record(t)
	chunk, usage, err := r.chat().Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	charged := chat.VendorCost{Read: chat.CostReported, Micros: 400}
	if want := (chat.Usage{PromptTokens: 3, CompletionTokens: 2, CachedPromptTokens: 1, ReasoningTokens: 1, VendorCost: charged}); usage != want {
		t.Errorf("usage %+v, want %+v", usage, want)
	}
	var out strings.Builder
	chunk.WriteTo(&out)
	for _, leak := range []string{"cost", "is_byok", "DeepInfra", "gen-1"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("the reply names %q: %s", leak, out.String())
		}
	}
	var streamed strings.Builder
	usage, err = r.chat().Stream(context.Background(), call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`), func(c chat.Chunk) error {
		c.WriteTo(&streamed)
		return nil
	})
	if err != nil || usage.PromptTokens != 3 || usage.CompletionTokens != 2 || usage.VendorCost != charged {
		t.Fatalf("stream usage %+v err %v, want %+v charged", usage, err, charged)
	}
	for _, leak := range []string{"cost", "is_byok", "DeepInfra"} {
		if strings.Contains(streamed.String(), leak) {
			t.Errorf("the stream names %q: %s", leak, streamed.String())
		}
	}
}

func TestAStreamSendsTheUsageOpenRouterPutsOnTheFinishingChunkOnlyToAClientThatAsked(t *testing.T) {
	r := record(t)
	for _, asked := range []bool{true, false} {
		body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`
		if asked {
			body = `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`
		}
		var chunks []string
		usage, err := r.chat().Stream(context.Background(), call(t, body), func(c chat.Chunk) error {
			var out strings.Builder
			c.WriteTo(&out)
			chunks = append(chunks, out.String())
			return nil
		})
		if err != nil || usage.PromptTokens != 3 || usage.CompletionTokens != 2 {
			t.Fatalf("asked %t: usage %+v err %v", asked, usage, err)
		}
		var withUsage []string
		for _, c := range chunks {
			if strings.Contains(c, `"usage"`) {
				withUsage = append(withUsage, c)
			}
		}
		last := chunks[len(chunks)-1]
		switch {
		case asked && (len(withUsage) != 1 || withUsage[0] != last || !strings.Contains(last, `"choices":[]`) || !strings.Contains(last, `"prompt_tokens":3`)):
			t.Errorf("asked: chunks %q, want the usage alone on a last, choice-less chunk", chunks)
		case !asked && len(withUsage) != 0:
			t.Errorf("not asked: usage reached the client in %q", withUsage)
		}
		if !strings.Contains(chunks[len(chunks)-1-len(withUsage)], `"finish_reason":"stop"`) {
			t.Errorf("asked %t: the finishing chunk is missing from %q", asked, chunks)
		}
	}
}

func TestAReplyOpenRouterStreamedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"*She smiles.* "}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"","reasoning":"\"Follow me.\""}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"","reasoning":null},"finish_reason":"stop","native_finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop","native_finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`+"\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	c := NewChat(srv.URL+"/api", "sk-or", "inclusionai/ling-3.0-flash", price, srv.Client())
	var content string
	var finished bool
	_, err := c.Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(ch chat.Chunk) error {
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

func TestAReplyOpenRouterCompletedAllAsReasoningReachesTheClientAsContent(t *testing.T) {
	for name, c := range map[string]struct{ reply, content, reasoning string }{
		"all reasoning": {
			`{"id":"gen-1","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning":"*She smiles.* \"Follow me.\""},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`,
			`*She smiles.* "Follow me."`, `*She smiles.* "Follow me."`,
		},
		"content beside reasoning": {
			`{"id":"gen-1","choices":[{"index":0,"message":{"role":"assistant","content":"Hello.","reasoning":"The user greets her."},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}`,
			"Hello.", "The user greets her.",
		},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, c.reply) }))
		t.Cleanup(srv.Close)
		chunk, _, err := NewChat(srv.URL+"/api", "sk-or", "inclusionai/ling-3.0-flash", price, srv.Client()).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		if d := chunk.Delta(); err != nil || d.Content != c.content || d.Reasoning != c.reasoning || d.Finish != chat.FinishStop {
			t.Errorf("%s: content %q reasoning %q finish %s err %v, want content %q", name, d.Content, d.Reasoning, d.Finish, err, c.content)
		}
	}
}

func TestAReplyWithContentKeepsItsReasoningAsReasoning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"reasoning":"The user greets her."}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"Hello."}}]}`+"\n\n")
		io.WriteString(w, `data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	c := NewChat(srv.URL+"/api", "sk-or", "inclusionai/ling-3.0-flash", price, srv.Client())
	var content, reasoning string
	_, err := c.Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(ch chat.Chunk) error {
		d := ch.Delta()
		content, reasoning = content+d.Content, reasoning+d.Reasoning
		return nil
	})
	if err != nil || content != "Hello." || reasoning != "The user greets her." {
		t.Fatalf("content %q reasoning %q err %v", content, reasoning, err)
	}
}

func busyFrom(provider string) refusal {
	return refusal{http.StatusTooManyRequests, `{"error":{"code":429,"message":"Provider returned error","metadata":{"provider_name":"` + provider + `","raw":"rate limited"}}}`}
}

const constraint = `{"zdr":true,"data_collection":"deny","max_price":{"prompt":0.3,"completion":1.2}}`

func (r *recorder) retried() chat.BusyRetry {
	return chat.BusyRetry{Provider: r.chat(), Waits: []time.Duration{0}}
}

func TestABusyRefusalNamingItsProviderIsSentAtOncePastThatProvider(t *testing.T) {
	const stream = `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	const complete = `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	for _, streamed := range []bool{true, false} {
		r := record(t, busyFrom("Novita"))
		var content string
		var attempts chat.Attempts
		var err error
		if streamed {
			_, attempts, err = r.retried().Stream(context.Background(), call(t, stream), func(c chat.Chunk) error {
				content += c.Delta().Content
				return nil
			})
		} else {
			var chunk chat.Chunk
			chunk, _, attempts, err = r.retried().Complete(context.Background(), call(t, complete))
			content = chunk.Delta().Content
		}
		if err != nil || content != "hi" {
			t.Fatalf("streamed %t: content %q err %v, want the second attempt's reply", streamed, content, err)
		}
		if len(r.sent) != 2 || string(r.sent[0]["provider"]) != constraint ||
			string(r.sent[1]["provider"]) != `{"zdr":true,"data_collection":"deny","max_price":{"prompt":0.3,"completion":1.2},"ignore":["Novita"]}` {
			t.Fatalf("streamed %t: sent %d requests, providers %s", streamed, len(r.sent), providers(r.sent))
		}
		if attempts != (chat.Attempts{Retries: 1}) {
			t.Errorf("streamed %t: attempts %+v, want 1 retry", streamed, attempts)
		}
	}
}

func TestTheNextRequestIsStillHeldToTheWholeConstraint(t *testing.T) {
	r := record(t, busyFrom("Novita"))
	c := r.retried()
	if _, _, _, err := c.Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)); err != nil {
		t.Fatal(err)
	}
	if got := string(r.sent[2]["provider"]); got != constraint {
		t.Errorf("the call after a failover sent provider %s, want %s", got, constraint)
	}
}

func TestASecondBusyRefusalRoutesPastBothProvidersAndTheLastReachesTheClientAsTheSameBusyError(t *testing.T) {
	r := record(t, busyFrom("Novita"), busyFrom("DeepInfra"), busyFrom("Novita"), busyFrom("DeepInfra"))
	_, attempts, err := r.retried().Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(chat.Chunk) error { return nil })
	var e apierr.Error
	if !errors.As(err, &e) || e != apierr.ErrUpstreamBusy || err.Error() != apierr.ErrUpstreamBusy.Error() || !errors.Is(err, apierr.ErrUpstreamBusy) {
		t.Fatalf("err %v (%+v), want %v", err, e, apierr.ErrUpstreamBusy)
	}
	want := strings.Join([]string{constraint, `{"zdr":true,"data_collection":"deny","max_price":{"prompt":0.3,"completion":1.2},"ignore":["Novita"]}`, constraint}, " ")
	if got := providers(r.sent); got != want || attempts != (chat.Attempts{Retries: 2, Refused: true}) {
		t.Errorf("sent providers %s, attempts %+v, want %s: one reroute, then the wait's attempt under the whole constraint", got, attempts, want)
	}
}

func TestABusyRefusalStandsWhenItsProviderWasTheOnlyOneLeft(t *testing.T) {
	r := record(t, busyFrom("Novita"), refusal{http.StatusNotFound, `{"error":{"message":"All providers have been ignored. To change your default ignored providers, visit: https://openrouter.ai/settings/preferences","code":404}}`})
	_, _, attempts, err := r.retried().Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("err %v, want the wait's attempt served once every provider was ignored", err)
	}
	if len(r.sent) != 3 || attempts != (chat.Attempts{Retries: 2}) {
		t.Errorf("sent %d requests and attempts %+v, want 3 and 2 retries: the reroute, then the wait", len(r.sent), attempts)
	}
}

func TestOtherRefusalsAreNotSentAgain(t *testing.T) {
	for name, c := range map[string]struct {
		refusal refusal
		want    apierr.Error
	}{
		"server error":           {refusal{http.StatusInternalServerError, `{"error":{"code":500,"message":"x","metadata":{"provider_name":"Novita"}}}`}, apierr.ErrUpstream},
		"bad request":            {refusal{http.StatusBadRequest, `{"error":{"code":400,"message":"x","metadata":{"provider_name":"Novita"}}}`}, apierr.ErrInvalidRequest},
		"moderation flag":        {refusal{http.StatusForbidden, `{"error":{"code":403,"message":"openai/gpt-x requires moderation on OpenAI. Your input was flagged for \"harassment\". No credits were charged.","metadata":{"reasons":["harassment"],"flagged_input":"x","provider_name":"OpenAI","model_slug":"openai/gpt-x"}}}`}, apierr.ErrContentFilter},
		"forbidden with no flag": {refusal{http.StatusForbidden, `{"error":{"code":403,"message":"x","metadata":{"provider_name":"Novita"}}}`}, apierr.ErrUpstreamRefused},
		"no credits":             {refusal{http.StatusPaymentRequired, `{"error":{"code":402,"message":"x"}}`}, apierr.ErrUpstreamUnavailable},
	} {
		r := record(t, c.refusal)
		_, _, attempts, err := r.retried().Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		var e apierr.Error
		if !errors.As(err, &e) || e != c.want {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
		if len(r.sent) != 1 || attempts != (chat.Attempts{}) {
			t.Errorf("%s: sent %d requests and attempts %+v, want 1 and none", name, len(r.sent), attempts)
		}
	}
}

func TestABusyRefusalNamingNoProviderWaitsInsteadOfRerouting(t *testing.T) {
	r := record(t, refusal{http.StatusTooManyRequests, `{"error":{"code":429,"message":"Rate limit exceeded"}}`})
	_, _, attempts, err := r.retried().Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil || len(r.sent) != 2 || string(r.sent[1]["provider"]) != constraint || attempts != (chat.Attempts{Retries: 1}) {
		t.Errorf("err %v, sent %d requests (%s), attempts %+v, want the wait's attempt with nothing ignored", err, len(r.sent), providers(r.sent), attempts)
	}
}

func providers(sent []map[string]json.RawMessage) string {
	var out []string
	for _, s := range sent {
		out = append(out, string(s["provider"]))
	}
	return strings.Join(out, " ")
}

func TestTheVendorCostIsCostOrOnOurOwnProviderKeyCostPlusTheProvidersCharge(t *testing.T) {
	reported := func(micros int64, byok bool) chat.VendorCost {
		return chat.VendorCost{Read: chat.CostReported, Micros: micros, BYOK: byok}
	}
	for usage, want := range map[string]chat.VendorCost{
		`{"prompt_tokens":3}`:           {},
		`{"cost":null}`:                 {},
		`{"cost":0.0004}`:               reported(400, false),
		`{"cost":0}`:                    reported(0, false),
		`{"cost":0.0000001}`:            reported(1, false),
		`{"cost":4e-4,"is_byok":false}`: reported(400, false),
		`{"cost":-0.0004}`:              reported(-400, false),
		`{"cost":1e300}`:                {Read: chat.CostUnreadable},
		`{"cost":"0.0004"}`:             reported(400, false),
		`{"cost":"free"}`:               {Read: chat.CostUnreadable},
		`{"cost":true}`:                 {Read: chat.CostUnreadable},
		`{"cost":0.00002,"is_byok":true,"cost_details":{"upstream_inference_cost":0.0004}}`: reported(420, true),
		`{"cost":0.00002,"is_byok":true}`:                                                   {Read: chat.CostBYOKUpstreamMissing, BYOK: true},
		`{"cost":0.00002,"is_byok":true,"cost_details":{"upstream_inference_cost":null}}`:   {Read: chat.CostBYOKUpstreamMissing, BYOK: true},
		`{"cost":0.00002,"is_byok":true,"cost_details":{"upstream_inference_cost":1e300}}`:  {Read: chat.CostUnreadable, BYOK: true},
		`{"cost":0.0004,"cost_details":{"upstream_inference_cost":0.0005}}`:                 reported(500, false),
		`{"cost":0.0004,"cost_details":{"upstream_inference_cost":0.0003}}`:                 reported(400, false),
		`{"cost":0.0004,"is_byok":false,"cost_details":{"upstream_inference_cost":0.0005}}`: reported(500, false),
		`{"cost":0.0004,"cost_details":{"upstream_inference_cost":0}}`:                      reported(400, false),
	} {
		if got := vendorCost(json.RawMessage(usage)); got != want {
			t.Errorf("usage %s read as %+v, want %+v", usage, got, want)
		}
	}
}
