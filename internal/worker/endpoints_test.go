package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

type answeringProvider struct{}

func (answeringProvider) Stream(_ context.Context, _ chat.Call, emit func(chat.Chunk) error) (chat.Usage, error) {
	return chat.Usage{PromptTokens: 1, CompletionTokens: 1}, emit(chat.NewChunk([]byte(contentChunk)))
}

func (answeringProvider) Complete(context.Context, chat.Call) (chat.Chunk, chat.Usage, error) {
	panic("the test streams")
}

func endpointModels() map[string]Model {
	verbatim := func(r chat.VerbatimRoute) Serving {
		return Chat{ChatTerms: catalog.ChatTerms{MaxOutputTokens: testSealedMaxOutput}, Upstream: Verbatim{Route: r}}
	}
	return map[string]Model{
		"m": {ID: "z/m", Endpoint: "together", Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: answeringProvider{}}}},
		"kimi-e2ee": {ID: "z/m", Endpoint: "near", Tier: catalog.E2EE, Attester: "near", Serves: verbatim(nearVerbatimRoute{fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}}}),
			Fallbacks: []Model{{Endpoint: "phala", Tier: catalog.E2EE, Attester: "phala", Serves: verbatim(fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}})}}},
	}
}

func TestTheWorkerAdmitsANameAsItsModelWithTheOneEndpointThatCanReadTheBody(t *testing.T) {
	c := overTheWire(t, endpointModels())
	sealed := http.Header{"Content-Type": {"application/json"}}
	for k, v := range sealHeaders {
		sealed.Set(k, v)
	}
	for name, tc := range map[string]struct {
		header http.Header
		body   string
		want   []catalog.EndpointID
	}{
		"a plaintext chat on an alias":        {http.Header{"Content-Type": {"application/json"}}, streamBody(""), []catalog.EndpointID{"together"}},
		"a body sealed to the fallback's key": {sealed, sealedBody(""), []catalog.EndpointID{"phala"}},
	} {
		admitted, err := c.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/chat/completions", Header: tc.header, Body: strings.NewReader(tc.body)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a := admitted.(ChatAdmission)
		if a.Model != "z/m" || !reflect.DeepEqual(a.Candidates, tc.want) {
			t.Errorf("%s: admitted model %q with candidates %v, want z/m with %v", name, a.Model, a.Candidates, tc.want)
		}
	}
}

func TestTheWorkerRunsOnlyAGrantWhoseEndpointsAreAllItsCandidatesAndNamesTheOneThatServed(t *testing.T) {
	c := overTheWire(t, endpointModels())
	for name, tc := range map[string]struct {
		proposed []catalog.EndpointID
		served   bool
	}{
		"its candidate":                 {[]catalog.EndpointID{"together"}, true},
		"no endpoint":                   {nil, false},
		"an endpoint of another vendor": {[]catalog.EndpointID{"phala-tee"}, false},
		"its candidate then another":    {[]catalog.EndpointID{"together", "phala-tee"}, false},
	} {
		admitted, err := c.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/chat/completions", Header: http.Header{"Content-Type": {"application/json"}}, Body: strings.NewReader(streamBody(""))})
		if err != nil {
			t.Fatal(err)
		}
		reply := httptest.NewRecorder()
		m := c.Run(context.Background(), admitted.Handle(), ChatGrant{Endpoints: tc.proposed, OutputLimit: 64}, reply)
		switch {
		case tc.served && (reply.Code != http.StatusOK || !m.Served || m.Endpoint != "together"):
			t.Errorf("%s: replied %d, served %t at endpoint %q, want 200 served at together", name, reply.Code, m.Served, m.Endpoint)
		case !tc.served && (reply.Code != http.StatusServiceUnavailable || m.Served || m.Endpoint != ""):
			t.Errorf("%s: replied %d, served %t at endpoint %q, want 503 unserved at none", name, reply.Code, m.Served, m.Endpoint)
		}
	}
}
