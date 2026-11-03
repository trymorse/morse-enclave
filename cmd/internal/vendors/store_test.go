package vendors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"morse/backend/internal/attester"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/routes"
)

type sent struct {
	path string
	body map[string]json.RawMessage
}

func recordingVendor(t *testing.T) (*httptest.Server, func() []sent) {
	t.Helper()
	var mu sync.Mutex
	var got []sent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("%s: upstream body is not a JSON object: %s", r.URL.Path, raw)
		}
		mu.Lock()
		got = append(got, sent{r.URL.Path, body})
		mu.Unlock()
		http.Error(w, `{"error":{"message":"recorded"}}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []sent {
		mu.Lock()
		defer mu.Unlock()
		return append([]sent(nil), got...)
	}
}

func TestNoChatProviderSendsAVendorStoreTrueOrReachesAResponsesEndpointButOpenAIResponses(t *testing.T) {
	type vendor struct {
		name     string
		upstream routes.Upstream
	}
	vendors := []vendor{{"phala plaintext", routes.Attested{Attester: attester.Phala}}}
	for p := range chatProviders {
		vendors = append(vendors, vendor{p.String(), routes.Vendor{Provider: p}})
	}
	for _, v := range vendors {
		for _, stream := range []bool{false, true} {
			srv, sentNow := recordingVendor(t)
			rt := routes.Route{Model: "m", BaseURL: srv.URL, UpstreamModel: "up/m", Tier: catalog.Private, Upstream: v.upstream, Serves: routes.Chat{}}
			p, err := ChatProvider(rt, "k", srv.Client())
			if err != nil {
				t.Fatalf("%s: %v", v.name, err)
			}
			req, err := chat.ParseRequest(strings.NewReader(`{"model":"m","stream":` + strconv.FormatBool(stream) + `,"max_tokens":64,"store":true,"messages":[{"role":"user","content":"hi"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			call := chat.Call{Request: req, OutputLimit: 64, Efforts: chat.EffortLadder}
			if stream {
				p.Stream(context.Background(), call, func(chat.Chunk) error { return nil })
			} else {
				p.Complete(context.Background(), call)
			}
			got := sentNow()
			if len(got) == 0 {
				t.Errorf("%s stream=%t: no request reached the vendor, so the test proves nothing", v.name, stream)
			}
			for _, s := range got {
				responses := strings.HasSuffix(s.path, "/responses")
				store, carried := s.body["store"]
				switch {
				case responses && v.upstream != routes.Vendor{Provider: routes.ProviderOpenAIResponses}:
					t.Errorf("%s stream=%t: posted to %s, a Responses endpoint that stores by default", v.name, stream, s.path)
				case responses && string(store) != "false":
					t.Errorf("%s stream=%t: posted to %s with store %s, want false", v.name, stream, s.path, store)
				case !responses && carried:
					t.Errorf("%s stream=%t: posted to %s with store %s, want no store field", v.name, stream, s.path, store)
				}
			}
		}
	}
}
