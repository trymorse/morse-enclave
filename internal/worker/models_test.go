package worker

import (
	"strings"
	"testing"

	"morse/backend/internal/catalog"
)

func TestNewInProcessRefusesAModelWhoseUpstreamDisagreesWithItsTier(t *testing.T) {
	prov := panickingProvider{}
	verbatim := Verbatim{Route: fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}}}
	for name, m := range map[string]Model{
		"serving nothing":                {Tier: catalog.Anon},
		"chat with no upstream":          {Tier: catalog.Anon, Serves: Chat{}},
		"plain without a provider":       {Tier: catalog.Private, Serves: Chat{Upstream: Plain{}}},
		"e2ee with a plaintext provider": {Tier: catalog.E2EE, Serves: Chat{Upstream: Plain{Provider: prov, Attester: fakeAttester{}}}},
		"private with an attester":       {Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: prov, Attester: fakeAttester{}}}},
		"tee without an attester":        {Tier: catalog.TEE, Serves: Chat{Upstream: Plain{Provider: prov}}},
		"tee relaying verbatim":          {Tier: catalog.TEE, Serves: Chat{Upstream: verbatim}},
		"e2ee relaying through no route": {Tier: catalog.E2EE, Serves: Chat{Upstream: Verbatim{}}},
		"images with no generator":       {Tier: catalog.Anon, Serves: Images{}},
		"a fallback that serves none":    {Tier: catalog.E2EE, Serves: Chat{Upstream: verbatim}, Fallbacks: []Model{{Tier: catalog.E2EE, Attester: "phala"}}},
	} {
		if _, err := NewInProcess(Config{Models: map[string]Model{"m": m}}); err == nil || !strings.Contains(err.Error(), "model m ") {
			t.Errorf("%s: NewInProcess gave %v, want a refusal naming model m", name, err)
		}
	}
	equipped := map[string]Model{
		"anon":    {Tier: catalog.Anon, Serves: Chat{Upstream: Plain{Provider: prov}}},
		"private": {Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: prov}}},
		"tee":     {Tier: catalog.TEE, Serves: Chat{Upstream: Plain{Provider: prov, Attester: fakeAttester{}}}},
		"e2ee":    {Tier: catalog.E2EE, Serves: Chat{Upstream: verbatim}, Fallbacks: []Model{{Endpoint: "near", Tier: catalog.E2EE, Attester: "near", Serves: Chat{Upstream: Verbatim{Route: nearVerbatimRoute{}}}}}},
	}
	if _, err := NewInProcess(Config{Models: equipped}); err != nil {
		t.Errorf("models equipped for their tiers were refused: %v", err)
	}
}
