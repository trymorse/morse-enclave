package vendors

import (
	"maps"
	"slices"
	"testing"

	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/routes"
	"morse/backend/internal/worker"
)

func TestEveryProviderAndKindRoutesAcceptsHasABuilderAndNoBuilderIsUnreachable(t *testing.T) {
	for _, p := range routes.Providers() {
		for _, kind := range catalog.Kinds() {
			if built := builders[p][kind] != nil; built != p.Serves(kind) {
				t.Errorf("provider %s, kind %s: the routes file accepts it %t, the proxy builds it %t", p, kind, p.Serves(kind), built)
			}
		}
	}
	for p, kinds := range builders {
		if !slices.Contains(routes.Providers(), p) {
			t.Errorf("provider %s has builders for %v but no capabilities", p, slices.Collect(maps.Keys(kinds)))
		}
	}
}

func TestAChatRouteIsBuiltWithTheDefaultHedgeUnlessItIsNotHedgeable(t *testing.T) {
	for _, c := range []struct {
		provider routes.Provider
		want     chat.Hedge
	}{{routes.ProviderOpenAI, chat.DefaultHedge}, {routes.ProviderAnthropic, chat.Hedge{}}, {routes.ProviderGemini, chat.Hedge{}}} {
		rt := routes.Route{Model: "m", BaseURL: "https://u", UpstreamModel: "up/m", Tier: catalog.Anon, Upstream: routes.Vendor{Provider: c.provider}, Serves: routes.Chat{}}
		served, err := Build(rt, "k", Deps{})
		if err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		if got := served.(worker.Chat).Upstream.(worker.Plain).Hedge; got != c.want {
			t.Errorf("%s: built with hedge %+v, want %+v", c.provider, got, c.want)
		}
	}
}
