package routes

import (
	"fmt"
	"slices"

	"morse/backend/internal/attester"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/enum"
	"morse/backend/internal/plankind"
)

type Provider uint8

const (
	ProviderOpenAI Provider = iota + 1
	ProviderOpenAIResponses
	ProviderAnthropic
	ProviderXAI
	ProviderRunware
	ProviderFal
	ProviderParallel
	ProviderGemini
	ProviderOpenRouter
	ProviderVenice
)

var providerNames = enum.Names[Provider]{
	ProviderOpenAI:          "openai",
	ProviderOpenAIResponses: "openai-responses",
	ProviderAnthropic:       "anthropic",
	ProviderXAI:             "xai",
	ProviderRunware:         "runware",
	ProviderFal:             "fal",
	ProviderParallel:        "parallel",
	ProviderGemini:          "gemini",
	ProviderOpenRouter:      "openrouter",
	ProviderVenice:          "venice",
}

func (p Provider) String() string { return providerNames.String(p) }

func parseProvider(raw string) (Provider, error) {
	if raw == "" {
		return ProviderOpenAI, nil
	}
	p, ok := providerNames.Parse(raw)
	if !ok {
		return 0, fmt.Errorf("provider %q must be one of %s", raw, providerNames.List())
	}
	return p, nil
}

type Route struct {
	Model         string
	Tier          catalog.Tier
	Upstream      Upstream
	BaseURL       string
	Host          string
	UpstreamModel string
	APIKeyEnv     string
	Label         string
	OwnedBy       string
	Retention     catalog.Retention
	Serves        Serves
	Included      *Included
	RequiresPlan  plankind.Kind
	Fallbacks     []Route
	// AppOnly keeps the route from API keys: only a login or a guest may list or call it.
	AppOnly bool
}

func (rt Route) Upstreams() []Route { return append([]Route{rt}, rt.Fallbacks...) }

// KeyEnvs is every api_key_env that rts or their fallbacks name, sorted, each once.
func KeyEnvs(rts []Route) []string {
	var names []string
	for _, served := range rts {
		for _, rt := range served.Upstreams() {
			if rt.APIKeyEnv != "" {
				names = append(names, rt.APIKeyEnv)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// ReasoningUncapped is whether the route's provider spends reasoning beyond the client's output limit, so the relay
// holds for the route's maximum and the worker lets the model reach it.
func (rt Route) ReasoningUncapped() bool {
	up, vendor := rt.Upstream.(Vendor)
	return vendor && up.Provider.ReasoningUncapped()
}

// Hedgeable is whether a first chunk that is late is the vendor's stall, so a second call may race the first. An
// attested route never hedges: no measurement yet shows a second call escaping a TEE vendor's slow first chunk rather
// than adding to a full queue.
func (rt Route) Hedgeable() bool {
	up, vendor := rt.Upstream.(Vendor)
	c := capabilities[up.Provider]
	return vendor && !c.silentWhileReasoning && !c.slowsTogether
}

type Upstream interface {
	fmt.Stringer
	check(Route) error
}

type Vendor struct{ Provider Provider }

type Attested struct{ Attester *attester.Vendor }

func (v Vendor) String() string   { return "provider " + v.Provider.String() }
func (a Attested) String() string { return "attester " + a.Attester.Name }

type Serves interface{ Kind() catalog.Kind }

type Chat struct {
	catalog.ChatTerms
	Price              money.Price
	Markup             money.Markup
	DecodeMaxTPS       int
	Tokenizer          string
	HiddenReasoningTPS int
	OpenRouterID       string
}

func (c Chat) reasons() bool { return len(c.ReasoningEfforts) > 0 }

func ChatOf(s Serves) (Chat, bool) {
	c, ok := s.(Chat)
	return c, ok
}

func (c Chat) ThinkingTerms() measure.ThinkingTerms {
	return measure.ThinkingTerms{Seed: c.HiddenReasoningTPS, DecodeMax: c.DecodeMaxTPS}
}

type Image struct{ Price money.MediaPrice }

type Video struct{ Price money.MediaPrice }

type PerCall struct {
	Call  catalog.Kind
	Price money.Micros
}

func (c Chat) Billed() money.Price { return c.Markup.Price(c.Price) }

func (Chat) Kind() catalog.Kind      { return catalog.KindChat }
func (Image) Kind() catalog.Kind     { return catalog.KindImage }
func (Video) Kind() catalog.Kind     { return catalog.KindVideo }
func (c PerCall) Kind() catalog.Kind { return c.Call }
