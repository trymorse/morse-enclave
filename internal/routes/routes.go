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
	ProviderVenice
	ProviderIsoquant
	ProviderWafer
	ProviderNovita
	ProviderMorph
	ProviderDeepInfra
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
	ProviderVenice:          "venice",
	ProviderIsoquant:        "isoquant",
	ProviderWafer:           "wafer",
	ProviderNovita:          "novita",
	ProviderMorph:           "morph",
	ProviderDeepInfra:       "deepinfra",
}

func (p Provider) String() string { return providerNames.String(p) }

func ParseProvider(raw string) (Provider, error) {
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
	ID            catalog.ModelID
	Endpoint      catalog.EndpointID
	Tier          catalog.Tier
	Upstream      Upstream
	BaseURL       string
	Host          string
	UpstreamModel string
	APIKeyEnv     string
	Label         string
	OwnedBy       string
	Lab           string
	OpenWeights   bool
	Retention     catalog.Retention
	ProviderName  string
	Serves        Serves
	Included      *Included
	RequiresPlan  plankind.Kind
	// Place is how the endpoint serves under the route's name: a named route is the endpoint its name is given to,
	// and each route in its Beside is a fallback, an unnamed endpoint, or an on-behalf endpoint of that one.
	Place catalog.Place
	// Beside are the model's other endpoints that serve under this route's name, each placed. A sealed fallback
	// is a later e2ee endpoint a sealed client reseals to. An unnamed endpoint serves the tier's chats on the
	// route's terms, and no list, price row, or request name shows it. An on-behalf endpoint is the tee endpoint
	// through which the worker seals a plaintext chat to this sealed route's vendor for its client; it takes its
	// host, upstream model, key, and window from this route. A route beside another has none beside it.
	Beside []Route `json:",omitempty"`
	// OnBehalfOf is the sealed endpoint an on-behalf route seals to, and empty on every other route.
	OnBehalfOf catalog.EndpointID `json:",omitempty"`
	// Order is the endpoint's place in the routes file, the order a tier's endpoints are tried in.
	Order int
	// AppOnly keeps the route from API keys: only a login or a guest may list or call it.
	AppOnly bool
	// RebateShare is the part of an API key's margin on the model that the hourly rebate returns.
	RebateShare money.RebateShare
}

// Upstreams is the route and each endpoint beside it that is a host of its own: its fallbacks and its unnamed
// endpoints. An on-behalf endpoint reaches the route's own host, so it is left out.
func (rt Route) Upstreams() []Route {
	return append([]Route{rt}, rt.At(catalog.PlaceFallback, catalog.PlaceUnnamed)...)
}

// At is the routes beside rt at any of the places, in file order.
func (rt Route) At(places ...catalog.Place) []Route {
	var at []Route
	for _, b := range rt.Beside {
		if slices.Contains(places, b.Place) {
			at = append(at, b)
		}
	}
	return at
}

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

// IgnoresOutputLimit is whether the route's provider generates past the output limit it is sent, so the worker ends
// the reply at the limit itself.
func (rt Route) IgnoresOutputLimit() bool {
	up, vendor := rt.Upstream.(Vendor)
	return vendor && up.Provider.IgnoresOutputLimit()
}

// Hedgeable is whether a first chunk that is late is the vendor's stall, so a second call may race the first. An
// attested route never hedges: no measurement yet shows a second call escaping a TEE vendor's slow first chunk rather
// than adding to a full queue.
func (rt Route) Hedgeable() bool {
	up, vendor := rt.Upstream.(Vendor)
	return vendor && !rt.SilentWhileReasoning() && !capabilities[up.Provider].slowsTogether
}

func (rt Route) SilentWhileReasoning() bool {
	up, vendor := rt.Upstream.(Vendor)
	return vendor && capabilities[up.Provider].silentWhileReasoning
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
	// Price is what the model sells at this tier before markup, the list price a key pays.
	Price              money.Price
	Markup             money.Markup
	DecodeMaxTPS       int
	Tokenizer          string
	HiddenReasoningTPS int
	OpenRouterID       string
	// AnswersInReasoning marks a model that can send a whole answer as reasoning and stop with no content, as Ling
	// 3.0 Flash does on every host it runs on. Its provider shows that reasoning to the client as the answer.
	AnswersInReasoning bool
	// ReasoningInContent marks a host that writes the model's reasoning at the head of content, ended by </think>, as
	// Novita does for Qwen3.5 27B. Its provider moves that reasoning into reasoning_content.
	ReasoningInContent bool
	// ThinkingOffSwitch sends the host's switch that turns thinking off, Novita's enable_thinking false, on a call that
	// forwards the effort none or no effort.
	ThinkingOffSwitch bool
	// ToolCallsFinishStop marks a host that finishes a reply that calls a tool with stop, as DeepInfra does for
	// DeepSeek V3. Its provider reports tool_calls.
	ToolCallsFinishStop bool
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
