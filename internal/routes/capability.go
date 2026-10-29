package routes

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"morse/backend/internal/attester"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

type servedAt map[catalog.Kind][]catalog.Tier

type capability struct {
	kinds    servedAt
	zdrAt    []catalog.Tier
	zdrWhy   string
	needsKey bool
	// lacks lists the efforts on chat.EffortLadder the provider's API has no level for, so no route may list them.
	lacks []string
	hides bool
	// The provider spends reasoning beyond the client's output limit, so a hold covers the route maximum.
	uncapped bool
	// The model reasons at the vendor's default effort when the request names none, so only an effort of none the
	// route lists stops it. Anthropic's models think only at an effort the request names.
	reasonsUnasked bool
}

var (
	anonOnly       = []catalog.Tier{catalog.Anon}
	privateOnly    = []catalog.Tier{catalog.Private}
	anonAndPrivate = []catalog.Tier{catalog.Anon, catalog.Private}
)

var capabilities = map[Provider]capability{
	ProviderOpenAI:          {kinds: servedAt{catalog.KindChat: anonAndPrivate, catalog.KindTranscription: anonAndPrivate}},
	ProviderOpenAIResponses: {kinds: servedAt{catalog.KindChat: anonOnly}, needsKey: true, hides: true, reasonsUnasked: true},
	ProviderAnthropic:       {kinds: servedAt{catalog.KindChat: anonOnly}, needsKey: true, lacks: []string{chat.NoEffort}, hides: true},
	ProviderGemini: {
		kinds:          servedAt{catalog.KindChat: anonOnly, catalog.KindImage: anonOnly},
		needsKey:       true,
		lacks:          []string{chat.NoEffort, "xhigh", "max"},
		hides:          true,
		reasonsUnasked: true,
	},
	ProviderXAI: {
		kinds:          servedAt{catalog.KindChat: anonAndPrivate, catalog.KindImage: privateOnly, catalog.KindVideo: privateOnly},
		zdrAt:          privateOnly,
		zdrWhy:         "so every reply must confirm zero data retention",
		needsKey:       true,
		hides:          true,
		uncapped:       true,
		reasonsUnasked: true,
	},
	// OpenRouter routes a request to whichever host serves the model, so a route stands on the zdr constraint every
	// request carries, which keeps it to the endpoints OpenRouter lists as zero data retention.
	ProviderOpenRouter: {
		kinds:    servedAt{catalog.KindChat: privateOnly},
		zdrAt:    privateOnly,
		zdrWhy:   "because every request it sends is held to OpenRouter's zero data retention endpoints",
		needsKey: true,
	},
	// Venice keeps nothing only for the models it serves in its Private mode, under contract with their hosts. Its
	// image models carry no such contract, so they serve Anonymous.
	ProviderVenice: {
		kinds:    servedAt{catalog.KindChat: privateOnly, catalog.KindImage: anonOnly},
		zdrAt:    privateOnly,
		zdrWhy:   "because Venice keeps no prompt or reply only for the models it serves in its Private mode",
		needsKey: true,
	},
	ProviderRunware: {kinds: servedAt{catalog.KindImage: anonOnly, catalog.KindVideo: anonOnly}, needsKey: true},
	ProviderFal:     {kinds: servedAt{catalog.KindImage: anonOnly, catalog.KindVideo: anonOnly}, needsKey: true},
	// A private Parallel route stands on our zero data retention agreement with Parallel, which covers the account
	// that owns the route's key: it sends the same request as an anon route, and no reply is checked for it, unlike xAI's.
	ProviderParallel: {
		kinds:    servedAt{catalog.KindSearch: anonAndPrivate, catalog.KindFetch: anonAndPrivate, catalog.KindResearch: anonAndPrivate},
		zdrAt:    privateOnly,
		zdrWhy:   "because its self-serve terms keep queries and pages and allow training on them",
		needsKey: true,
	},
}

func attestedCapability(v *attester.Vendor) capability {
	kinds := servedAt{}
	for _, k := range catalog.Kinds() {
		for _, t := range catalog.Tiers() {
			if t.Attested() && t.Serves(k) && vendorServes(v, k, t) {
				kinds[k] = append(kinds[k], t)
			}
		}
	}
	return capability{kinds: kinds}
}

func vendorServes(v *attester.Vendor, k catalog.Kind, t catalog.Tier) bool {
	switch k {
	case catalog.KindChat:
		return t.Sealed() || !v.SealedChatOnly()
	case catalog.KindTranscription:
		return v.Transcribes()
	}
	return false
}

func Providers() []Provider { return slices.Sorted(maps.Keys(capabilities)) }

func (p Provider) Serves(kind catalog.Kind) bool {
	_, ok := capabilities[p].kinds[kind]
	return ok
}

func (p Provider) Tiers(kind catalog.Kind) []catalog.Tier {
	return slices.Clone(capabilities[p].kinds[kind])
}

func (p Provider) ReasoningUncapped() bool { return capabilities[p].uncapped }

// Reasoning is when p's model reasons on a route that lists efforts.
func (p Provider) Reasoning(efforts []string) chat.Reasoning {
	switch {
	case !capabilities[p].reasonsUnasked:
		return chat.ReasonsWhenAsked
	case slices.Contains(efforts, chat.NoEffort):
		return chat.ReasonsUnlessNone
	}
	return chat.ReasonsAlways
}

// openRouterWebSuffix turns on OpenRouter's web plugin, whose search runs outside the zdr constraint.
const openRouterWebSuffix = ":online"

func (v Vendor) check(rt Route) error {
	if v.Provider == ProviderOpenRouter && strings.HasSuffix(rt.UpstreamModel, openRouterWebSuffix) {
		return fmt.Errorf("uses %s with upstream_model %q, whose %s suffix runs a web search outside zero data retention", v, rt.UpstreamModel, openRouterWebSuffix)
	}
	return capabilities[v.Provider].check(v, rt)
}

func (c capability) check(up Upstream, rt Route) error {
	tiers, served := c.kinds[rt.Serves.Kind()]
	switch {
	case !served:
		return fmt.Errorf("is of kind %s, which %s does not serve", rt.Serves.Kind(), up)
	case !slices.Contains(tiers, rt.Tier):
		return fmt.Errorf("is tier %s, and %s serves %s routes only at tiers %v", rt.Tier, up, rt.Serves.Kind(), tiers)
	case slices.Contains(c.zdrAt, rt.Tier) && rt.Retention != catalog.RetentionZDR:
		return fmt.Errorf("uses %s at tier %s and must set retention %s, %s", up, rt.Tier, catalog.RetentionZDR, c.zdrWhy)
	case c.needsKey && rt.APIKeyEnv == "":
		return fmt.Errorf("uses %s and needs api_key_env", up)
	}
	chat, isChat := ChatOf(rt.Serves)
	if !isChat {
		return nil
	}
	if err := c.checkEfforts(up, chat); err != nil {
		return err
	}
	return c.reasoningShown(up, chat)
}

func (c capability) reasoningShown(up Upstream, chat Chat) error {
	switch {
	case c.hides && chat.reasons() && !chat.HidesReasoning:
		return fmt.Errorf("uses %s, which keeps a model's reasoning from the client, and must set hides_reasoning", up)
	case (!c.hides || !chat.reasons()) && chat.HidesReasoning:
		return fmt.Errorf("sets hides_reasoning, but %s streams whatever reasoning the model does", up)
	}
	return chat.thinkingTerms()
}

func (c Chat) thinkingTerms() error {
	switch {
	case !c.HidesReasoning && c.HiddenReasoningTPS != 0:
		return fmt.Errorf("sets hidden_reasoning_tps without hides_reasoning")
	case !c.HidesReasoning && c.DecodeMaxTPS != 0:
		return fmt.Errorf("sets decode_max_tps, which only a route that sets hides_reasoning takes")
	case !c.HidesReasoning:
		return nil
	case c.HiddenReasoningTPS <= 0 || c.DecodeMaxTPS <= 0:
		return fmt.Errorf("sets hides_reasoning and needs a positive hidden_reasoning_tps and decode_max_tps, both measured")
	case c.HiddenReasoningTPS > c.DecodeMaxTPS:
		return fmt.Errorf("sets hidden_reasoning_tps %d above its decode_max_tps %d", c.HiddenReasoningTPS, c.DecodeMaxTPS)
	}
	return nil
}

func (a Attested) check(rt Route) error {
	if err := attestedCapability(a.Attester).check(a, rt); err != nil {
		return err
	}
	c, _ := ChatOf(rt.Serves)
	if c.Tokenizer != "" {
		return fmt.Errorf("names a tokenizer, but %s relays its stream verbatim and the proxy counts only what it parses", a)
	}
	if !rt.Tier.Sealed() {
		return nil
	}
	switch {
	case c.DefaultMaxTokens != c.MaxOutputTokens:
		return fmt.Errorf("is tier %s, so default_max_tokens must equal max_output_tokens %d: the body is forwarded verbatim, so the proxy cannot add a limit", rt.Tier, c.MaxOutputTokens)
	case c.DefaultReasoningEffort != "":
		return fmt.Errorf("is tier %s and must not set default_reasoning_effort: the body is forwarded verbatim, so the proxy cannot add one", rt.Tier)
	case rt.Model != rt.UpstreamModel:
		return fmt.Errorf("is tier %s, so model must equal upstream_model %q: the body is forwarded verbatim and its receipt binds model", rt.Tier, rt.UpstreamModel)
	}
	return nil
}

func (c capability) checkEfforts(up Upstream, ch Chat) error {
	for _, effort := range ch.ReasoningEfforts {
		if slices.Contains(c.lacks, effort) {
			return fmt.Errorf("uses %s, whose API has no effort %q", up, effort)
		}
	}
	return nil
}
