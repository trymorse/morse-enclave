package routes

import (
	"fmt"
	"maps"
	"slices"

	"morse/backend/internal/attester"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

type servedAt map[catalog.Kind][]catalog.Tier

type capability struct {
	kinds          servedAt
	zdrAt          []catalog.Tier
	zdrWhy         string
	zdrLink        string
	zdrLinkChecked string
	zdrAgreed      string
	zdrHeld        Held
	makes          map[string]string
	needsKey       bool
	// lacks lists the efforts on chat.EffortLadder the provider's API has no level for, so no route may list them.
	lacks      []string
	hides      bool
	summarizes bool
	// The provider spends reasoning beyond the client's output limit, so a hold covers the route maximum.
	uncapped bool
	// The provider generates past the output limit it is sent, whichever field carries it, so the worker counts the reply
	// and ends it at the limit itself, and the hold for the limit covers what the reply is billed.
	ignoresLimit bool
	// The model reasons at the vendor's default effort when the request names none, so only an effort of none the
	// route lists stops it.
	reasonsUnasked bool
	// Gemini returns thought parts only to a request that sets includeThoughts, so the first chunk waits out the
	// reasoning. A late first chunk is then not a stall to hedge, and only answer tokens follow it.
	silentWhileReasoning bool
	// A slow first chunk is the vendor slowing every request at once, so a second call is as late as the first and
	// only adds to the bill. Anthropic's slow windows held a hedge's call as long as the first: it won 0 of 36.
	slowsTogether bool
	// The provider shows a reply that is all reasoning as the answer for a model that sets answers_in_reasoning.
	answersFromReasoning bool
	refusesDryAccount    bool
	openAIHost           bool
	switchesThinking     bool
	sendsSettings        bool
}

var (
	anonOnly       = []catalog.Tier{catalog.Anon}
	privateOnly    = []catalog.Tier{catalog.Private}
	anonAndPrivate = []catalog.Tier{catalog.Anon, catalog.Private}
)

var capabilities = map[Provider]capability{
	ProviderOpenAI: {kinds: servedAt{catalog.KindChat: anonAndPrivate, catalog.KindTranscription: anonAndPrivate}, makes: map[string]string{"api.openai.com": "OpenAI"}},
	// Meta's muse routes share this provider, and their dry-account reply is undocumented, so a dry account is no
	// account refusal.
	ProviderOpenAIResponses: {kinds: servedAt{catalog.KindChat: anonOnly}, makes: map[string]string{"api.openai.com": "OpenAI", "api.meta.ai": "Meta"}, needsKey: true, hides: true, summarizes: true, reasonsUnasked: true},
	// An empty Anthropic prepaid balance is a 400 by report only, and a spend limit we set is a 400 that stands as a bad
	// request, so a dry account is no account refusal.
	ProviderAnthropic: {kinds: servedAt{catalog.KindChat: anonOnly}, makes: map[string]string{"api.anthropic.com": "Anthropic"}, needsKey: true, lacks: []string{chat.NoEffort}, hides: true, summarizes: true, slowsTogether: true, reasonsUnasked: true},
	// Gemini's docs name no status for a dry billing account, and its 403 PERMISSION_DENIED maps to upstream_refused,
	// so a dry account is no account refusal.
	ProviderGemini: {
		kinds:                servedAt{catalog.KindChat: anonOnly, catalog.KindImage: anonOnly},
		makes:                map[string]string{"generativelanguage.googleapis.com": "Google"},
		needsKey:             true,
		lacks:                []string{chat.NoEffort, "max"},
		hides:                true,
		summarizes:           true,
		reasonsUnasked:       true,
		silentWhileReasoning: true,
	},
	// xAI's docs say only that requests are rejected once prepaid credit runs out. The status is unknown until a
	// depleted key answers, so a dry account is no account refusal.
	ProviderXAI: {
		kinds:          servedAt{catalog.KindChat: anonAndPrivate, catalog.KindImage: privateOnly, catalog.KindVideo: privateOnly},
		zdrAt:          privateOnly,
		zdrWhy:         "so every reply must confirm zero data retention",
		zdrLink:        "https://docs.x.ai/developers/faq/security#what-is-zero-data-retention-zdr",
		zdrLinkChecked: "2026-11-17",
		zdrHeld:        HeldReplyCheck,
		makes:          map[string]string{"api.x.ai": "xAI"},
		needsKey:       true,
		hides:          true,
		uncapped:       true,
		reasonsUnasked: true,
		sendsSettings:  true,
	},
	// Venice keeps nothing only for the models it serves in its Private mode, under contract with their hosts. Venice
	// documents 402 INSUFFICIENT_BALANCE and the two spend-limit codes for a dry account, and its chat path takes
	// apierr.SanitizedUpstreamError's default mapping of a 402 to upstream_unavailable. No dry account has answered a
	// request yet.
	ProviderVenice: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Venice keeps no prompt or reply only for the models it serves in its Private mode",
		zdrLink:           "https://docs.venice.ai/overview/privacy",
		zdrLinkChecked:    "2026-11-17",
		zdrHeld:           HeldPublishedTerms,
		needsKey:          true,
		refusesDryAccount: true,
		sendsSettings:     true,
	},
	// Isoquant answers 402 when the balance cannot cover a request's max_tokens (the scout's report of 2026-11-05, not a
	// captured reply), and its chat path takes apierr.SanitizedUpstreamError's default mapping of a 402 to
	// upstream_unavailable. A model the key may not use answers 403 model_forbidden (captured 2026-11-05), which apierr
	// maps to the same account refusal. No dry account has answered a request yet.
	ProviderIsoquant: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Isoquant keeps nothing only for a request that carries the Isoquant-ZDR header, and has no account setting for it",
		zdrLink:           "https://isoquant.ai/privacy",
		zdrLinkChecked:    "2026-11-17",
		zdrHeld:           HeldRequestHeader,
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// why: Phala's gateway routes a request only to hosts that keep no prompt or completion when its body carries
	// provider.zdr true, and fails it with 404 before the prompt is sent when none can. A dry account answered 402
	// insufficient_quota on 2026-11-04 (internal/phala/phalatest/testdata/dry-account-402.http).
	ProviderPhalaZDR: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Phala keeps nothing only of a request whose body carries provider.zdr true, which this provider sends on every request beside aci_verified true; it is a body field, not a header, and no account setting replaces it",
		zdrLink:           "https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/zero-data-retention",
		zdrLinkChecked:    "2026-11-21",
		zdrHeld:           HeldRequestHeader,
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// Wafer documents no status for a dry account; its chat path takes apierr.SanitizedUpstreamError's default mapping
	// of a 401 or 402 to upstream_unavailable. No dry account has answered a request yet. Wafer ignores the output
	// limit: on DeepSeek V4 Flash 0731 with a limit of 256 it sent 9,379 completion tokens for max_tokens and 1,448 for
	// max_completion_tokens, each with finish_reason stop (probes of 2026-11-10).
	ProviderWafer: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Wafer keeps nothing of a request that carries Wafer-ZDR: required, which this provider sends on every request whatever the account's default",
		zdrLink:           "https://docs.wafer.ai/serverless/zero-data-retention",
		zdrLinkChecked:    "2026-11-17",
		zdrHeld:           HeldRequestHeader,
		needsKey:          true,
		ignoresLimit:      true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// Novita has no per-request retention header, so a route stands on its Terms of Service, section 10.2, which give
	// zero data retention for every Novita model.
	// Novita documents 402 for an insufficient balance; its chat path takes apierr.SanitizedUpstreamError's default
	// mapping of a 401 or 402 to upstream_unavailable.
	ProviderNovita: {
		kinds:                servedAt{catalog.KindChat: anonAndPrivate},
		zdrAt:                privateOnly,
		zdrWhy:               "because Novita's Terms of Service, section 10.2 (https://novita.ai/legal/terms-of-service), keep nothing beyond generating and delivering the output and train on nothing, with carve-outs for law, support and automated safety screening, which is zero data retention per Novita's terms for every Novita model; no per-request header",
		zdrLink:              "https://novita.ai/legal/terms-of-service",
		zdrLinkChecked:       "2026-11-17",
		zdrHeld:              HeldPublishedTerms,
		needsKey:             true,
		answersFromReasoning: true,
		refusesDryAccount:    true,
		openAIHost:           true,
		switchesThinking:     true,
	},
	// Morph documents no zero retention header or setting, so a Morph route stands on Morph's zero data retention
	// terms for the account that owns the route's key. Morph documents no status for a dry account; its chat
	// path takes apierr.SanitizedUpstreamError's default mapping of a 401 or 402 to upstream_unavailable. No dry
	// account has answered a request yet.
	ProviderMorph: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Morph documents no zero retention header or setting, so a Morph route stands on Morph's zero data retention terms for the account that owns the route's key",
		zdrLink:           "https://www.morphllm.com/zdr",
		zdrLinkChecked:    "2026-11-17",
		zdrHeld:           HeldAccountAgreement,
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// why: Abliteration serves its own fine-tunes, so a route whose lab is Abliteration is on its maker's own API. It
	// answers a dry account with 402 (https://docs.abliteration.ai/api/errors.md).
	ProviderAbliteration: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Abliteration's data-handling page (https://abliteration.ai/data-handling) processes prompts and completions in memory, writes them to no disk or log, and marks every chat completion zero data retention, and its terms (https://abliteration.ai/terms-of-service) retain no input or output, which is zero data retention per Abliteration's terms; no per-request header",
		zdrLink:           "https://abliteration.ai/data-handling",
		zdrLinkChecked:    "2026-11-21",
		zdrHeld:           HeldPublishedTerms,
		makes:             map[string]string{"api.abliteration.ai": "Abliteration"},
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// why: Silk Compute names no legal entity in its terms (https://silkcompute.com/terms, read 2026-11-21), so its zero
	// retention rests on its privacy policy alone. It answers a dry account with 402 insufficient_credits
	// (https://silkcompute.com/docs/errors).
	ProviderSilk: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Silk Compute's privacy policy (https://silkcompute.com/privacy, updated 2026-11-14) stores no prompt and no model answer, and says the infrastructure providers it uses store none either, which is zero data retention per Silk Compute's terms; no per-request header",
		zdrLink:           "https://silkcompute.com/privacy",
		zdrLinkChecked:    "2026-11-21",
		zdrHeld:           HeldPublishedTerms,
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// why: Heabsy resells partner models through NanoGPT with no zero retention, so a route may name only a model its
	// catalog marks hosting heabsy (heabsyHostedModels in cmd/proxy). It documents no status for a dry account.
	ProviderHeabsy: {
		kinds:             servedAt{catalog.KindChat: privateOnly},
		zdrAt:             privateOnly,
		zdrWhy:            "because Heabsy's privacy policy (https://heabsy.com/privacy, effective 2026-10-26) writes no prompt or completion processed on Heabsy infrastructure to durable storage or logs and trains on nothing, which is zero data retention per Heabsy's terms only for the models it hosts itself; no per-request header",
		zdrLink:           "https://heabsy.com/privacy",
		zdrLinkChecked:    "2026-11-19",
		zdrHeld:           HeldPublishedTerms,
		needsKey:          true,
		refusesDryAccount: true,
		openAIHost:        true,
	},
	// DeepInfra has no per-request retention header, so a route stands on its published data policy alone, which gives
	// zero data retention per DeepInfra's terms. DeepInfra documents no status for a dry account; its chat path takes
	// apierr.SanitizedUpstreamError's default mapping of a 401 or 402 to upstream_unavailable. No dry account has
	// answered a request yet.
	ProviderDeepInfra: {
		kinds:                servedAt{catalog.KindChat: privateOnly, catalog.KindSpeech: privateOnly},
		zdrAt:                privateOnly,
		zdrWhy:               "because DeepInfra's published data policy (https://docs.deepinfra.com/account/data-privacy) keeps inputs in memory only, logs no content and trains on nothing, which is zero data retention per DeepInfra's terms, since DeepInfra offers no per-request header",
		zdrLink:              "https://docs.deepinfra.com/account/data-privacy",
		zdrLinkChecked:       "2026-11-17",
		zdrHeld:              HeldPublishedTerms,
		needsKey:             true,
		answersFromReasoning: true,
		refusesDryAccount:    true,
		openAIHost:           true,
	},
	ProviderRunware: {kinds: servedAt{catalog.KindImage: anonOnly, catalog.KindVideo: anonOnly}, needsKey: true},
	ProviderFal:     {kinds: servedAt{catalog.KindImage: anonOnly, catalog.KindVideo: anonOnly}, needsKey: true},
	// why: spicyapi.ai keeps prompts and outputs for a window and names no model host (spicyapi.ai/legal/privacy), and
	// answers a dry balance or spend cap 402 (40201, 40202), which maps to upstream_unavailable (docs.spicyapi.ai/docs/errors).
	ProviderSpicyAPI: {kinds: servedAt{catalog.KindImage: anonOnly, catalog.KindVideo: anonOnly}, needsKey: true, refusesDryAccount: true},
	// A private Parallel route stands on our zero data retention agreement with Parallel, which covers the account
	// that owns the route's key: it sends the same request as an anon route, and no reply is checked for it, unlike xAI's.
	ProviderParallel: {
		kinds:    servedAt{catalog.KindSearch: anonAndPrivate, catalog.KindFetch: anonAndPrivate, catalog.KindResearch: anonAndPrivate},
		zdrAt:    privateOnly,
		zdrWhy:   "because its self-serve terms keep queries and pages and allow training on them",
		zdrHeld:  HeldAccountAgreement,
		makes:    map[string]string{"api.parallel.ai": "Parallel"},
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
	// A zero-balance Phala account answered a plaintext chat 402 insufficient_quota on 2026-11-04, which
	// apierr.SanitizedUpstreamError maps to upstream_unavailable, and phala's refuseSealed maps the documented "Balance
	// is too low" 403 the same way. internal/phala/phalatest/testdata/dry-account-402.http replays the capture.
	return capability{kinds: kinds, refusesDryAccount: v == attester.Phala, sendsSettings: v == attester.Phala}
}

// RefusesDryAccount is whether rt's provider maps a dry account at the vendor to an account refusal.
func (rt Route) RefusesDryAccount() bool {
	switch up := rt.Upstream.(type) {
	case Attested:
		return attestedCapability(up.Attester).refusesDryAccount
	case Vendor:
		return capabilities[up.Provider].refusesDryAccount
	}
	return false
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

// OpenAIHost is whether p is one of the hosts openaihosts serves, whose provider makes a route's protocol fixes.
func (p Provider) OpenAIHost() bool { return capabilities[p].openAIHost }

// SwitchesThinking is whether p's host documents a request field that turns thinking off.
func (p Provider) SwitchesThinking() bool { return capabilities[p].switchesThinking }

func (p Provider) IgnoresOutputLimit() bool { return capabilities[p].ignoresLimit }

// RetentionTerms is the recorded basis on which p keeps nothing of a request at tier t, the reason a route there must
// set retention zdr, and false when this file records none for p at t.
func (p Provider) RetentionTerms(t catalog.Tier) (string, bool) {
	c := capabilities[p]
	if !slices.Contains(c.zdrAt, t) {
		return "", false
	}
	return c.zdrWhy, true
}

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

func (v Vendor) check(rt Route) error {
	if rt.OnBehalfOf != "" {
		return fmt.Errorf("is on behalf of endpoint %q and uses %s; only an attested endpoint is sealed to", rt.OnBehalfOf, v)
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
	if err := c.checkRouteFixes(up, rt, chat); err != nil {
		return err
	}
	if err := c.checkResponseFormats(up, rt, chat); err != nil {
		return err
	}
	return c.reasoningShown(up, chat)
}

func (c capability) checkResponseFormats(up Upstream, rt Route, chat Chat) error {
	switch {
	case chat.ResponseFormats == 0:
		return nil
	case rt.Tier.Sealed():
		return fmt.Errorf("sets response_formats at tier %s, whose body is forwarded verbatim, so the proxy neither reads nor sends its response_format", rt.Tier)
	case !c.openAIHost && !c.sendsSettings:
		return fmt.Errorf("sets response_formats, but %s does not send a key's response_format to its host", up)
	}
	return nil
}

func (c capability) checkRouteFixes(up Upstream, rt Route, chat Chat) error {
	var field string
	switch {
	case chat.ReasoningInContent:
		field = "reasoning_in_content"
	case chat.ToolCallsFinishStop:
		field = "tool_calls_finish_stop"
	case chat.NoTools:
		field = "tools false"
	case chat.ThinkingOffSwitch:
		field = "thinking_off_switch"
	default:
		return nil
	}
	switch {
	case !c.openAIHost:
		return fmt.Errorf("sets %s, which only the shared OpenAI-compatible host provider makes, and %s is not one", field, up)
	case chat.ThinkingOffSwitch && !c.switchesThinking:
		return fmt.Errorf("sets thinking_off_switch, but %s documents no request field that turns thinking off", up)
	case chat.NoTools && rt.Tier.Sealed():
		return fmt.Errorf("sets tools false at tier %s, whose body is forwarded verbatim, so the proxy cannot drop its tools", rt.Tier)
	}
	return nil
}

func (c capability) reasoningShown(up Upstream, chat Chat) error {
	switch {
	case c.hides && chat.reasons() && !chat.ReasoningView.Hides():
		return fmt.Errorf("uses %s, which keeps a model's reasoning from the client, and must set hides_reasoning", up)
	case (!c.hides || !chat.reasons()) && chat.ReasoningView.Hides():
		return fmt.Errorf("sets hides_reasoning, but %s streams whatever reasoning the model does", up)
	case chat.ReasoningView.Summarizes() && !c.summarizes:
		return fmt.Errorf("sets summarizes_reasoning, but the proxy asks %s for no summary of the reasoning it hides", up)
	case chat.AnswersInReasoning && !c.answersFromReasoning:
		return fmt.Errorf("sets answers_in_reasoning, but %s would show a reply that is all reasoning as an empty answer", up)
	}
	return chat.thinkingTerms()
}

func (c Chat) thinkingTerms() error {
	switch {
	case !c.ReasoningView.Hides() && c.HiddenReasoningTPS != 0:
		return fmt.Errorf("sets hidden_reasoning_tps without hides_reasoning")
	case !c.ReasoningView.Hides() && c.DecodeMaxTPS != 0:
		return fmt.Errorf("sets decode_max_tps, which only a route that sets hides_reasoning takes")
	case !c.ReasoningView.Hides():
		return nil
	case c.HiddenReasoningTPS <= 0 || c.DecodeMaxTPS <= 0:
		return fmt.Errorf("sets hides_reasoning and needs a positive hidden_reasoning_tps and decode_max_tps, both measured")
	case c.HiddenReasoningTPS > c.DecodeMaxTPS:
		return fmt.Errorf("sets hidden_reasoning_tps %d above its decode_max_tps %d", c.HiddenReasoningTPS, c.DecodeMaxTPS)
	}
	return nil
}

func (a Attested) check(rt Route) error {
	if rt.OnBehalfOf != "" {
		return a.checkOnBehalf(rt)
	}
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

// checkOnBehalf holds an on-behalf route to what the worker can do for it: a plaintext chat at tee, sealed to a vendor
// that seals each message and not the whole body.
func (a Attested) checkOnBehalf(rt Route) error {
	c, chats := ChatOf(rt.Serves)
	switch {
	case !chats:
		return fmt.Errorf("is on behalf of endpoint %q and serves %s; only a chat is sealed on its client's behalf", rt.OnBehalfOf, rt.Serves.Kind())
	case rt.Tier != catalog.OnBehalfTier:
		return fmt.Errorf("is on behalf of endpoint %q at tier %s, and a chat sealed on its client's behalf is tier %s", rt.OnBehalfOf, rt.Tier, catalog.OnBehalfTier)
	case a.Attester.SealsBody():
		return fmt.Errorf("is on behalf of endpoint %q, whose attester %s seals a request whole, so it has no seal for a plaintext chat", rt.OnBehalfOf, a)
	case c.Tokenizer != "":
		return fmt.Errorf("names a tokenizer, but %s relays its stream verbatim and the proxy counts only what it parses", a)
	}
	return attestedCapability(a.Attester).reasoningShown(a, c)
}

func (c capability) checkEfforts(up Upstream, ch Chat) error {
	for _, effort := range ch.ReasoningEfforts {
		if slices.Contains(c.lacks, effort) {
			return fmt.Errorf("uses %s, whose API has no effort %q", up, effort)
		}
	}
	return nil
}
