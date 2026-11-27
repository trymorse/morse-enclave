package openaihosts

import (
	"encoding/json"
	"maps"
	"net/http"

	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/phala"
	"morse/backend/internal/upstream"
)

const ZDRValue = "required"

type Host struct {
	Name           string
	ZDRHeader      string
	admit          func(chat.Call) error
	limitField     openaicompat.LimitField
	thinkingField  string
	sendsCacheKey  bool
	cacheKeyHeader string
	force          map[string]json.RawMessage
	usageEachChunk bool
	reasoningKeys  []string
}

// why: each host's chat template reads an assistant message's earlier reasoning from reasoning_content, and Wafer's
// Kimi K3 only from reasoning (replay probes of 2026-11-24, 29 host and model pairs, no host refused either key).
var (
	replaysReasoningContent = []string{"reasoning_content"}
	replaysBothKeys         = []string{"reasoning_content", "reasoning"}
)

var (
	Wafer    = Host{Name: "wafer", ZDRHeader: "Wafer-ZDR", limitField: openaicompat.MaxTokens, reasoningKeys: replaysBothKeys}
	Isoquant = Host{Name: "isoquant", ZDRHeader: "Isoquant-ZDR", admit: openaicompat.FunctionToolsTextAndImages, limitField: openaicompat.MaxTokens, reasoningKeys: replaysReasoningContent}
	Novita   = Host{Name: "novita", thinkingField: "enable_thinking", reasoningKeys: replaysReasoningContent}
	// why: Morph documents that x-session-id "reaches both region and worker placement", where prompt_cache_key
	// "steers region placement only" (https://docs.morphllm.com/sdk/components/caching.md).
	Morph = Host{Name: "morph", limitField: openaicompat.MaxTokens, cacheKeyHeader: "X-Session-Id", reasoningKeys: replaysReasoningContent}
	// why: DeepInfra documents that requests with the same prompt_cache_key and model share a KV cache
	// (https://docs.deepinfra.com/chat/prompt-caching.md). Wafer, Isoquant and Novita document no cache key.
	DeepInfra = Host{Name: "deepinfra", limitField: openaicompat.MaxTokens, sendsCacheKey: true, reasoningKeys: replaysReasoningContent}
	// why: Phala's zero data retention is a field of the request body, so it is forced on every request as the
	// attested Phala route forces it (internal/phala), with the usage on each chunk that route asks for.
	PhalaZDR = Host{Name: "phala-zdr", limitField: openaicompat.MaxTokens, force: map[string]json.RawMessage{"provider": json.RawMessage(phala.Constraint)}, usageEachChunk: true, reasoningKeys: replaysReasoningContent}
	Heabsy   = Host{Name: "heabsy", limitField: openaicompat.MaxTokens, reasoningKeys: replaysReasoningContent}
	Silk     = Host{Name: "silk", limitField: openaicompat.MaxTokens, reasoningKeys: replaysReasoningContent}
	// why: Abliteration documents prompt_cache_key as the routing hint that keeps a conversation's requests on a warm
	// cache (https://docs.abliteration.ai/capabilities/prompt-caching.md).
	Abliteration = Host{Name: "abliteration", limitField: openaicompat.MaxTokens, sendsCacheKey: true, reasoningKeys: replaysReasoningContent}
)

func Hosts() []Host {
	return []Host{Wafer, Isoquant, Novita, Morph, DeepInfra, PhalaZDR, Heabsy, Silk, Abliteration}
}

func (h Host) Endpoint(baseURL, key string, client *http.Client) upstream.Endpoint {
	auth := upstream.Bearer(key)
	if h.ZDRHeader != "" {
		if auth == nil {
			auth = http.Header{}
		}
		auth.Set(h.ZDRHeader, ZDRValue)
	}
	return upstream.Endpoint{BaseURL: baseURL, Auth: auth, HTTP: client}
}

func (h Host) SwitchesThinking() bool { return h.thinkingField != "" }

func (h Host) NewChat(baseURL, key, model string, fixes catalog.Fixes, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:          openaicompat.HTTPSender{Endpoint: h.Endpoint(baseURL, key, client)},
		Model:           model,
		Force:           maps.Clone(h.force),
		ContinuousUsage: h.usageEachChunk,
		LimitField:      h.limitField,
		Admit:           h.admit,
		Fixes:           fixes,
		ThinkingField:   h.thinkingField,
		ReasoningKeys:   h.reasoningKeys,
		SendsCacheKey:   h.sendsCacheKey,
		CacheKeyHeader:  h.cacheKeyHeader,
	}
}
