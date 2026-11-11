// Package openaihosts sends chat to the OpenAI-compatible hosts that differ from one another only in a Host: the header
// without which a host may keep a request, and which calls it admits. A new such host is one Host in Hosts.
package openaihosts

import (
	"net/http"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const ZDRValue = "required"

// A Host is one OpenAI-compatible host. The zero Host sends the key alone, caps a reply with max_completion_tokens and
// admits every call.
type Host struct {
	// Name is the host's provider in the routes file.
	Name string
	// ZDRHeader is the header every request to the host carries as ZDRValue, or "" for a host that needs none.
	ZDRHeader      string
	admit          func(chat.Call) error
	limitField     openaicompat.LimitField
	thinkingSwitch string
}

// Route is how one route on a host departs from the OpenAI protocol, each a field the route sets in routes.json.
type Route struct {
	// AnswersInReasoning shows a reply that is all reasoning as its answer too (answers_in_reasoning).
	AnswersInReasoning bool
	// ReasoningInContent moves reasoning the host writes into content, ended by </think>, out of it
	// (reasoning_in_content).
	ReasoningInContent bool
	// ThinkingOff sends the host's thinking switch as false on a call that asks for no reasoning (thinking_off_switch).
	ThinkingOff bool
	// ToolCallsFinishStop reports a reply that called a tool and finished stop as tool_calls (tool_calls_finish_stop).
	ToolCallsFinishStop bool
	// NoTools sends no tools (tools false).
	NoTools bool
}

var (
	// Wafer documents every Serverless request as zero data retention by default
	// (https://docs.wafer.ai/serverless/zero-data-retention.md) and accepts Wafer-ZDR: required, refusing any other
	// value. The proxy sends that header anyway, so zero retention never rests on the account's plan or a default that
	// could change.
	Wafer = Host{Name: "wafer", ZDRHeader: "Wafer-ZDR", limitField: openaicompat.MaxTokens}
	// Isoquant has no account setting for zero data retention. A request keeps nothing only when it carries
	// Isoquant-ZDR: required, so that header is the one control standing between a prompt and Isoquant's logs.
	Isoquant = Host{Name: "isoquant", ZDRHeader: "Isoquant-ZDR", admit: openaicompat.FunctionToolsTextAndImages, limitField: openaicompat.MaxTokens}
	// Novita offers no per-request retention header. Its Terms of Service (https://novita.ai/legal/terms-of-service,
	// section 10.2, Zero Data Retention) say it keeps nothing of a request beyond generating and delivering the output
	// and trains on nothing, with carve-outs for law, support and automated safety screening. That is zero data
	// retention per Novita's terms, so a private route on this host stands on the terms alone.
	// Novita ignores max_tokens and runs a reply past the hold the proxy reserved, but stops at max_completion_tokens,
	// counting reasoning against it.
	// Novita documents enable_thinking, default true, which turns thinking off for a hybrid reasoning model when false
	// (https://docs.novita.ai/api-reference/model-apis-llm-create-chat-completion, read 2026-11-11). It documents no
	// reasoning_effort.
	Novita = Host{Name: "novita", thinkingSwitch: "enable_thinking"}
	// Morph documents no per-request zero data retention header and no account setting for it. Zero retention rests on
	// Morph's zero data retention terms for the account that holds the key. So the key sent here must be that
	// account's, and Morph's other models and products stay out of the private tier.
	Morph = Host{Name: "morph", limitField: openaicompat.MaxTokens}
	// DeepInfra offers no per-request retention header. Its published data policy
	// (https://docs.deepinfra.com/account/data-privacy, read 2026-11-05) says inputs live only in memory and are never
	// stored to disk, outputs are deleted once sent, request content is not logged, and nothing submitted is used for
	// training or shared, except for Google and Anthropic models and bulk inference, which no route here uses. That is
	// zero data retention per DeepInfra's terms, so a private route on this host stands on the policy alone.
	DeepInfra = Host{Name: "deepinfra", limitField: openaicompat.MaxTokens}
)

func Hosts() []Host { return []Host{Wafer, Isoquant, Novita, Morph, DeepInfra} }

// Endpoint is the only way to reach h at baseURL with key.
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

// SwitchesThinking is whether h documents a request field that turns thinking off.
func (h Host) SwitchesThinking() bool { return h.thinkingSwitch != "" }

func (h Host) NewChat(baseURL, key, model string, r Route, client *http.Client) *openaicompat.Provider {
	p := &openaicompat.Provider{
		Sender:              openaicompat.HTTPSender{Endpoint: h.Endpoint(baseURL, key, client)},
		Model:               model,
		LimitField:          h.limitField,
		Admit:               h.admit,
		AnswersInReasoning:  r.AnswersInReasoning,
		ReasoningInContent:  r.ReasoningInContent,
		ToolCallsFinishStop: r.ToolCallsFinishStop,
		NoTools:             r.NoTools,
	}
	if r.ThinkingOff {
		p.ThinkingSwitch = h.thinkingSwitch
	}
	return p
}
