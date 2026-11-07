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

// A Host is one OpenAI-compatible host. The zero Host sends the key alone and admits every call.
type Host struct {
	// Name is the host's provider in the routes file.
	Name string
	// ZDRHeader is the header every request to the host carries as ZDRValue, or "" for a host that needs none.
	ZDRHeader string
	admit     func(chat.Call) error
}

var (
	// Wafer documents every Serverless request as zero data retention by default
	// (https://docs.wafer.ai/serverless/zero-data-retention.md) and accepts Wafer-ZDR: required, refusing any other
	// value. The proxy sends that header anyway, so zero retention never rests on the account's plan or a default that
	// could change.
	Wafer = Host{Name: "wafer", ZDRHeader: "Wafer-ZDR"}
	// Isoquant has no account setting for zero data retention. A request keeps nothing only when it carries
	// Isoquant-ZDR: required, so that header is the one control standing between a prompt and Isoquant's logs.
	Isoquant = Host{Name: "isoquant", ZDRHeader: "Isoquant-ZDR", admit: openaicompat.FunctionToolsTextAndImages}
	// Novita offers no per-request retention header. Its Terms of Service (https://novita.ai/legal/terms-of-service,
	// section 10.2, Zero Data Retention) say it keeps nothing of a request beyond generating and delivering the output
	// and trains on nothing, with carve-outs for law, support and automated safety screening. Daniel accepted that as
	// zero data retention for Ling 3.0 Flash on 2026-11-05, so a private route on this host stands on the terms alone.
	Novita = Host{Name: "novita"}
	// Morph documents no per-request zero data retention header and no account setting for it. Zero retention rests on
	// the ZDR addendum Morph signed with us, which Daniel confirmed with Morph on 2026-11-05 covers our account. So the
	// key sent here must be the account the addendum covers, and Morph's other models and products stay out of the
	// private tier.
	Morph = Host{Name: "morph"}
	// DeepInfra offers no per-request retention header. Its published data policy
	// (https://docs.deepinfra.com/account/data-privacy, read 2026-11-05) says inputs live only in memory and are never
	// stored to disk, outputs are deleted once sent, request content is not logged, and nothing submitted is used for
	// training or shared, except for Google and Anthropic models and bulk inference, which no route here uses. Daniel
	// accepted that policy as zero data retention on 2026-11-05 without a written agreement, so a private route on this
	// host stands on the policy alone.
	DeepInfra = Host{Name: "deepinfra"}
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

func (h Host) NewChat(baseURL, key, model string, answersInReasoning bool, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:             openaicompat.HTTPSender{Endpoint: h.Endpoint(baseURL, key, client)},
		Model:              model,
		LimitField:         openaicompat.MaxTokens,
		Admit:              h.admit,
		AnswersInReasoning: answersInReasoning,
	}
}
