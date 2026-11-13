package openaihosts

import (
	"net/http"

	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const ZDRValue = "required"

type Host struct {
	Name          string
	ZDRHeader     string
	admit         func(chat.Call) error
	limitField    openaicompat.LimitField
	thinkingField string
}

var (
	Wafer     = Host{Name: "wafer", ZDRHeader: "Wafer-ZDR", limitField: openaicompat.MaxTokens}
	Isoquant  = Host{Name: "isoquant", ZDRHeader: "Isoquant-ZDR", admit: openaicompat.FunctionToolsTextAndImages, limitField: openaicompat.MaxTokens}
	Novita    = Host{Name: "novita", thinkingField: "enable_thinking"}
	Morph     = Host{Name: "morph", limitField: openaicompat.MaxTokens}
	DeepInfra = Host{Name: "deepinfra", limitField: openaicompat.MaxTokens}
)

func Hosts() []Host { return []Host{Wafer, Isoquant, Novita, Morph, DeepInfra} }

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
		Sender:        openaicompat.HTTPSender{Endpoint: h.Endpoint(baseURL, key, client)},
		Model:         model,
		LimitField:    h.limitField,
		Admit:         h.admit,
		Fixes:         fixes,
		ThinkingField: h.thinkingField,
	}
}
