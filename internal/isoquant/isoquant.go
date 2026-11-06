// Package isoquant sends chat to Isoquant's OpenAI-compatible API.
//
// Isoquant has no account setting for zero data retention. A request keeps nothing only when it carries
// Isoquant-ZDR: required, so that header is the one control standing between a prompt and Isoquant's logs. It rides
// in the endpoint's credentials, which upstream.Endpoint copies onto every request it sends after the request's own
// headers, so a stream, a whole reply, a retry, a failover into this host and a probe of an open circuit all carry it
// and no caller or route can drop or replace it.
package isoquant

import (
	"net/http"

	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	ZDRHeader = "Isoquant-ZDR"
	ZDRValue  = "required"
)

func NewChat(baseURL, apiKey, model string, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:     openaicompat.HTTPSender{Endpoint: Endpoint(baseURL, apiKey, client)},
		Model:      model,
		LimitField: openaicompat.MaxTokens,
		Admit:      openaicompat.FunctionToolsTextAndImages,
	}
}

// Endpoint is the only way this package reaches Isoquant.
func Endpoint(baseURL, apiKey string, client *http.Client) upstream.Endpoint {
	auth := upstream.Bearer(apiKey)
	if auth == nil {
		auth = http.Header{}
	}
	auth.Set(ZDRHeader, ZDRValue)
	return upstream.Endpoint{BaseURL: baseURL, Auth: auth, HTTP: client}
}
