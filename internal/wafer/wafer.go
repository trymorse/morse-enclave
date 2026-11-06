// Package wafer sends chat to Wafer's OpenAI-compatible API.
//
// Wafer documents every Serverless request as zero data retention by default
// (https://docs.wafer.ai/serverless/zero-data-retention.md) and accepts Wafer-ZDR: required, refusing any other value.
// The proxy sends that header anyway, so zero retention never rests on the account's plan or a default that could
// change. The header rides in the endpoint's credentials, which upstream.Endpoint copies onto every request
// it sends after the request's own headers, so a stream, a whole reply, a retry, a hedge, a failover into this host and
// a probe of an open circuit all carry it and no caller or route can drop or replace it.
package wafer

import (
	"net/http"

	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	ZDRHeader = "Wafer-ZDR"
	ZDRValue  = "required"
)

func NewChat(baseURL, apiKey, model string, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:     openaicompat.HTTPSender{Endpoint: Endpoint(baseURL, apiKey, client)},
		Model:      model,
		LimitField: openaicompat.MaxTokens,
	}
}

// Endpoint is the only way this package reaches Wafer.
func Endpoint(baseURL, apiKey string, client *http.Client) upstream.Endpoint {
	auth := upstream.Bearer(apiKey)
	if auth == nil {
		auth = http.Header{}
	}
	auth.Set(ZDRHeader, ZDRValue)
	return upstream.Endpoint{BaseURL: baseURL, Auth: auth, HTTP: client}
}
