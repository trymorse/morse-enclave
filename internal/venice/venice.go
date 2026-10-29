// Package venice serves chat and images on Venice, whose Private chat models keep no prompt or reply.
package venice

import (
	"encoding/json"
	"net/http"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

// Parameters ride every request. Venice adds its own system prompt unless told not to, and runs web search,
// page scraping and X search on other services, so all of them are off, and a client cannot turn them on:
// the proxy forwards no venice_parameters of its own, and refuses the web_search and x_search tools.
var Parameters = json.RawMessage(`{"include_venice_system_prompt":false,"enable_web_search":"off","enable_web_scraping":false,"enable_x_search":false}`)

type Chat struct{ openaicompat.Provider }

var _ chat.Provider = (*Chat)(nil)

func NewChat(baseURL, apiKey, model string, client *http.Client) *Chat {
	vendor := upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}
	return &Chat{openaicompat.Provider{
		Sender:     openaicompat.HTTPSender{Endpoint: vendor},
		Model:      model,
		Force:      map[string]json.RawMessage{"venice_parameters": Parameters},
		LimitField: openaicompat.MaxCompletionTokens,
		// Venice runs a web_search tool as its web search and an x_search tool as xAI's, and turns files and audio
		// into text on its own services.
		Admit:        openaicompat.FunctionToolsTextAndImages,
		ChargeFields: []string{"cost"},
	}}
}
