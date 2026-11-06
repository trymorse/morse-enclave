// Package morph sends chat to Morph's OpenAI-compatible API.
//
// Morph documents no per-request zero data retention header and no account setting for it. Zero retention rests on
// the ZDR addendum Morph signed with us, which Daniel confirmed with Morph on 2026-11-05 covers our account. So the
// key this package sends must be the account the addendum covers, and Morph's other models and products stay out of
// the private tier.
package morph

import (
	"net/http"

	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

func NewChat(baseURL, apiKey, model string, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:     openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}},
		Model:      model,
		LimitField: openaicompat.MaxTokens,
	}
}
