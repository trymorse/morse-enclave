// Package deepinfra sends chat to DeepInfra's OpenAI-compatible API.
//
// DeepInfra offers no per-request retention header. Its published data policy (https://docs.deepinfra.com/account/data-privacy,
// read 2026-11-05) says inputs live only in memory and are never stored to disk, outputs are deleted once sent, request
// content is not logged, and nothing submitted is used for training or shared, except for Google and Anthropic models
// and bulk inference, which no route here uses. Daniel accepted that policy as zero data retention on 2026-11-05
// without a written agreement, so a private route on this host stands on the policy alone.
package deepinfra

import (
	"net/http"

	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

func NewChat(baseURL, apiKey, model string, answersInReasoning bool, client *http.Client) *openaicompat.Provider {
	return &openaicompat.Provider{
		Sender:             openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}},
		Model:              model,
		LimitField:         openaicompat.MaxTokens,
		AnswersInReasoning: answersInReasoning,
		OneThingPerChunk:   true,
	}
}
