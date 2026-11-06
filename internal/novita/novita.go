// Package novita sends chat to Novita's OpenAI-compatible API.
//
// Novita offers no per-request retention header. Its Terms of Service (https://novita.ai/legal/terms-of-service, section
// 10.2, Zero Data Retention) say it keeps nothing of a request beyond generating and delivering the output and trains on
// nothing, with carve-outs for law, support and automated safety screening. Daniel accepted that as zero data retention
// for Ling 3.0 Flash on 2026-11-05, so a private route on this host stands on the terms alone.
package novita

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
	}
}
