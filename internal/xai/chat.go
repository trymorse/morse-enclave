package xai

import (
	"encoding/json"
	"net/http"
	"strconv"

	"morse/backend/internal/catalog"
	"morse/backend/internal/completions"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/openaicompat"
)

func NewChat(baseURL, apiKey, model string, retention catalog.Retention, client *http.Client) *openaicompat.Provider {
	vendor := endpoint(baseURL, apiKey, client, Confirmation(retention))
	return &openaicompat.Provider{Sender: openaicompat.HTTPSender{Endpoint: vendor}, Model: model, LimitField: openaicompat.MaxCompletionTokens, ChargeFields: []string{"cost_in_usd_ticks"}, Bill: reasoningAsCompletion}
}

// xAI reports reasoning tokens outside completion_tokens and bills them at the completion rate, so its
// usage is rewritten into OpenAI's shape before the adapter reads it. The client then reads the
// completion it is charged for.
func reasoningAsCompletion(usage json.RawMessage) (json.RawMessage, error) {
	var raw map[string]json.RawMessage
	var u completions.Usage
	if err := json.Unmarshal(usage, &raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(usage, &u); err != nil {
		return nil, err
	}
	completion := u.CompletionTokens + u.Domain().ReasoningTokens
	raw["completion_tokens"] = json.RawMessage(strconv.Itoa(completion))
	raw["total_tokens"] = json.RawMessage(strconv.Itoa(u.PromptTokens + completion))
	return jsonx.Encode(raw), nil
}
