package openaicompat

import (
	"encoding/json"

	"morse/backend/internal/jsonx"
)

type clientUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	PromptDetails    struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

// uniformUsage is the usage a client sees, the same fields in the same order whichever host sent it, or nil when the
// reply carries none. Hosts add fields of their own (audio_tokens, a cache write count) and
// differ in their order, which would tell a client which host served. What the proxy bills is read from the host's
// usage before this runs.
func (r *reply) uniformUsage() json.RawMessage {
	if raw, ok := r.value("usage"); !ok || isNull(raw) || r.usage == nil {
		return nil
	}
	u := r.usage.Domain()
	out := clientUsage{PromptTokens: r.usage.PromptTokens, CompletionTokens: r.usage.CompletionTokens, TotalTokens: r.usage.TotalTokens}
	if out.TotalTokens == 0 {
		out.TotalTokens = out.PromptTokens + out.CompletionTokens
	}
	out.PromptDetails.CachedTokens = u.CachedPromptTokens
	out.CompletionDetails.ReasoningTokens = u.ReasoningTokens
	return jsonx.Encode(out)
}
