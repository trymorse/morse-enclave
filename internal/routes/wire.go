package routes

import (
	"encoding/json"
	"errors"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
)

type common struct {
	Model         string       `json:"model"`
	Tier          string       `json:"tier"`
	Attester      string       `json:"attester"`
	BaseURL       string       `json:"base_url"`
	UpstreamModel string       `json:"upstream_model"`
	APIKeyEnv     string       `json:"api_key_env"`
	Provider      string       `json:"provider"`
	ProviderName  string       `json:"provider_name"`
	Label         string       `json:"label"`
	OwnedBy       string       `json:"owned_by"`
	Lab           string       `json:"lab"`
	OpenWeights   bool         `json:"open_weights"`
	Retention     string       `json:"retention"`
	Kind          catalog.Kind `json:"kind"`
	Included      *Included    `json:"included"`
	RequiresPlan  string       `json:"requires_plan"`
	AppOnly       bool         `json:"app_only"`
	RebateShare   *int64       `json:"rebate_share_bps"`
	// OnBehalfOf is set by Flatten on an on-behalf endpoint's route, which it builds from the sealed endpoint it names.
	OnBehalfOf catalog.EndpointID `json:"on_behalf_of"`
}

type marked struct {
	Markup json.RawMessage `json:"markup"`
}

func (m marked) markup(defaultMarkup money.Markup) (money.Markup, error) {
	if m.Markup == nil {
		return defaultMarkup, nil
	}
	k, err := money.ParseMarkup(string(m.Markup))
	if err != nil {
		return 0, errors.New("markup must be a number from 1 to 10 with at most four decimal places")
	}
	return k, nil
}

type chatRoute struct {
	common
	marked
	Price                  *tokenPrice `json:"price"`
	MaxOutputTokens        int         `json:"max_output_tokens"`
	DefaultMaxTokens       int         `json:"default_max_tokens"`
	DefaultReasoningEffort string      `json:"default_reasoning_effort"`
	ReasoningEfforts       []string    `json:"reasoning_efforts"`
	InputModalities        []string    `json:"input_modalities"`
	ContextTokens          int         `json:"context_tokens"`
	CompactAtTokens        int         `json:"compact_at_tokens"`
	Tokenizer              string      `json:"tokenizer"`
	OpenRouterID           string      `json:"openrouter_id"`
	HidesReasoning         bool        `json:"hides_reasoning"`
	AnswersInReasoning     bool        `json:"answers_in_reasoning"`
	ReasoningInContent     bool        `json:"reasoning_in_content"`
	ThinkingOffSwitch      bool        `json:"thinking_off_switch"`
	ToolCallsFinishStop    bool        `json:"tool_calls_finish_stop"`
	Tools                  *bool       `json:"tools"`
	HiddenReasoningTPS     int         `json:"hidden_reasoning_tps"`
	DecodeMaxTPS           int         `json:"decode_max_tps"`
}

type imageRoute struct {
	common
	marked
	Price *imagePrice `json:"price"`
}

type videoRoute struct {
	common
	marked
	Price *videoPrice `json:"price"`
}

type callRoute struct {
	common
	Price *callPrice `json:"price"`
}

type tokenPrice struct {
	PromptMicrosPerMTok           *money.Micros `json:"prompt_micros_per_mtok"`
	CachedPromptMicrosPerMTok     *money.Micros `json:"cached_prompt_micros_per_mtok"`
	CacheWritePromptMicrosPerMTok *money.Micros `json:"cache_write_prompt_micros_per_mtok"`
	CompletionMicrosPerMTok       *money.Micros `json:"completion_micros_per_mtok"`
	FromPromptTokens              int           `json:"from_prompt_tokens"`
	LongContext                   *tokenPrice   `json:"long_context"`
}

type imagePrice struct {
	HoldMicrosPerImage     *money.Micros `json:"hold_micros_per_image"`
	HoldMicrosPerReference *money.Micros `json:"hold_micros_per_reference"`
}

type videoPrice struct {
	HoldMicrosPerSecond *money.Micros `json:"hold_micros_per_second"`
}

type callPrice struct {
	MicrosPerCall *money.Micros `json:"micros_per_call"`
}

type Included struct {
	From       string `json:"from"`
	Quota      string `json:"quota"`
	Characters bool   `json:"characters"`
}
