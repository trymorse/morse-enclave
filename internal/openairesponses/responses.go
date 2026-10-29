package openairesponses

import (
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/upstream"
)

const (
	responsesPath             = "/v1/responses"
	incompleteOnContentFilter = "content_filter"
	itemFunctionCall          = "function_call"
	invalidRequestType        = "invalid_request_error"
)

func New(baseURL, apiKey, model string, client *http.Client) *completions.Provider {
	return &completions.Provider{
		Endpoint:   upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client},
		Translator: translator{model: model},
	}
}

type translator struct {
	model string
}

func (t translator) Request(conv completions.Conversation) (string, string, any) {
	return responsesPath, "text/event-stream", newRequest(conv, t.model)
}

func (translator) Events(w *completions.Writer) func([]byte) (bool, error) {
	return (&translation{w: w}).events().ByType
}

type translation struct {
	w       *completions.Writer
	refused bool
}

type outputItem struct {
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type usageWire struct {
	InputTokens        int `json:"input_tokens"`
	InputTokensDetails struct {
		CachedTokens     int `json:"cached_tokens"`
		CacheWriteTokens int `json:"cache_write_tokens"`
	} `json:"input_tokens_details"`
	OutputTokens        int `json:"output_tokens"`
	OutputTokensDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func (u *usageWire) usage() chat.Usage {
	if u == nil {
		return chat.Usage{}
	}
	return chat.Usage{
		PromptTokens:           u.InputTokens,
		CompletionTokens:       u.OutputTokens,
		CachedPromptTokens:     u.InputTokensDetails.CachedTokens,
		CacheWritePromptTokens: u.InputTokensDetails.CacheWriteTokens,
		ReasoningTokens:        u.OutputTokensDetails.ReasoningTokens,
	}
}

type vendorError struct {
	Code string `json:"code"`
	Type string `json:"type"`
}

type incompleteDetails struct {
	Reason string `json:"reason"`
}

type itemEvent struct {
	OutputIndex int        `json:"output_index"`
	Item        outputItem `json:"item"`
}

type deltaEvent struct {
	OutputIndex int    `json:"output_index"`
	Delta       string `json:"delta"`
}

type responseEvent struct {
	Response struct {
		IncompleteDetails *incompleteDetails `json:"incomplete_details"`
		Error             *vendorError       `json:"error"`
		Usage             *usageWire         `json:"usage"`
	} `json:"response"`
}

type errorEvent struct {
	Code  *string      `json:"code"`
	Error *vendorError `json:"error"`
}

func (s *translation) events() completions.Events {
	ended := func(completed bool) func([]byte) (bool, error) {
		return completions.On(func(e responseEvent) (bool, error) {
			s.w.Count(e.Response.Usage.usage(), true)
			return true, s.finish(completed, e.Response.IncompleteDetails)
		})
	}
	return completions.Events{
		"response.output_item.added": completions.On(func(e itemEvent) (bool, error) {
			if e.Item.Type != itemFunctionCall {
				return false, s.w.Start()
			}
			return false, s.w.ToolStart(e.OutputIndex, e.Item.CallID, e.Item.Name)
		}),
		"response.output_text.delta": completions.On(func(e deltaEvent) (bool, error) { return false, s.w.Text(e.Delta) }),
		"response.refusal.delta": completions.On(func(e deltaEvent) (bool, error) {
			s.refused = true
			return false, s.w.Refusal(e.Delta)
		}),
		"response.function_call_arguments.delta": completions.On(func(e deltaEvent) (bool, error) {
			return false, s.w.ToolArguments(e.OutputIndex, e.Delta)
		}),
		"response.output_item.done": completions.On(func(e itemEvent) (bool, error) {
			if e.Item.Type != itemFunctionCall {
				return false, nil
			}
			return false, s.w.ToolEnd(e.OutputIndex, e.Item.Arguments)
		}),
		"response.completed":  ended(true),
		"response.incomplete": ended(false),
		"response.failed": completions.On(func(e responseEvent) (bool, error) {
			s.w.Count(e.Response.Usage.usage(), true)
			return true, s.failure(e.Response.Error, nil)
		}),
		"error": completions.On(func(e errorEvent) (bool, error) { return true, s.failure(e.Error, e.Code) }),
	}
}

func (s *translation) finish(completed bool, incomplete *incompleteDetails) error {
	reason := completions.FinishLength
	switch {
	case s.refused || incomplete != nil && incomplete.Reason == incompleteOnContentFilter:
		reason = completions.FinishContentFilter
	case completed && s.w.Calls() > 0:
		reason = completions.FinishToolCalls
	case completed:
		reason = completions.FinishStop
	}
	return s.w.Finish(reason)
}

func (s *translation) failure(vendor *vendorError, code *string) error {
	var e vendorError
	if vendor != nil {
		e = *vendor
	}
	if e.Code == "" && code != nil {
		e.Code = *code
	}
	if e.Type == invalidRequestType {
		return s.w.Fail(e.Code, apierr.ErrInvalidRequest)
	}
	return s.w.Fail(e.Code, apierr.ErrUpstream)
}
