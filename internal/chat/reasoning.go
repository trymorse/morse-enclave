package chat

import (
	"encoding/json"
	"slices"

	"morse/backend/internal/strictjson"
)

var (
	errInvalidReasoning = strictjson.Invalid("reasoning must be an object whose effort is one of none, minimal, low, medium, high, xhigh, and max, whose max_tokens is a positive integer, and whose enabled and exclude are true or false.")
	errReasoningTwice   = strictjson.Invalid("reasoning names an effort and a max_tokens, or an effort other than reasoning_effort's. Send one of them.")
)

// why: reasoning is OpenRouter's request object for what OpenAI's Chat Completions calls reasoning_effort: effort,
// or max_tokens as a thinking budget, or enabled, and exclude to leave the reasoning out of the reply
// (https://openrouter.ai/docs/guides/best-practices/reasoning-tokens).
type reasoningAsk struct {
	Effort    *string `json:"effort"`
	MaxTokens *int    `json:"max_tokens"`
	Enabled   *bool   `json:"enabled"`
	Exclude   *bool   `json:"exclude"`
}

const enabledEffort = "medium"

func (a reasoningAsk) effort() (string, error) {
	switch {
	case a.Effort != nil && a.MaxTokens != nil:
		return "", errReasoningTwice
	case a.Effort != nil && !slices.Contains(EffortLadder, *a.Effort), a.MaxTokens != nil && *a.MaxTokens <= 0:
		return "", errInvalidReasoning
	case a.Enabled != nil && !*a.Enabled:
		return NoEffort, nil
	case a.Effort != nil:
		return *a.Effort, nil
	case a.MaxTokens != nil:
		return EffortOfBudget(*a.MaxTokens), nil
	case a.Enabled != nil:
		return enabledEffort, nil
	}
	return "", nil
}

func (r *Request) readReasoning() error {
	raw, ok := r.fields["reasoning"]
	if !ok || string(raw) == "null" {
		return nil
	}
	var ask reasoningAsk
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &ask) != nil {
		return errInvalidReasoning
	}
	effort, err := ask.effort()
	switch {
	case err != nil:
		return err
	case effort != "" && r.effort != nil && *r.effort != effort:
		return errReasoningTwice
	case effort != "":
		r.effort = &effort
	}
	r.excludesReasoning = ask.Exclude != nil && *ask.Exclude
	return nil
}

func (r *Request) ExcludesReasoning() bool { return r.excludesReasoning }

var budgetEfforts = []struct {
	upTo   int
	effort string
}{{2048, "low"}, {8192, "medium"}, {24576, "high"}, {49152, "xhigh"}}

func EffortOfBudget(tokens int) string {
	for _, b := range budgetEfforts {
		if tokens <= b.upTo {
			return b.effort
		}
	}
	return "max"
}

func (c Chunk) WithoutReasoning() Chunk {
	var envelope map[string]json.RawMessage
	var choices []map[string]json.RawMessage
	if json.Unmarshal(c.object, &envelope) != nil || json.Unmarshal(envelope["choices"], &choices) != nil {
		return c
	}
	thought := false
	for _, choice := range choices {
		for _, part := range []string{"delta", "message"} {
			var answer map[string]json.RawMessage
			if json.Unmarshal(choice[part], &answer) != nil || answer == nil {
				continue
			}
			for _, key := range reasoningKeys {
				if _, ok := answer[key]; ok {
					delete(answer, key)
					thought = true
				}
			}
			choice[part] = encodeObject(answer)
		}
	}
	if !thought {
		return c
	}
	list := []byte{'['}
	for i, choice := range choices {
		if i > 0 {
			list = append(list, ',')
		}
		list = append(list, encodeObject(choice)...)
	}
	envelope["choices"] = append(list, ']')
	return Chunk{object: encodeObject(envelope)}
}
