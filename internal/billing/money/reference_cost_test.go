package money_test

import (
	"testing"

	"morse/backend/internal/billing/money"
)

func TestTheReferenceTurnCostsWhatOneAgentTurnCostsOnEachGLMFlashHost(t *testing.T) {
	cost := func(prompt, cached, completion money.Micros) money.Price {
		return money.Price{PromptPerMTok: prompt, CachedPromptPerMTok: cached, CacheWritePromptPerMTok: prompt, CompletionPerMTok: completion}
	}
	for name, c := range map[string]struct {
		price money.Price
		want  money.Micros
	}{
		"together": {cost(150_000, 30_000, 500_000), 4_100},
		"wafer":    {cost(50_000, 30_000, 200_000), 3_300},
		"isoquant": {cost(70_000, 25_000, 150_000), 2_875},
		"long-context rates from 100,000 tokens": {
			money.Price{PromptPerMTok: 1, CacheWritePromptPerMTok: 1, CompletionPerMTok: 1, LongContext: &money.LongContext{FromPromptTokens: 100_000, Price: cost(150_000, 30_000, 500_000)}},
			4_100,
		},
	} {
		if got := c.price.ReferenceCost(); got != c.want {
			t.Errorf("%s: the reference turn costs %d micros, want %d", name, got, c.want)
		}
	}
}
