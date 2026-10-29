package money_test

import (
	"testing"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
)

func TestABillCostsWhatWasMeasuredAtThePriceAndKeepsTheMeasurementsLabels(t *testing.T) {
	price := money.Price{PromptPerMTok: 1_000_000, CompletionPerMTok: 2_000_000}
	reported := chat.Usage{PromptTokens: 12, CachedPromptTokens: 5, CompletionTokens: 40, ReasoningTokens: 30}
	for name, tc := range map[string]struct {
		e      measure.Evidence
		cost   money.Micros
		source measure.UsageSource
	}{
		"reported":   {measure.Evidence{Outcome: measure.Completed, Upstream: reported, Reply: measure.Streamed{Events: 2}}, 87, measure.UsageReported},
		"unanswered": {measure.Evidence{Outcome: measure.Completed, Upstream: reported, Reply: measure.Streamed{Events: 2}, Finish: chat.FinishLength, Unanswered: true}, 7, measure.UsageReported},
		"hidden thinking": {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, PromptBytes: 100, PromptBound: 100, Reply: measure.Streamed{Events: 7}, OutputLimit: 900, ReasoningCap: 900,
			ReasoningRequested: true, HidesReasoning: true, Thinking: measure.ThinkingTime{Duration: 2500 * time.Millisecond, Rate: 100}}, 564, measure.UsageEstimated},
		"rejected with nothing reported":   {measure.Evidence{Outcome: measure.Rejected, PromptBytes: 100, PromptBound: 100, Reply: measure.Streamed{Events: 3}}, 0, measure.UsageNone},
		"rejected with the upstream usage": {measure.Evidence{Outcome: measure.Rejected, Upstream: chat.Usage{PromptTokens: 12}, Reply: measure.Streamed{Events: 3}}, 12, measure.UsageReported},
	} {
		m := tc.e.Measure()
		want := money.Settlement{Outcome: tc.e.Outcome, Tokens: m.Tokens, Cost: tc.cost, Source: tc.source, Sides: m.Sides, Thinking: m.Thinking, Finish: tc.e.Finish, Unanswered: tc.e.Unanswered}
		if got := price.Bill(m); got != want {
			t.Errorf("%s: billed %+v, want %+v", name, got, want)
		}
	}
}
