package money_test

import (
	"testing"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
)

func TestTheEnvelopePricesEveryCachedAndWrittenTokenAtTheDearerPromptRateAndAddsTheFeeAllowance(t *testing.T) {
	list := money.Price{PromptPerMTok: 1_000_000, CachedPromptPerMTok: 100_000, CacheWritePromptPerMTok: 1_250_000, CompletionPerMTok: 2_000_000,
		LongContext: &money.LongContext{FromPromptTokens: 10_000, Price: money.Price{PromptPerMTok: 2_000_000, CachedPromptPerMTok: 200_000, CacheWritePromptPerMTok: 2_000_000, CompletionPerMTok: 3_000_000}}}
	for name, tc := range map[string]struct {
		u    chat.Usage
		want money.Micros
	}{
		"nothing":                          {chat.Usage{}, money.FeeAllowance},
		"plain prompt and completion":      {chat.Usage{PromptTokens: 1000, CompletionTokens: 100}, 1000 + 200 + money.FeeAllowance},
		"cached tokens at the write rate":  {chat.Usage{PromptTokens: 1000, CachedPromptTokens: 400, CompletionTokens: 100}, 600 + 500 + 200 + money.FeeAllowance},
		"written tokens at the write rate": {chat.Usage{PromptTokens: 1000, CacheWritePromptTokens: 400, CompletionTokens: 100}, 600 + 500 + 200 + money.FeeAllowance},
		"long context at its own rates":    {chat.Usage{PromptTokens: 10_000, CachedPromptTokens: 5_000, CompletionTokens: 1000}, 20_000 + 3000 + money.FeeAllowance},
	} {
		if got := list.Envelope(tc.u); got != tc.want {
			t.Errorf("%s: envelope %d, want %d", name, got, tc.want)
		}
	}
}

func TestAVendorsReportedCostIsTakenUnlessARuleSendsItToListOrHoldsItToTheEnvelope(t *testing.T) {
	list := money.Price{PromptPerMTok: 1_000_000, CachedPromptPerMTok: 100_000, CacheWritePromptPerMTok: 1_000_000, CompletionPerMTok: 2_000_000}
	u := chat.Usage{PromptTokens: 1000, CachedPromptTokens: 500, CompletionTokens: 100}
	atList := money.EndpointCost{Micros: 750, Source: money.CostList}
	envelope := money.Micros(1200) + money.FeeAllowance
	for name, tc := range map[string]struct {
		v       chat.VendorCost
		want    money.EndpointCost
		refused money.CostVerdict
	}{
		"unreported":                   {chat.VendorCost{}, atList, money.CostAccepted},
		"reported under list":          {chat.VendorCost{Read: chat.CostReported, Micros: 300}, money.EndpointCost{Micros: 300, Source: money.CostReported}, money.CostAccepted},
		"reported as nothing":          {chat.VendorCost{Read: chat.CostReported}, money.EndpointCost{Source: money.CostReported}, money.CostAccepted},
		"reported at the envelope":     {chat.VendorCost{Read: chat.CostReported, Micros: int64(envelope)}, money.EndpointCost{Micros: envelope, Source: money.CostReported}, money.CostAccepted},
		"reported past the envelope":   {chat.VendorCost{Read: chat.CostReported, Micros: int64(envelope) + 1}, money.EndpointCost{Micros: envelope, Source: money.CostEnvelope}, money.AboveEnvelope},
		"reported negative":            {chat.VendorCost{Read: chat.CostReported, Micros: -1}, atList, money.NotACost},
		"no number":                    {chat.VendorCost{Read: chat.CostUnreadable}, atList, money.NotACost},
		"our own key with no upstream": {chat.VendorCost{Read: chat.CostBYOKUpstreamMissing, BYOK: true}, atList, money.BYOKUpstreamMissing},
		"our own key, priced":          {chat.VendorCost{Read: chat.CostReported, Micros: 420, BYOK: true}, money.EndpointCost{Micros: 420, Source: money.CostReported}, money.CostAccepted},
	} {
		got, refused := money.VendorCharged(list, u, tc.v)
		if got != tc.want || refused != tc.refused {
			t.Errorf("%s: recorded %+v refused as %s, want %+v refused as %s", name, got, refused, tc.want, tc.refused)
		}
	}
}
