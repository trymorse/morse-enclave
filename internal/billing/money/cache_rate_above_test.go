package money_test

import (
	"testing"

	"morse/backend/internal/billing/money"
)

func TestCacheRateAboveNamesTheCachedOrCacheWriteRateThatPassesRetailsAtAnyPromptSize(t *testing.T) {
	price := func(prompt, cached, write, completion money.Micros) money.Price {
		return money.Price{PromptPerMTok: prompt, CachedPromptPerMTok: cached, CacheWritePromptPerMTok: write, CompletionPerMTok: completion}
	}
	withLong := func(base money.Price, from int, long money.Price) money.Price {
		base.LongContext = &money.LongContext{FromPromptTokens: from, Price: long}
		return base
	}
	retail := price(1_000_000, 100_000, 1_000_000, 4_000_000)
	for name, c := range map[string]struct {
		cost, retail money.Price
		want         string
	}{
		"equal prices":                                  {retail, retail, ""},
		"cheaper cached and cache-write":                {price(800_000, 50_000, 900_000, 4_000_000), retail, ""},
		"a dearer prompt is not its business":           {price(2_000_000, 100_000, 2_000_000, 8_000_000), price(1_000_000, 100_000, 2_000_000, 4_000_000), ""},
		"a dearer cached rate":                          {price(1_000_000, 100_001, 1_000_000, 4_000_000), retail, "its cached rate 100001 is above the tier's 100000 at a prompt of 0 tokens"},
		"a dearer explicit cache-write":                 {price(1_000_000, 100_000, 1_000_001, 4_000_000), retail, "its cache-write rate 1000001 is above the tier's 1000000 at a prompt of 0 tokens"},
		"an absent cache-write follows an equal prompt": {price(1_000_000, 100_000, 1_000_000, 4_000_000), price(1_000_000, 100_000, 1_200_000, 4_000_000), ""},
		"an absent cache-write follows a dearer prompt": {price(1_100_000, 100_000, 1_100_000, 4_000_000), retail, "its cache-write rate 1100000 is above the tier's 1000000 at a prompt of 0 tokens"},
		"a cost long context at 100k dearer than a retail one at 200k": {
			withLong(retail, 100_000, price(1_000_000, 200_000, 1_000_000, 4_000_000)),
			withLong(retail, 200_000, price(1_000_000, 300_000, 1_000_000, 4_000_000)),
			"its cached rate 200000 is above the tier's 100000 at a prompt of 100000 tokens",
		},
		"a cost long context at 200k dearer than a retail one at 100k": {
			withLong(retail, 200_000, price(1_000_000, 100_000, 1_300_000, 4_000_000)),
			withLong(retail, 100_000, price(1_000_000, 100_000, 1_200_000, 4_000_000)),
			"its cache-write rate 1300000 is above the tier's 1200000 at a prompt of 200000 tokens",
		},
		"a cost long context at 100k that retail's at 200k never undercuts": {
			withLong(retail, 100_000, price(1_000_000, 100_000, 1_000_000, 4_000_000)),
			withLong(retail, 200_000, price(1_000_000, 300_000, 1_000_000, 4_000_000)), "",
		},
		"a cost long context at 200k that retail's at 100k covers": {
			withLong(retail, 200_000, price(1_000_000, 250_000, 1_000_000, 4_000_000)),
			withLong(retail, 100_000, price(1_000_000, 250_000, 1_000_000, 4_000_000)), "",
		},
		"a cached rate above retail's base that its long context covers only later": {
			price(1_000_000, 150_000, 1_000_000, 4_000_000),
			withLong(retail, 64_000, price(2_000_000, 200_000, 2_000_000, 6_000_000)),
			"its cached rate 150000 is above the tier's 100000 at a prompt of 0 tokens",
		},
	} {
		if err := c.cost.Validate(); err != nil {
			t.Fatalf("%s: the case's cost is invalid: %v", name, err)
		}
		if err := c.retail.Validate(); err != nil {
			t.Fatalf("%s: the case's retail is invalid: %v", name, err)
		}
		if got := c.cost.CacheRateAbove(c.retail); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}
