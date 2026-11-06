package money_test

import (
	"testing"

	"morse/backend/internal/billing/money"
)

func TestExceedsRetailHoldsPromptAndCompletionStrictAndCachedRatesToTheWorstCaseRequest(t *testing.T) {
	retail := money.Price{PromptPerMTok: 1_000_000, CachedPromptPerMTok: 100_000, CacheWritePromptPerMTok: 1_000_000, CompletionPerMTok: 4_000_000}
	flatRetailWithLong := func(from int, long money.Price) money.Price {
		p := retail
		p.LongContext = &money.LongContext{FromPromptTokens: from, Price: long}
		return p
	}
	costWithLong := func(base money.Price, from int, long money.Price) money.Price {
		base.LongContext = &money.LongContext{FromPromptTokens: from, Price: long}
		return base
	}
	price := func(prompt, cached, write, completion money.Micros) money.Price {
		return money.Price{PromptPerMTok: prompt, CachedPromptPerMTok: cached, CacheWritePromptPerMTok: write, CompletionPerMTok: completion}
	}
	for name, c := range map[string]struct {
		cost, retail money.Price
		want         string
	}{
		"equal prices":                     {retail, retail, ""},
		"a cheaper completion":             {price(1_000_000, 100_000, 1_000_000, 3_999_999), retail, ""},
		"a dearer prompt":                  {price(1_000_001, 100_000, 1_000_001, 4_000_000), retail, "its prompt rate is above the tier's"},
		"a dearer completion":              {price(1_000_000, 100_000, 1_000_000, 4_000_001), retail, "its completion rate is above the tier's"},
		"a dearer prompt cannot be repaid": {price(1_000_001, 1, 1_000_001, 1), retail, "its prompt rate is above the tier's"},
		"a zero cached rate is free":       {price(1_000_000, 0, 1_000_000, 4_000_000), retail, ""},
		"a cached rate above retail that the mix covers": {
			price(500_000, 150_000, 500_000, 1_500_000), retail, "",
		},
		"a cached rate above retail that the mix does not cover": {
			price(900_000, 300_000, 900_000, 4_000_000), retail,
			"a request of 100000 prompt tokens, 95000 of them cached, and 1000 completion tokens costs it 37000 micros against the tier's 18500",
		},
		"a cache-write rate above retail that the mix covers": {
			price(500_000, 100_000, 1_050_000, 1_000_000), retail, "",
		},
		"a cache-write rate above retail that the mix does not cover": {
			price(1_000_000, 100_000, 1_300_000, 4_000_000), retail,
			"a request of 100000 prompt tokens, 95000 of them cache-written, and 1000 completion tokens costs it 132500 micros against the tier's 104000",
		},
		"a dearer prompt at a long-context threshold": {
			costWithLong(retail, 128_000, price(1_500_000, 100_000, 1_500_000, 4_000_000)), retail,
			"its prompt rate is above the tier's at a prompt of 128000 tokens",
		},
		"a dearer completion at the retail's threshold": {
			costWithLong(price(1_000_000, 100_000, 1_000_000, 5_000_000), 200_000, price(1_000_000, 100_000, 1_000_000, 5_000_000)),
			flatRetailWithLong(200_000, price(1_000_000, 100_000, 1_000_000, 4_500_000)),
			"its completion rate is above the tier's",
		},
		"a cost whose long-context rates apply to the worst-case request and lose": {
			costWithLong(retail, 64_000, price(1_000_000, 300_000, 1_000_000, 4_000_000)), retail,
			"a request of 100000 prompt tokens, 95000 of them cached, and 1000 completion tokens costs it 37500 micros against the tier's 18500",
		},
		"a cached rate above retail's base that retail's own long-context rates cover": {
			price(1_000_000, 150_000, 1_000_000, 4_000_000),
			flatRetailWithLong(64_000, price(2_000_000, 200_000, 2_000_000, 6_000_000)), "",
		},
	} {
		if err := c.cost.Validate(); err != nil {
			t.Fatalf("%s: the case's cost is invalid: %v", name, err)
		}
		if got := c.cost.ExceedsRetail(c.retail); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}
