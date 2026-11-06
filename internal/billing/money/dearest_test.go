package money_test

import (
	"testing"

	"morse/backend/internal/billing/money"
)

func TestDearestIsAtLeastEachPriceAtEveryPromptSizeAndStaysValid(t *testing.T) {
	a := money.Price{PromptPerMTok: 100, CachedPromptPerMTok: 10, CacheWritePromptPerMTok: 100, CompletionPerMTok: 400,
		LongContext: &money.LongContext{FromPromptTokens: 200_000, Price: money.Price{PromptPerMTok: 200, CachedPromptPerMTok: 20, CacheWritePromptPerMTok: 200, CompletionPerMTok: 600}}}
	b := money.Price{PromptPerMTok: 150, CachedPromptPerMTok: 5, CacheWritePromptPerMTok: 150, CompletionPerMTok: 300,
		LongContext: &money.LongContext{FromPromptTokens: 100_000, Price: money.Price{PromptPerMTok: 150, CachedPromptPerMTok: 5, CacheWritePromptPerMTok: 150, CompletionPerMTok: 900}}}
	c := money.Price{PromptPerMTok: 120, CachedPromptPerMTok: 12, CacheWritePromptPerMTok: 120, CompletionPerMTok: 350}
	for _, pair := range [][2]money.Price{{a, b}, {a, c}, {b, c}, {c, c}} {
		d := money.Dearest(pair[0], pair[1])
		if err := d.Validate(); err != nil {
			t.Errorf("Dearest of %+v and %+v is invalid: %v", pair[0], pair[1], err)
		}
		for _, p := range pair {
			if rate := p.ExceedsRetail(d); rate != "" {
				t.Errorf("Dearest of %+v and %+v is below %+v on %s", pair[0], pair[1], p, rate)
			}
		}
	}
	d := money.Dearest(a, b)
	if d.LongContext == nil || d.LongContext.FromPromptTokens != 100_000 {
		t.Fatalf("the merged threshold is the lowest, 100000: %+v", d.LongContext)
	}
	if got := d.LongContext.PromptPerMTok; got != 200 {
		t.Errorf("a's long-context prompt rate 200 is the most either charges from 100000 on, so the merge is 200, got %d", got)
	}
	if got := d.LongContext.CompletionPerMTok; got != 900 {
		t.Errorf("merged long-context completion = %d, want b's 900", got)
	}
}
