package money_test

import (
	"errors"
	"math"
	"testing"

	"morse/backend/internal/billing/money"
)

const testMarkup money.Markup = 5_000

func TestParseMarkupReadsOneToTenWithAtMostFourPlacesAsTheShareAboveList(t *testing.T) {
	for text, want := range map[string]money.Markup{"1": 0, "1.0": 0, "1.3": 3_000, "1.30": 3_000, "1.25": 2_500, "1.0001": 1, "2": 10_000, "10": 90_000, "10.0000": 90_000} {
		if got, err := money.ParseMarkup(text); err != nil || got != want {
			t.Errorf("%s = %d (%v), want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "0", "0.9999", "-1", "10.0001", "11", "12", "1.23456", "1e0", ".5", "1.", `"1.3"`, "null", "+1.3", " 1.3"} {
		if got, err := money.ParseMarkup(text); !errors.Is(err, money.ErrInvalidMarkup) {
			t.Errorf("%q = %d (%v), want ErrInvalidMarkup", text, got, err)
		}
	}
}

func TestMarkupOfRoundsUpToTheMicroAndSaturates(t *testing.T) {
	for _, c := range []struct {
		markup money.Markup
		in     money.Micros
		want   money.Micros
	}{
		{0, 12_345, 12_345},
		{testMarkup, 0, 0},
		{testMarkup, 1, 2},
		{testMarkup, 5, 8},
		{testMarkup, 30_000, 45_000},
		{testMarkup, 3_000_000, 4_500_000},
		{testMarkup, 6_000, 9_000},
		{testMarkup, -5, -5},
		{1, 10_000, 10_001},
		{90_000, 7, 70},
		{90_000, math.MaxInt64 / 2, math.MaxInt64},
	} {
		if got := c.markup.Of(c.in); got != c.want {
			t.Errorf("%d.Of(%d) = %d, want %d", c.markup, c.in, got, c.want)
		}
	}
}

func TestMarkupPriceMarksEveryRateIncludingLongContextAndLeavesTheListAlone(t *testing.T) {
	long := &money.LongContext{FromPromptTokens: 272_001, Price: money.Price{PromptPerMTok: 4_000_000, CachedPromptPerMTok: 200_000, CacheWritePromptPerMTok: 5_000_000, CompletionPerMTok: 15_000_000}}
	list := money.Price{PromptPerMTok: 2_000_000, CachedPromptPerMTok: 100_000, CacheWritePromptPerMTok: 2_500_000, CompletionPerMTok: 10_000_000, LongContext: long}
	got := testMarkup.Price(list)
	want := money.Price{PromptPerMTok: 3_000_000, CachedPromptPerMTok: 150_000, CacheWritePromptPerMTok: 3_750_000, CompletionPerMTok: 15_000_000,
		LongContext: &money.LongContext{FromPromptTokens: 272_001, Price: money.Price{PromptPerMTok: 6_000_000, CachedPromptPerMTok: 300_000, CacheWritePromptPerMTok: 7_500_000, CompletionPerMTok: 22_500_000}}}
	if got.PromptPerMTok != want.PromptPerMTok || got.CachedPromptPerMTok != want.CachedPromptPerMTok || got.CacheWritePromptPerMTok != want.CacheWritePromptPerMTok || got.CompletionPerMTok != want.CompletionPerMTok || *got.LongContext != *want.LongContext {
		t.Errorf("marked %+v long %+v, want %+v long %+v", got, got.LongContext, want, want.LongContext)
	}
	if got.LongContext == long || long.PromptPerMTok != 4_000_000 || list.PromptPerMTok != 2_000_000 {
		t.Error("marking changed the list price")
	}
	if err := got.Validate(); err != nil {
		t.Errorf("marked price invalid: %v", err)
	}
	if money.Markup(0).Price(list).PromptPerMTok != list.PromptPerMTok {
		t.Error("a zero markup changed the price")
	}
}
