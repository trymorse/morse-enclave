package money

import (
	"testing"

	"morse/backend/internal/chat"
)

func TestAPriceCapAdmitsAPriceWhoseCappedRatesAreAtOrBelowIt(t *testing.T) {
	micros := func(m Micros) *Micros { return &m }
	price := Price{PromptPerMTok: 600_000, CompletionPerMTok: 2_500_000}
	for name, tc := range map[string]struct {
		cap  PriceCap
		want bool
	}{
		"no cap":                         {PriceCap{}, true},
		"a prompt cap at the rate":       {PriceCap{Prompt: micros(600_000)}, true},
		"a prompt cap below the rate":    {PriceCap{Prompt: micros(599_999)}, false},
		"a completion cap at the rate":   {PriceCap{Completion: micros(2_500_000)}, true},
		"a completion cap below it":      {PriceCap{Completion: micros(2_499_999)}, false},
		"both caps met":                  {PriceCap{Prompt: micros(1_000_000), Completion: micros(3_000_000)}, true},
		"one of two caps missed":         {PriceCap{Prompt: micros(1_000_000), Completion: micros(1)}, false},
		"a cap of zero on a priced rate": {PriceCap{Prompt: micros(0)}, false},
	} {
		if got := tc.cap.Admits(price, 1_000); got != tc.want || tc.cap.Set() != (tc.cap != PriceCap{}) {
			t.Errorf("%s: admits %t, want %t", name, got, tc.want)
		}
	}
}

func TestAPriceCapComparesTheLongContextRatesOnceThePromptReachesThem(t *testing.T) {
	micros := func(m Micros) *Micros { return &m }
	price := Price{PromptPerMTok: 2_000_000, CompletionPerMTok: 8_000_000, LongContext: &LongContext{FromPromptTokens: 200_000, Price: Price{PromptPerMTok: 4_000_000, CompletionPerMTok: 16_000_000}}}
	for name, tc := range map[string]struct {
		cap    PriceCap
		prompt int
		want   bool
	}{
		"a prompt cap at the base rate, under the threshold": {PriceCap{Prompt: micros(2_000_000)}, 199_999, true},
		"the same cap at the threshold":                      {PriceCap{Prompt: micros(2_000_000)}, 200_000, false},
		"a completion cap at the base rate, past it":         {PriceCap{Completion: micros(8_000_000)}, 500_000, false},
		"caps at the long-context rates, past the threshold": {PriceCap{Prompt: micros(4_000_000), Completion: micros(16_000_000)}, 500_000, true},
	} {
		if got := tc.cap.Admits(price, tc.prompt); got != tc.want {
			t.Errorf("%s: admits %t, want %t", name, got, tc.want)
		}
		if bills := price.Cost(chat.Usage{PromptTokens: tc.prompt, CompletionTokens: 1_000_000}) - price.Cost(chat.Usage{PromptTokens: tc.prompt}); tc.cap.Completion != nil && tc.want != (bills <= *tc.cap.Completion) {
			t.Errorf("%s: admits %t, but a million completion tokens bill %d", name, tc.want, bills)
		}
	}
}

func TestDollarsPerMillionTokensBecomeWholeMicrosRoundedDown(t *testing.T) {
	for dollars, want := range map[float64]Micros{0: 0, 0.29: 290_000, 0.6: 600_000, 0.5555555: 555_555, 2.5: 2_500_000, 1e9: MaxMicrosPerMTok} {
		if got := CapMicros(dollars); got != want {
			t.Errorf("$%v became %d micros, want %d", dollars, got, want)
		}
	}
	if got := Micros(2_500_000).Dollars(); got != "$2.5" {
		t.Errorf("2500000 micros read %s, want $2.5", got)
	}
}
