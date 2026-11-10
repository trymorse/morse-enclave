package money_test

import (
	"math"
	"testing"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
)

func TestCostRoundsUpOnceOverThePromptAndCompletionSum(t *testing.T) {
	llama := money.Price{PromptPerMTok: 200_000, CachedPromptPerMTok: 20_000, CompletionPerMTok: 600_000}
	cases := []struct {
		name  string
		price money.Price
		usage chat.Usage
		want  money.Micros
	}{
		{"nothing used", llama, chat.Usage{}, 0},
		{"fractional micro rounds up", llama, chat.Usage{PromptTokens: 12, CompletionTokens: 40}, 27},
		{"exact micros stay exact", money.Price{PromptPerMTok: 5, CompletionPerMTok: 7}, chat.Usage{PromptTokens: 1_000_000, CompletionTokens: 2_000_000}, 19},
		{"two sub-micro halves round to one micro, not two", money.Price{PromptPerMTok: 1, CompletionPerMTok: 1}, chat.Usage{PromptTokens: 1, CompletionTokens: 1}, 1},
		{"negative upstream counts bill nothing", llama, chat.Usage{PromptTokens: -5, CompletionTokens: -1}, 0},
		{"free model", money.Price{}, chat.Usage{PromptTokens: 1 << 20, CompletionTokens: 1 << 20}, 0},
	}
	for _, c := range cases {
		if got := c.price.Cost(c.usage); got != c.want {
			t.Errorf("%s: Cost = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCostBillsCachedPromptTokensAtTheCachedRateAndTheRestAtThePromptRate(t *testing.T) {
	kimi := money.Price{PromptPerMTok: 3_000_000, CachedPromptPerMTok: 300_000, CompletionPerMTok: 15_000_000}
	cases := []struct {
		name  string
		price money.Price
		usage chat.Usage
		want  money.Micros
	}{
		{"nine tenths cached", kimi, chat.Usage{PromptTokens: 10_000, CachedPromptTokens: 9_000, CompletionTokens: 100}, 1_000*3 + 9_000*3/10 + 100*15},
		{"no cache hits cost the full prompt rate", kimi, chat.Usage{PromptTokens: 10_000, CompletionTokens: 100}, 10_000*3 + 100*15},
		{"every prompt token cached", kimi, chat.Usage{PromptTokens: 10_000, CachedPromptTokens: 10_000}, 10_000 * 3 / 10},
		{"negative cached bills the whole prompt at the prompt rate", kimi, chat.Usage{PromptTokens: 10_000, CachedPromptTokens: -1}, 10_000 * 3},
		{"cached share rounds up once with the rest", money.Price{PromptPerMTok: 1, CachedPromptPerMTok: 1, CompletionPerMTok: 1}, chat.Usage{PromptTokens: 2, CachedPromptTokens: 1, CompletionTokens: 1}, 1},
	}
	for _, c := range cases {
		if got := c.price.Cost(c.usage); got != c.want {
			t.Errorf("%s: Cost = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCostAtTheLargestTokensAndPriceDoesNotOverflow(t *testing.T) {
	most := money.Price{PromptPerMTok: money.MaxMicrosPerMTok, CachedPromptPerMTok: money.MaxMicrosPerMTok, CacheWritePromptPerMTok: money.MaxMicrosPerMTok, CompletionPerMTok: money.MaxMicrosPerMTok}
	want := money.Micros(2 * (math.MaxInt32) * (money.MaxMicrosPerMTok / 1_000_000))
	for _, split := range [][2]int{{0, 0}, {math.MaxInt, 0}, {0, math.MaxInt}, {math.MaxInt, math.MaxInt}} {
		if got := most.Cost(chat.Usage{PromptTokens: math.MaxInt, CachedPromptTokens: split[0], CacheWritePromptTokens: split[1], CompletionTokens: math.MaxInt}); got != want {
			t.Errorf("cached %d written %d: Cost = %d, want %d", split[0], split[1], got, want)
		}
	}
}

func TestHoldIsTheCostOfTheBoundsWithNoCacheDiscount(t *testing.T) {
	p := money.Price{PromptPerMTok: 300_000, CachedPromptPerMTok: 30_000, CacheWritePromptPerMTok: 300_000, CompletionPerMTok: 1_500_000}
	if got, want := p.Hold(4096, 1024), p.Cost(chat.Usage{PromptTokens: 4096, CompletionTokens: 1024}); got != want || got == 0 {
		t.Errorf("Hold = %d, want %d", got, want)
	}
}

func TestValidateAcceptsFreeAndRejectsNegativeOrAboveTheCeiling(t *testing.T) {
	for _, p := range []money.Price{{}, {PromptPerMTok: money.MaxMicrosPerMTok, CacheWritePromptPerMTok: money.MaxMicrosPerMTok, CompletionPerMTok: 1}, {PromptPerMTok: 2, CachedPromptPerMTok: 2, CacheWritePromptPerMTok: 3}} {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", p, err)
		}
	}
	for _, p := range []money.Price{{PromptPerMTok: -1}, {CompletionPerMTok: -1}, {PromptPerMTok: money.MaxMicrosPerMTok + 1}, {CompletionPerMTok: money.MaxMicrosPerMTok + 1}, {PromptPerMTok: 1, CachedPromptPerMTok: -1}, {PromptPerMTok: money.MaxMicrosPerMTok, CachedPromptPerMTok: money.MaxMicrosPerMTok + 1}, {CacheWritePromptPerMTok: money.MaxMicrosPerMTok + 1}} {
		if p.Validate() == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestValidateRejectsACachedRateAboveThePromptRate(t *testing.T) {
	if err := (money.Price{PromptPerMTok: 1, CachedPromptPerMTok: 2, CacheWritePromptPerMTok: 2}).Validate(); err == nil {
		t.Error("a cached rate above the prompt rate was accepted")
	}
	if err := (money.Price{CachedPromptPerMTok: 1}).Validate(); err == nil {
		t.Error("a cached rate on a free prompt was accepted")
	}
}

func grokPrice() money.Price {
	return money.Price{PromptPerMTok: 2_000_000, CachedPromptPerMTok: 500_000, CacheWritePromptPerMTok: 2_000_000, CompletionPerMTok: 6_000_000, LongContext: &money.LongContext{
		FromPromptTokens: 200_000,
		Price:            money.Price{PromptPerMTok: 4_000_000, CachedPromptPerMTok: 1_000_000, CacheWritePromptPerMTok: 4_000_000, CompletionPerMTok: 12_000_000},
	}}
}

func TestCostMatchesTheVendorsReportedCostBelowTheLongContextThreshold(t *testing.T) {
	if got := grokPrice().Cost(chat.Usage{PromptTokens: 1249, CachedPromptTokens: 1152, CompletionTokens: 79}); got != 1244 {
		t.Errorf("Cost = %d, want 1244, xAI's cost_in_usd_ticks of 12440000", got)
	}
}

func TestLongContextRatesApplyToTheWholeRequestFromTheThreshold(t *testing.T) {
	p := grokPrice()
	for _, c := range []struct {
		prompt int
		want   money.Micros
	}{{199_999, 399_998 + 6_000}, {200_000, 800_000 + 12_000}, {400_000, 1_600_000 + 12_000}} {
		if got := p.Cost(chat.Usage{PromptTokens: c.prompt, CompletionTokens: 1000}); got != c.want {
			t.Errorf("prompt %d: Cost = %d, want %d", c.prompt, got, c.want)
		}
	}
}

func TestHoldPricesAPromptAtTheThresholdAtTheLongContextRates(t *testing.T) {
	p := grokPrice()
	hold, cost := p.Hold(200_000, 4096), p.Cost(chat.Usage{PromptTokens: 200_000, CompletionTokens: 4096})
	if hold != 800_000+49_152 || hold < cost {
		t.Errorf("Hold = %d, want 849152, the long-context rates, covering Cost %d", hold, cost)
	}
}

func TestValidateRejectsMalformedLongContextPrices(t *testing.T) {
	if err := grokPrice().Validate(); err != nil {
		t.Fatalf("grok price rejected: %v", err)
	}
	for name, mutate := range map[string]func(*money.Price){
		"no threshold":        func(p *money.Price) { p.LongContext.FromPromptTokens = 0 },
		"cheaper prompt":      func(p *money.Price) { p.LongContext.PromptPerMTok = 1_000_000 },
		"cheaper cached":      func(p *money.Price) { p.LongContext.CachedPromptPerMTok = 100_000 },
		"cheaper completion":  func(p *money.Price) { p.LongContext.CompletionPerMTok = 1 },
		"nested long context": func(p *money.Price) { p.LongContext.LongContext = &money.LongContext{FromPromptTokens: 1} },
		"invalid long rates":  func(p *money.Price) { p.LongContext.CachedPromptPerMTok = 5_000_000 },
	} {
		p := grokPrice()
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func lunaPrice() money.Price {
	return money.Price{PromptPerMTok: 100_000, CachedPromptPerMTok: 10_000, CacheWritePromptPerMTok: 125_000, CompletionPerMTok: 500_000, LongContext: &money.LongContext{
		FromPromptTokens: 272_001,
		Price:            money.Price{PromptPerMTok: 200_000, CachedPromptPerMTok: 20_000, CacheWritePromptPerMTok: 250_000, CompletionPerMTok: 750_000},
	}}
}

func TestCostBillsCacheWritesAtTheCacheWriteRateAtBothTiers(t *testing.T) {
	cases := []struct {
		name  string
		usage chat.Usage
		want  money.Micros
	}{
		{"recorded luna cache write", chat.Usage{PromptTokens: 3487, CacheWritePromptTokens: 3484, CompletionTokens: 5}, 439},
		{"cached, written, and uncached in one prompt", chat.Usage{PromptTokens: 10_000, CachedPromptTokens: 4_000, CacheWritePromptTokens: 5_000, CompletionTokens: 100}, (1_000*100_000 + 4_000*10_000 + 5_000*125_000 + 100*500_000) / 1_000_000},
		{"long context", chat.Usage{PromptTokens: 300_000, CachedPromptTokens: 100_000, CacheWritePromptTokens: 100_000, CompletionTokens: 1_000}, (100_000*200_000 + 100_000*20_000 + 100_000*250_000 + 1_000*750_000) / 1_000_000},
		{"writes past the prompt bill the whole prompt as written", chat.Usage{PromptTokens: 1_000, CacheWritePromptTokens: 5_000}, 125},
		{"writes past what the cache left bill only the rest", chat.Usage{PromptTokens: 1_000, CachedPromptTokens: 800, CacheWritePromptTokens: 500}, (800*10_000 + 200*125_000) / 1_000_000},
		{"cached past the prompt leaves nothing to write or bill at the prompt rate", chat.Usage{PromptTokens: 1_000, CachedPromptTokens: 2_000, CacheWritePromptTokens: 10}, 10},
		{"negative writes bill the prompt rate", chat.Usage{PromptTokens: 1_000, CacheWritePromptTokens: -1}, 100},
	}
	for _, c := range cases {
		if got := lunaPrice().Cost(c.usage); got != c.want {
			t.Errorf("%s: Cost = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestHoldCoversAPromptThatIsAllCacheWritesAtBothTiers(t *testing.T) {
	p := lunaPrice()
	for _, prompt := range []int{4096, 272_000, 272_001, 400_000} {
		hold := p.Hold(prompt, 1024)
		for _, u := range []chat.Usage{
			{PromptTokens: prompt, CompletionTokens: 1024},
			{PromptTokens: prompt, CacheWritePromptTokens: prompt, CompletionTokens: 1024},
		} {
			if cost := p.Cost(u); cost > hold {
				t.Errorf("prompt %d: Cost %+v = %d exceeds Hold %d", prompt, u, cost, hold)
			}
		}
	}
}

func TestValidateRejectsACacheWriteRateBelowThePromptRate(t *testing.T) {
	if err := (money.Price{PromptPerMTok: 2, CacheWritePromptPerMTok: 1}).Validate(); err == nil {
		t.Error("a cache-write rate below the prompt rate was accepted")
	}
	p := lunaPrice()
	p.LongContext.CacheWritePromptPerMTok = p.LongContext.PromptPerMTok
	p.CacheWritePromptPerMTok = p.LongContext.PromptPerMTok + 1
	if err := p.Validate(); err == nil {
		t.Error("a long-context cache-write rate below the base cache-write rate was accepted")
	}
}

func TestOutputWithinIsTheMostOutputWhoseHoldTheMicrosCover(t *testing.T) {
	fable := money.Price{PromptPerMTok: 12_000_000, CachedPromptPerMTok: 1_200_000, CacheWritePromptPerMTok: 15_000_000, CompletionPerMTok: 60_000_000}
	long := fable
	long.LongContext = &money.LongContext{FromPromptTokens: 200_000, Price: money.Price{PromptPerMTok: 24_000_000, CachedPromptPerMTok: 2_400_000, CacheWritePromptPerMTok: 30_000_000, CompletionPerMTok: 90_000_000}}
	cases := []struct {
		name   string
		price  money.Price
		micros money.Micros
		prompt int
		want   int
	}{
		{"184 credits after a 1,000 token prompt", fable, 1_840_000, 1_000, 30_416},
		{"the prompt and exactly one token", fable, 15_060, 1_000, 1},
		{"a micro short of one token", fable, 15_059, 1_000, 0},
		{"exactly the prompt", fable, 15_000, 1_000, 0},
		{"less than the prompt", fable, 14_999, 1_000, 0},
		{"nothing", fable, 0, 0, 0},
		{"a negative amount", fable, -1, 0, 0},
		{"a prompt below the long-context threshold", long, 10_000_000, 199_999, 116_666},
		{"a prompt at the long-context threshold", long, 10_000_000, 200_000, 44_444},
		{"a rate below a micro a token", money.Price{CompletionPerMTok: 1}, 1, 0, 1_000_000},
		{"free output", money.Price{PromptPerMTok: 1, CacheWritePromptPerMTok: 1}, 1, 1, math.MaxInt32},
		{"more than any request holds", fable, math.MaxInt64, 0, math.MaxInt32},
	}
	for _, c := range cases {
		got := c.price.OutputWithin(c.micros, c.prompt)
		if got != c.want {
			t.Errorf("%s: OutputWithin = %d, want %d", c.name, got, c.want)
		}
		if got > 0 && c.price.Hold(c.prompt, got) > c.micros {
			t.Errorf("%s: Hold of %d tokens is %d, above %d", c.name, got, c.price.Hold(c.prompt, got), c.micros)
		}
		if got < math.MaxInt32 && c.price.Hold(c.prompt, got+1) <= c.micros {
			t.Errorf("%s: Hold of %d tokens is %d, within %d", c.name, got+1, c.price.Hold(c.prompt, got+1), c.micros)
		}
	}
}

func TestAVeilRateChargesEachCallAndRoundsItsTokensUp(t *testing.T) {
	r := money.VeilRate{PerCall: 200, PerMTok: 800_000}
	for _, c := range []struct {
		calls, tokens int
		want          money.Micros
	}{{1, 1000, 1000}, {2, 0, 400}, {1, 1, 201}, {0, 0, 0}, {-1, -5, 0}, {3, 1_000_000, 800_600}} {
		if got := r.Of(c.calls, c.tokens); got != c.want {
			t.Errorf("Of(%d, %d) = %d, want %d", c.calls, c.tokens, got, c.want)
		}
	}
	if !(money.VeilRate{}).Zero() || r.Zero() {
		t.Error("Zero reads the rate wrong")
	}
}
