package money

import (
	"errors"
	"fmt"
	"math"

	"morse/backend/internal/chat"
)

const (
	tokensPerPriceUnit            = 1_000_000
	MaxMicrosPerMTok       Micros = 1_000_000_000
	maxBillableTokens             = math.MaxInt32
	priceUnitRoundingSlack        = tokensPerPriceUnit - 1
)

type Price struct {
	PromptPerMTok           Micros
	CachedPromptPerMTok     Micros
	CacheWritePromptPerMTok Micros
	CompletionPerMTok       Micros
	LongContext             *LongContext
}

type LongContext struct {
	FromPromptTokens int
	Price
}

func (p Price) Validate() error {
	for _, rate := range []Micros{p.PromptPerMTok, p.CachedPromptPerMTok, p.CacheWritePromptPerMTok, p.CompletionPerMTok} {
		if billableRate(rate) != rate {
			return fmt.Errorf("prices must be between 0 and %d micros per million tokens", MaxMicrosPerMTok)
		}
	}
	if p.CachedPromptPerMTok > p.PromptPerMTok {
		return errors.New("the cached prompt price must not exceed the prompt price")
	}
	if p.CacheWritePromptPerMTok < p.PromptPerMTok {
		return errors.New("the cache-write prompt price must not be below the prompt price")
	}
	long := p.LongContext
	switch {
	case long == nil:
		return nil
	case long.FromPromptTokens <= 0 || long.LongContext != nil:
		return errors.New("a long-context price needs a positive from_prompt_tokens and no long-context price of its own")
	case long.PromptPerMTok < p.PromptPerMTok || long.CachedPromptPerMTok < p.CachedPromptPerMTok || long.CacheWritePromptPerMTok < p.CacheWritePromptPerMTok || long.CompletionPerMTok < p.CompletionPerMTok:
		return errors.New("long-context prices must not be below the base prices")
	}
	return long.Price.Validate()
}

// At is the price a chat of promptTokens bills at: the long-context price once the prompt reaches its threshold.
func (p Price) At(promptTokens int) Price {
	if long := p.LongContext; long != nil && promptTokens >= long.FromPromptTokens {
		return long.Price
	}
	return p
}

func (p Price) Cost(u chat.Usage) Micros {
	p = p.At(u.PromptTokens)
	prompt := billableTokens(u.PromptTokens)
	cached := min(billableTokens(u.CachedPromptTokens), prompt)
	written := min(billableTokens(u.CacheWritePromptTokens), prompt-cached)
	scaled := (prompt-cached-written)*int64(billableRate(p.PromptPerMTok)) +
		cached*int64(billableRate(p.CachedPromptPerMTok)) +
		written*int64(billableRate(p.CacheWritePromptPerMTok)) +
		billableTokens(u.CompletionTokens)*int64(billableRate(p.CompletionPerMTok))
	return PerMTok(Micros(scaled))
}

func PerMTok(scaled Micros) Micros {
	return (scaled + priceUnitRoundingSlack) / tokensPerPriceUnit
}

func (p Price) Hold(promptTokens, completionBound int) Micros {
	return p.Cost(chat.Usage{PromptTokens: promptTokens, CacheWritePromptTokens: promptTokens, CompletionTokens: completionBound})
}

// OutputWithin is the most completion tokens whose Hold with promptTokens stays within micros, and zero when
// micros does not cover the prompt and one token.
func (p Price) OutputWithin(micros Micros, promptTokens int) int {
	p = p.At(promptTokens)
	left := int64(min(max(micros, 0), math.MaxInt64/tokensPerPriceUnit))*tokensPerPriceUnit -
		billableTokens(promptTokens)*int64(billableRate(p.CacheWritePromptPerMTok))
	rate := int64(billableRate(p.CompletionPerMTok))
	switch {
	case left < 0:
		return 0
	case rate == 0:
		return maxBillableTokens
	}
	return int(min(left/rate, maxBillableTokens))
}

func billableTokens(n int) int64 { return int64(min(max(n, 0), maxBillableTokens)) }

func billableRate(r Micros) Micros { return min(max(r, 0), MaxMicrosPerMTok) }

// at is the price's rates for a prompt of that many tokens.
func (p Price) at(promptTokens int) Price {
	if long := p.LongContext; long != nil && promptTokens >= long.FromPromptTokens {
		return long.Price
	}
	return Price{PromptPerMTok: p.PromptPerMTok, CachedPromptPerMTok: p.CachedPromptPerMTok, CacheWritePromptPerMTok: p.CacheWritePromptPerMTok, CompletionPerMTok: p.CompletionPerMTok}
}

var ReferenceTurn = chat.Usage{PromptTokens: 100_000, CachedPromptTokens: 95_000, CompletionTokens: 1_000}

var cacheWrittenTurn = chat.Usage{PromptTokens: 100_000, CacheWritePromptTokens: 95_000, CompletionTokens: 1_000}

func (p Price) ReferenceCost() Micros { return p.Cost(ReferenceTurn) }

// promptSizes are the prompt sizes at which p or retail changes price: zero and each long-context threshold.
func promptSizes(p, retail Price) []int {
	sizes := []int{0}
	for _, q := range []Price{p, retail} {
		if q.LongContext != nil {
			sizes = append(sizes, q.LongContext.FromPromptTokens)
		}
	}
	return sizes
}

// ExceedsRetail says why p, a host's cost, may not be served at retail's price, or "" when it may. Its prompt and
// completion rates must be at most retail's at every prompt size. Its cached and cache-write rates may be above
// retail's while ReferenceTurn, cached or cache-written, costs p no more than retail charges.
func (p Price) ExceedsRetail(retail Price) string {
	for _, n := range promptSizes(p, retail) {
		cost, sold := p.at(n), retail.at(n)
		for _, rate := range []struct {
			name       string
			cost, sold Micros
		}{
			{"prompt", cost.PromptPerMTok, sold.PromptPerMTok},
			{"completion", cost.CompletionPerMTok, sold.CompletionPerMTok},
		} {
			if rate.cost > rate.sold {
				if n > 0 {
					return fmt.Sprintf("its %s rate is above the tier's at a prompt of %d tokens", rate.name, n)
				}
				return fmt.Sprintf("its %s rate is above the tier's", rate.name)
			}
		}
	}
	for _, mix := range []struct {
		name string
		turn chat.Usage
	}{
		{"cached", ReferenceTurn},
		{"cache-written", cacheWrittenTurn},
	} {
		if cost, sold := p.Cost(mix.turn), retail.Cost(mix.turn); cost > sold {
			return fmt.Sprintf("a request of %d prompt tokens, %d of them %s, and %d completion tokens costs it %d micros against the tier's %d",
				mix.turn.PromptTokens, mix.turn.CachedPromptTokens+mix.turn.CacheWritePromptTokens, mix.name, mix.turn.CompletionTokens, cost, sold)
		}
	}
	return ""
}

// CacheRateAbove says which of p's cached or cache-write rates is above retail's at some prompt size, or "" when
// neither is.
func (p Price) CacheRateAbove(retail Price) string {
	for _, n := range promptSizes(p, retail) {
		cost, sold := p.at(n), retail.at(n)
		for _, rate := range []struct {
			name       string
			cost, sold Micros
		}{
			{"cached", cost.CachedPromptPerMTok, sold.CachedPromptPerMTok},
			{"cache-write", cost.CacheWritePromptPerMTok, sold.CacheWritePromptPerMTok},
		} {
			if rate.cost > rate.sold {
				return fmt.Sprintf("its %s rate %d is above the tier's %d at a prompt of %d tokens", rate.name, rate.cost, rate.sold, n)
			}
		}
	}
	return ""
}
