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

func (p Price) Cost(u chat.Usage) Micros {
	if long := p.LongContext; long != nil && u.PromptTokens >= long.FromPromptTokens {
		p = long.Price
	}
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
	if long := p.LongContext; long != nil && promptTokens >= long.FromPromptTokens {
		p = long.Price
	}
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
