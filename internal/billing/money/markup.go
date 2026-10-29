package money

import (
	"errors"
	"math"
	"math/big"
)

type Markup int64

const (
	ListPrice      Markup = 0
	markupListOnly        = tenThousandths
	markupCeiling         = 10 * tenThousandths
)

var ErrInvalidMarkup = errors.New("billing: markup must be a number from 1 to 10 with at most four decimal places")

func ParseMarkup(text string) (Markup, error) {
	n, ok := parseTenThousandths(text)
	if !ok || n < markupListOnly || n > markupCeiling {
		return 0, ErrInvalidMarkup
	}
	return Markup(n - markupListOnly), nil
}

func (k Markup) Of(m Micros) Micros {
	if m <= 0 || k <= 0 {
		return m
	}
	marked := new(big.Int).Mul(big.NewInt(int64(m)), big.NewInt(int64(k)))
	marked.Add(marked, big.NewInt(tenThousandths-1)).Quo(marked, big.NewInt(tenThousandths)).Add(marked, big.NewInt(int64(m)))
	if !marked.IsInt64() {
		return math.MaxInt64
	}
	return Micros(marked.Int64())
}

func (k Markup) Price(p Price) Price {
	marked := Price{
		PromptPerMTok:           k.Of(p.PromptPerMTok),
		CachedPromptPerMTok:     k.Of(p.CachedPromptPerMTok),
		CacheWritePromptPerMTok: k.Of(p.CacheWritePromptPerMTok),
		CompletionPerMTok:       k.Of(p.CompletionPerMTok),
	}
	if long := p.LongContext; long != nil {
		marked.LongContext = &LongContext{FromPromptTokens: long.FromPromptTokens, Price: k.Price(long.Price)}
	}
	return marked
}
