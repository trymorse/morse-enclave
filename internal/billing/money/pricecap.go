package money

import "strconv"

// PriceCap is a request's provider.max_price: the most a chat may charge per million prompt tokens and per million
// completion tokens, in micros. A nil rate sets no cap on that side.
type PriceCap struct {
	Prompt     *Micros `json:"prompt,omitempty"`
	Completion *Micros `json:"completion,omitempty"`
}

func (c PriceCap) Set() bool { return c.Prompt != nil || c.Completion != nil }

// Admits says p bills a chat of promptTokens within the cap, at the long-context rates once the prompt reaches them.
func (c PriceCap) Admits(p Price, promptTokens int) bool {
	p = p.At(promptTokens)
	return (c.Prompt == nil || p.PromptPerMTok <= *c.Prompt) && (c.Completion == nil || p.CompletionPerMTok <= *c.Completion)
}

func CapMicros(dollars float64) Micros {
	const maxDollars = float64(MaxMicrosPerMTok) / 1e6
	dollars = min(dollars, maxDollars)
	return Micros(int64(dollars*1e9+0.5) / 1000)
}

func (m Micros) Dollars() string {
	return "$" + strconv.FormatFloat(float64(m)/1e6, 'f', -1, 64)
}
