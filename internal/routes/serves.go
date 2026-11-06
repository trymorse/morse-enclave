package routes

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/compaction"
)

func (r chatRoute) serves(defaultMarkup money.Markup) (Serves, error) {
	c, err := r.chat(defaultMarkup)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r chatRoute) chat(defaultMarkup money.Markup) (Chat, error) {
	price, err := r.Price.parse("price")
	if err != nil {
		return Chat{}, err
	}
	markup, err := r.markup(defaultMarkup)
	if err != nil {
		return Chat{}, err
	}
	if err := markup.Price(price).Validate(); err != nil {
		return Chat{}, fmt.Errorf("has an invalid price at its markup: %w", err)
	}
	if r.MaxOutputTokens <= 0 {
		return Chat{}, errors.New("needs a positive max_output_tokens")
	}
	if r.DefaultMaxTokens <= 0 || r.DefaultMaxTokens > r.MaxOutputTokens {
		return Chat{}, fmt.Errorf("needs a default_max_tokens between 1 and its max_output_tokens %d", r.MaxOutputTokens)
	}
	if r.ReasoningEfforts == nil {
		return Chat{}, errors.New("must list the reasoning_efforts its upstream model accepts, [] for none")
	}
	rung := -1
	for _, effort := range r.ReasoningEfforts {
		next := slices.Index(chat.EffortLadder, effort)
		if next <= rung {
			return Chat{}, fmt.Errorf("reasoning_efforts must name each of %s at most once, in that order", strings.Join(chat.EffortLadder, ", "))
		}
		rung = next
	}
	if r.DefaultReasoningEffort != "" && (r.DefaultReasoningEffort == chat.NoEffort || !slices.Contains(r.ReasoningEfforts, r.DefaultReasoningEffort)) {
		return Chat{}, fmt.Errorf("default_reasoning_effort must be one of its reasoning_efforts other than %s", chat.NoEffort)
	}
	inputs, err := catalog.ParseInputs(r.InputModalities)
	if err != nil {
		return Chat{}, err
	}
	compactAt, err := r.compactAt()
	if err != nil {
		return Chat{}, err
	}
	return Chat{
		ChatTerms: catalog.ChatTerms{
			MaxOutputTokens: r.MaxOutputTokens, DefaultMaxTokens: r.DefaultMaxTokens, DefaultReasoningEffort: r.DefaultReasoningEffort, ReasoningEfforts: r.ReasoningEfforts,
			Inputs: inputs, ContextTokens: r.ContextTokens, CompactAtTokens: compactAt, HidesReasoning: r.HidesReasoning,
		},
		Price: price, Markup: markup, DecodeMaxTPS: r.DecodeMaxTPS,
		Tokenizer: r.Tokenizer, HiddenReasoningTPS: r.HiddenReasoningTPS,
		OpenRouterID: cmp.Or(r.OpenRouterID, r.UpstreamModel), AnswersInReasoning: r.AnswersInReasoning,
	}, nil
}

func (r chatRoute) compactAt() (int, error) {
	if r.ContextTokens <= 0 {
		return 0, errors.New("needs a positive context_tokens, the window its upstream host serves the model with")
	}
	if r.MaxOutputTokens > r.ContextTokens {
		return 0, fmt.Errorf("has max_output_tokens %d above its context_tokens %d", r.MaxOutputTokens, r.ContextTokens)
	}
	threshold := compaction.Threshold(r.ContextTokens, r.DefaultMaxTokens)
	switch {
	case threshold <= 0:
		return 0, fmt.Errorf("has context_tokens %d, too small to hold a reply and a compaction call of %d tokens", r.ContextTokens, compaction.SummaryReserve)
	case r.CompactAtTokens == 0:
		return threshold, nil
	case r.CompactAtTokens < 0 || r.CompactAtTokens > threshold:
		return 0, fmt.Errorf("needs a compact_at_tokens between 1 and %d, so a reply and the compaction call still fit its context_tokens %d", threshold, r.ContextTokens)
	}
	return r.CompactAtTokens, nil
}

// ParsePrice parses a token-rate object as routes.json writes a tier's price: prompt, cached, and completion rates per
// million tokens, a cache-write rate that defaults to the prompt rate, and an optional long_context with its
// from_prompt_tokens. field names the object in errors.
func ParsePrice(raw json.RawMessage, field string) (money.Price, error) {
	var tp *tokenPrice
	if err := decodeStrict(raw, &tp); err != nil {
		return money.Price{}, fmt.Errorf("%s: %w", field, err)
	}
	return tp.parse(field)
}

// ParseMicrosPerCall parses {"micros_per_call": n} as routes.json writes a per-call price, from 1 to
// money.MaxMicrosPerUnit. field names the object in errors.
func ParseMicrosPerCall(raw json.RawMessage, field string) (money.Micros, error) {
	var cp *callPrice
	if err := decodeStrict(raw, &cp); err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if cp == nil || cp.MicrosPerCall == nil {
		return 0, fmt.Errorf("needs %s.micros_per_call", field)
	}
	return cp.micros(field)
}

func decodeStrict(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

func (tp *tokenPrice) parse(field string) (money.Price, error) {
	p, err := tp.price(field)
	if err != nil {
		return money.Price{}, err
	}
	if tp.FromPromptTokens != 0 {
		return money.Price{}, fmt.Errorf("sets from_prompt_tokens outside %s.long_context", field)
	}
	if err := p.Validate(); err != nil {
		return money.Price{}, fmt.Errorf("has an invalid %s: %w", field, err)
	}
	return p, nil
}

func (tp *tokenPrice) price(field string) (money.Price, error) {
	if tp == nil || tp.PromptMicrosPerMTok == nil || tp.CachedPromptMicrosPerMTok == nil || tp.CompletionMicrosPerMTok == nil {
		return money.Price{}, fmt.Errorf("needs %[1]s.prompt_micros_per_mtok, %[1]s.cached_prompt_micros_per_mtok, and %[1]s.completion_micros_per_mtok", field)
	}
	p := money.Price{
		PromptPerMTok:           *tp.PromptMicrosPerMTok,
		CachedPromptPerMTok:     *tp.CachedPromptMicrosPerMTok,
		CacheWritePromptPerMTok: *cmp.Or(tp.CacheWritePromptMicrosPerMTok, tp.PromptMicrosPerMTok),
		CompletionPerMTok:       *tp.CompletionMicrosPerMTok,
	}
	if tp.LongContext != nil {
		long, err := tp.LongContext.price(field + ".long_context")
		if err != nil {
			return money.Price{}, err
		}
		p.LongContext = &money.LongContext{FromPromptTokens: tp.LongContext.FromPromptTokens, Price: long}
	}
	return p, nil
}

func (r imageRoute) serves(defaultMarkup money.Markup) (Serves, error) {
	var perImage, perReference *money.Micros
	if r.Price != nil {
		perImage, perReference = r.Price.HoldMicrosPerImage, r.Price.HoldMicrosPerReference
	}
	price, err := r.common.mediaPrice(r.marked, defaultMarkup, perImage, "hold_micros_per_image", perReference)
	return Image{Price: price}, err
}

func (r videoRoute) serves(defaultMarkup money.Markup) (Serves, error) {
	var perSecond *money.Micros
	if r.Price != nil {
		perSecond = r.Price.HoldMicrosPerSecond
	}
	price, err := r.common.mediaPrice(r.marked, defaultMarkup, perSecond, "hold_micros_per_second", nil)
	return Video{Price: price}, err
}

func (c common) mediaPrice(m marked, defaultMarkup money.Markup, perUnit *money.Micros, perUnitField string, perReference *money.Micros) (money.MediaPrice, error) {
	if perUnit == nil {
		return money.MediaPrice{}, fmt.Errorf("of kind %s needs price.%s", c.Kind, perUnitField)
	}
	markup, err := m.markup(defaultMarkup)
	if err != nil {
		return money.MediaPrice{}, err
	}
	price := money.MediaPrice{PerUnit: *perUnit, Markup: markup}
	if perReference != nil {
		price.PerReference = *perReference
	}
	if err := price.Validate(); err != nil {
		return money.MediaPrice{}, fmt.Errorf("has an invalid price: %w", err)
	}
	return price, nil
}

func (r callRoute) serves(money.Markup) (Serves, error) {
	if r.Price == nil || r.Price.MicrosPerCall == nil {
		return nil, fmt.Errorf("of kind %s needs price.micros_per_call", r.Kind)
	}
	price, err := r.Price.micros("price")
	if err != nil {
		return nil, err
	}
	return PerCall{Call: r.Kind, Price: price}, nil
}

func (cp callPrice) micros(field string) (money.Micros, error) {
	if *cp.MicrosPerCall <= 0 || *cp.MicrosPerCall > money.MaxMicrosPerUnit {
		return 0, fmt.Errorf("%s.micros_per_call must be between 1 and %d micros", field, money.MaxMicrosPerUnit)
	}
	return *cp.MicrosPerCall, nil
}
