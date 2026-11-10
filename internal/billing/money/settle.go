package money

import (
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

type Settlement struct {
	Outcome      measure.Outcome
	Tokens       chat.Usage
	Duration     time.Duration
	Cost         Micros
	Source       measure.UsageSource
	Sides        measure.Sides
	Thinking     measure.Thinking
	Refusal      measure.RefusalCode
	Finish       chat.Finish
	Unanswered   bool
	Endpoint     catalog.EndpointID
	Tier         catalog.Tier
	EndpointCost EndpointCost
	Provider     string
	Placement    Placement
	PrivacyVeil  VeilCharge
}

// VeilCharge is what a chat's Privacy Veil cost: the filter's billable calls and tokens, how long its scan took, the
// part of Cost the caller paid for it, and what Morse paid Tinfoil.
type VeilCharge struct {
	Calls, Tokens int
	Millis        int64
	Micros        Micros
	Cost          Micros
}

func Unbilled(o measure.Outcome) Settlement { return Settlement{Outcome: o, Source: measure.UsageNone} }

func AtHold(o measure.Outcome, hold Micros) Settlement {
	return Settlement{Outcome: o, Cost: hold, Source: measure.UsageHold}
}

func Voided(took time.Duration) Settlement {
	voided := Unbilled(measure.Failed)
	voided.Duration = took
	return voided
}

func (p Price) Bill(m measure.Measurement) Settlement {
	charged := m.Tokens
	if m.Unanswered {
		charged.CompletionTokens = 0
	}
	return Settlement{Outcome: m.Outcome, Tokens: m.Tokens, Cost: p.Cost(charged), Source: m.Source(), Sides: m.Sides, Thinking: m.Thinking, Finish: m.Finish, Unanswered: m.Unanswered}
}
