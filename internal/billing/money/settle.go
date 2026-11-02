package money

import (
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
)

type Settlement struct {
	Outcome    measure.Outcome
	Tokens     chat.Usage
	Duration   time.Duration
	Cost       Micros
	Source     measure.UsageSource
	Sides      measure.Sides
	Thinking   measure.Thinking
	Refusal    measure.RefusalCode
	Finish     chat.Finish
	ServedBy   chat.Host
	Unanswered bool
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
	return Settlement{Outcome: m.Outcome, Tokens: m.Tokens, Cost: p.Cost(charged), Source: m.Source(), Sides: m.Sides, Thinking: m.Thinking, Finish: m.Finish, Unanswered: m.Unanswered, ServedBy: m.ServedBy}
}
