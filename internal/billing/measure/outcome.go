package measure

import (
	"morse/backend/internal/enum"
)

type Outcome uint8

const (
	Completed Outcome = iota
	Cancelled
	Rejected
	Failed
	Abandoned
	Exhausted
)

var outcomeNames = enum.Names[Outcome]{
	Completed: "completed",
	Cancelled: "cancelled",
	Rejected:  "rejected",
	Failed:    "failed",
	Abandoned: "abandoned",
	Exhausted: "exhausted",
}

func ParseOutcome(name string) (Outcome, bool) { return outcomeNames.Parse(name) }

func Outcomes() []Outcome { return outcomeNames.Values() }

func (o Outcome) String() string { return outcomeNames.String(o) }

func (o Outcome) MarshalText() ([]byte, error) { return outcomeNames.MarshalText(o) }

func (o *Outcome) UnmarshalText(text []byte) error { return outcomeNames.UnmarshalText(o, text) }
