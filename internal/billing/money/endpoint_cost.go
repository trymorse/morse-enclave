package money

import (
	"morse/backend/internal/chat"
	"morse/backend/internal/enum"
)

type EndpointCost struct {
	Micros Micros
	Source CostSource
}

type CostSource uint8

const (
	CostUnknown CostSource = iota
	CostReported
	CostEnvelope
	CostList
)

var costSourceNames = enum.Names[CostSource]{CostReported: "reported", CostEnvelope: "envelope", CostList: "list"}

func CostSources() []CostSource { return costSourceNames.Values() }

func (s CostSource) String() string { return costSourceNames.String(s) }

func (s CostSource) Known() bool { return costSourceNames.Valid(s) }

func AtList(list Price, u chat.Usage) EndpointCost {
	return EndpointCost{Micros: list.Cost(u), Source: CostList}
}
