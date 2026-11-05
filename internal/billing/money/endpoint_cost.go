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

const FeeAllowance Micros = 10_000

// Envelope is the most a call measured as u can cost on an endpoint listed at list when the vendor holds its prompt
// and completion rates to list, as OpenRouter's max_price does: every cached and cache-write prompt token at the
// dearer of the prompt and cache-write rates, plus FeeAllowance.
func (list Price) Envelope(u chat.Usage) Micros {
	return list.uncached().Cost(u) + FeeAllowance
}

func (p Price) uncached() Price {
	p.CacheWritePromptPerMTok = max(p.PromptPerMTok, p.CacheWritePromptPerMTok)
	p.CachedPromptPerMTok = p.CacheWritePromptPerMTok
	if long := p.LongContext; long != nil {
		p.LongContext = &LongContext{FromPromptTokens: long.FromPromptTokens, Price: long.Price.uncached()}
	}
	return p
}

type CostVerdict uint8

const (
	CostAccepted CostVerdict = iota
	BYOKUpstreamMissing
	NotACost
	AboveEnvelope
)

var costVerdictNames = enum.Names[CostVerdict]{CostAccepted: "accepted", BYOKUpstreamMissing: "byok_upstream_missing", NotACost: "not_a_cost", AboveEnvelope: "above_envelope"}

func (r CostVerdict) String() string { return costVerdictNames.String(r) }

func VendorCharged(list Price, u chat.Usage, v chat.VendorCost) (EndpointCost, CostVerdict) {
	switch {
	case v.Read == chat.CostBYOKUpstreamMissing:
		return AtList(list, u), BYOKUpstreamMissing
	case v.Read == chat.CostUnreadable || v.Read == chat.CostReported && v.Micros < 0:
		return AtList(list, u), NotACost
	case v.Read != chat.CostReported:
		return AtList(list, u), CostAccepted
	}
	if envelope := list.Envelope(u); Micros(v.Micros) > envelope {
		return EndpointCost{Micros: envelope, Source: CostEnvelope}, AboveEnvelope
	}
	return EndpointCost{Micros: Micros(v.Micros), Source: CostReported}, CostAccepted
}
