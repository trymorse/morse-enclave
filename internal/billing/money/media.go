package money

import (
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/enum"
	"slices"
)

const (
	MaxMicrosPerUnit   Micros = 10_000_000
	MinMicrosPerOutput        = MicrosPerCredit
	microsPerUSD              = 1_000_000
)

type MediaPrice struct {
	PerUnit      Micros
	PerUnitAt    map[string]Micros `json:",omitempty"`
	PerReference Micros
	Markup       Markup
	// why: a clip with reference pictures bills by what the vendor lists for them, which for some models is a
	// higher rate per second (WithReferencesAt, by resolution, where it differs from PerUnitAt) and a flat charge
	// for each picture past the first FreeReferencePictures (PerReferencePicture).
	WithReferencesAt      map[string]Micros `json:",omitempty"`
	PerReferencePicture   Micros            `json:",omitempty"`
	FreeReferencePictures int               `json:",omitempty"`
}

func (p MediaPrice) Validate() error {
	rates := append([]Micros{p.PerUnit, p.PerReference, p.PerReferencePicture}, slices.Collect(maps.Values(p.PerUnitAt))...)
	for _, rate := range append(rates, slices.Collect(maps.Values(p.WithReferencesAt))...) {
		if rate < 0 || rate > MaxMicrosPerUnit {
			return errors.New("media hold prices must be between 0 and 10000000 micros")
		}
	}
	if p.PerUnit == 0 || slices.Contains(slices.Collect(maps.Values(p.PerUnitAt)), 0) {
		return errors.New("media routes need a positive hold price per unit")
	}
	if slices.Contains(slices.Collect(maps.Values(p.WithReferencesAt)), 0) {
		return errors.New("a rate with reference pictures must be positive, or left out to fall back to the base rate")
	}
	if p.FreeReferencePictures < 0 {
		return errors.New("free reference pictures can't be negative")
	}
	return nil
}

func (p MediaPrice) At(resolution string) MediaPrice {
	switch rate, ok := p.PerUnitAt[resolution]; {
	case ok:
		p.PerUnit = rate
	case resolution == "":
		p.PerUnit = max(p.PerUnit, slices.Max(append(slices.Collect(maps.Values(p.PerUnitAt)), 0)))
	}
	p.PerUnitAt = nil
	return p
}

func (p MediaPrice) Hold(units, references, outputs int) Micros {
	return max(p.Markup.Of(Micros(units)*(p.PerUnit+Micros(references)*p.PerReference)), minimumFor(outputs))
}

func (p MediaPrice) HoldClip(resolution string, seconds, pictures int) Micros {
	rate := p.At(resolution).PerUnit
	if rated, ok := p.WithReferencesAt[resolution]; ok && pictures > 0 {
		rate = rated
	}
	extra := Micros(max(pictures-max(p.FreeReferencePictures, 0), 0)) * p.PerReferencePicture
	return max(p.Markup.Of(Micros(seconds)*rate+extra), minimumFor(1))
}

func (p MediaPrice) Settle(o measure.Outcome, r Reported, delivered int, hold Micros) Settlement {
	switch {
	case r.known == costUnpriced:
		return AtHold(o, hold)
	case r.known == costKnown:
		return Settlement{Outcome: o, Cost: max(p.Markup.Of(r.micros), minimumFor(delivered)), Source: measure.UsageReported, EndpointCost: EndpointCost{Micros: r.micros, Source: CostReported}}
	case delivered > 0:
		return AtHold(o, hold)
	}
	return Unbilled(o)
}

func minimumFor(outputs int) Micros { return Micros(max(outputs, 0)) * MinMicrosPerOutput }

func ReportedUSD(usd string) Reported { return ReportedUnits(usd, microsPerUSD) }

// fal's units header is a Python float repr. Seen live: 1.5, 30, and 2.4000000000000004 for 3 s
// at 0.8 units a second.
func ReportedUnits(units string, perUnit Micros) Reported {
	r, ok := new(big.Rat).SetString(units)
	if !ok || r.Sign() < 0 || perUnit < 0 {
		return Reported{}
	}
	r.Mul(r, big.NewRat(int64(perUnit), 1))
	q, rem := new(big.Int).QuoRem(r.Num(), r.Denom(), new(big.Int))
	if rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return Reported{}
	}
	return ReportedCost(Micros(q.Int64()))
}

type costKnowledge uint8

const (
	costNone costKnowledge = iota
	costKnown
	costUnpriced
)

type Reported struct {
	micros Micros
	known  costKnowledge
}

func ReportedCost(micros Micros) Reported { return Reported{micros: micros, known: costKnown} }

func (r Reported) Delivered() Reported {
	if r.known == costNone {
		r.known = costUnpriced
	}
	return r
}

func (r Reported) Micros() (Micros, bool) { return r.micros, r.known != costUnpriced }

func (r Reported) Add(other Reported) Reported {
	return Reported{micros: r.micros + other.micros, known: max(r.known, other.known)}
}

var costKnowledgeNames = enum.Names[costKnowledge]{costNone: "none", costKnown: "known", costUnpriced: "unpriced"}

func (k costKnowledge) MarshalText() ([]byte, error) { return costKnowledgeNames.MarshalText(k) }

func (k *costKnowledge) UnmarshalText(text []byte) error {
	return costKnowledgeNames.UnmarshalText(k, text)
}

type reportedJSON struct {
	Micros Micros        `json:"micros"`
	Known  costKnowledge `json:"known"`
}

func (r Reported) MarshalJSON() ([]byte, error) { return json.Marshal(reportedJSON{r.micros, r.known}) }

func (r *Reported) UnmarshalJSON(data []byte) error {
	var j reportedJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	*r = Reported{micros: j.Micros, known: j.Known}
	return nil
}
