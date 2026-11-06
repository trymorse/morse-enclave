package money

import "morse/backend/internal/enum"

// Placement is why a charge went where it went, what charges.placement stores. PlacementNone is NULL.
type Placement uint8

const (
	PlacementNone Placement = iota
	PlacedDeclared
	PlacedHome
	PlacedSpread
	PlacedCanary
	PlacedFailover
	PlacedFallback
)

var placementNames = enum.Names[Placement]{PlacedDeclared: "declared", PlacedHome: "home", PlacedSpread: "spread", PlacedCanary: "canary", PlacedFailover: "failover", PlacedFallback: "fallback"}

func Placements() []Placement { return placementNames.Values() }

func (p Placement) String() string { return placementNames.String(p) }

func (p Placement) Valid() bool { return placementNames.Valid(p) }
