package catalog

import (
	"fmt"

	"morse/backend/internal/enum"
)

// Place is how an endpoint serves under a public name. The named endpoint is the one the name is given to; every
// other endpoint of the name serves beside it, and no endpoint beside one has endpoints of its own.
type Place uint8

const (
	// PlaceNamed is the endpoint a public name is given to.
	PlaceNamed Place = iota
	// PlaceFallback is a later sealed endpoint of the named endpoint's model and tier, which a sealed client reseals
	// a request to.
	PlaceFallback
	// PlaceUnnamed is an endpoint of the named endpoint's tier with no name of its own, serving on the named
	// endpoint's terms.
	PlaceUnnamed
	// PlaceOnBehalf is a tee endpoint through which the worker seals a plaintext chat to the named sealed endpoint's
	// vendor for its client.
	PlaceOnBehalf
)

var placeNames = enum.Names[Place]{PlaceNamed: "named", PlaceFallback: "fallback", PlaceUnnamed: "unnamed", PlaceOnBehalf: "on-behalf"}

func (p Place) String() string { return placeNames.String(p) }

func (p Place) MarshalText() ([]byte, error) { return placeNames.MarshalText(p) }

// Describe names an endpoint at p in an error: a fallback by its attester, any other endpoint by its id.
func (p Place) Describe(attester string, endpoint EndpointID) string {
	if p == PlaceFallback {
		return "fallback " + attester
	}
	return fmt.Sprintf("%s endpoint %q", p, endpoint)
}
