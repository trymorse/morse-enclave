package worker

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

const floorField = "min_privacy"

var notYetTaken = []string{"allow_fallbacks", "data_collection", "enforce_distillable_text", "ignore", "max_price", "only", "order", "quantizations", "require_parameters", "sort", "zdr"}

var (
	errProviderNotObject = apierr.InvalidParameter(`provider must be an object, such as {"min_privacy":"tee"}.`)
	errFloorNotTier      = apierr.InvalidParameter("provider.min_privacy must be one of " + catalog.TierNames() + ".")
	errFloorSealed       = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_field_refused", Code: "e2ee_field_refused", Message: "Field provider.min_privacy is refused on e2ee models, which meet every privacy floor and forward the body verbatim, so leave min_privacy out of a sealed request."}
)

func floorOf(req *chat.Request) (catalog.Tier, error) {
	raw, sent := req.Field("provider")
	if !sent {
		return 0, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return 0, errProviderNotObject
	}
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		switch {
		case key == floorField:
		case slices.Contains(notYetTaken, key):
			return 0, apierr.Invalid(http.StatusBadRequest, "unsupported_parameter", fmt.Sprintf("provider.%s is not supported yet, so Morse refuses the request rather than ignore it. provider takes min_privacy alone for now.", key))
		default:
			return 0, apierr.InvalidParameter(fmt.Sprintf("provider.%s is not a field Morse takes. provider takes min_privacy alone.", key))
		}
	}
	named, ok := fields[floorField]
	if !ok {
		return 0, nil
	}
	var name string
	if json.Unmarshal(named, &name) != nil {
		return 0, errFloorNotTier
	}
	floor, err := catalog.ParseTier(name)
	if err != nil {
		return 0, errFloorNotTier
	}
	return floor, nil
}

func (r chatRoute) refuseBelow(floor catalog.Tier) error {
	if r.tier >= floor {
		return nil
	}
	return catalog.FloorError{Tier: r.tier, Floor: floor}
}

func namesFloor(provider json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(provider, &fields) != nil {
		return false
	}
	_, named := fields[floorField]
	return named
}
