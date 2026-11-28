package catalog

import (
	"fmt"
	"net/http"

	"morse/backend/internal/apierr"
)

var ErrKeyE2EE = apierr.Invalid(http.StatusForbidden, "e2ee_app_only", "End-to-end encryption is not offered to API keys for now. Send the request without E2EE headers, to a model id from GET /v1/models.")

type FloorError struct {
	Tier, Floor          Tier
	Key, KeyCaller       bool
	InTheClear, Sealable bool
}

func (e FloorError) Error() string { return e.Body().Error() }

func (e FloorError) Body() apierr.Error {
	if e.Floor.Sealed() && (e.Key || e.KeyCaller) {
		return e.sealedFloorOfAKey()
	}
	inTheClear := ""
	if e.InTheClear {
		inTheClear = " at most in the clear"
	}
	if e.Key {
		lower := "or lower the key's min_privacy"
		if e.Sealable {
			lower = "lower the key's min_privacy, or seal the request to its e2ee endpoint"
		}
		return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf("This model is tier %s%s, below this API key's min_privacy of %s. Choose a model of tier %s or above from GET /v1/models, %s.", e.Tier, inTheClear, e.Floor, e.Floor, lower)).Naming("key.min_privacy")
	}
	lower := "or lower min_privacy"
	if e.Sealable {
		lower = "lower min_privacy, or seal the request to its e2ee endpoint"
	}
	return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf("This model is tier %s%s, below the request's provider.min_privacy of %s. Choose a model of tier %s or above from GET /v1/models, %s.", e.Tier, inTheClear, e.Floor, e.Floor, lower))
}

func (e FloorError) sealedFloorOfAKey() apierr.Error {
	const why = "End-to-end encryption is not offered to API keys for now, so no request from a key meets a min_privacy of %s. Lower %s to tee or below."
	if e.Key {
		return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf(why, e.Floor, "the key's min_privacy")).Naming("key.min_privacy")
	}
	return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf(why, e.Floor, "provider.min_privacy"))
}

func (e FloorError) As(target any) bool {
	body, ok := target.(*apierr.Error)
	if ok {
		*body = e.Body()
	}
	return ok
}
