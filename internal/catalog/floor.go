package catalog

import (
	"fmt"
	"net/http"

	"morse/backend/internal/apierr"
)

type FloorError struct {
	Tier, Floor          Tier
	Key                  bool
	InTheClear, Sealable bool
}

func (e FloorError) Error() string { return e.Body().Error() }

func (e FloorError) Body() apierr.Error {
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

func (e FloorError) As(target any) bool {
	body, ok := target.(*apierr.Error)
	if ok {
		*body = e.Body()
	}
	return ok
}
