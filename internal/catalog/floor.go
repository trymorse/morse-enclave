package catalog

import (
	"fmt"
	"net/http"

	"morse/backend/internal/apierr"
)

type FloorError struct {
	Tier, Floor Tier
	Key         bool
}

func (e FloorError) Error() string { return e.Body().Error() }

func (e FloorError) Body() apierr.Error {
	if e.Key {
		return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf("This model is tier %s, below this API key's min_privacy of %s. Choose a model of tier %s or above from GET /v1/models, or lower the key's min_privacy.", e.Tier, e.Floor, e.Floor)).Naming("key.min_privacy")
	}
	return apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", fmt.Sprintf("This model is tier %s, below the request's provider.min_privacy of %s. Choose a model of tier %s or above from GET /v1/models, or lower min_privacy.", e.Tier, e.Floor, e.Floor))
}

func (e FloorError) As(target any) bool {
	body, ok := target.(*apierr.Error)
	if ok {
		*body = e.Body()
	}
	return ok
}
