package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"morse/backend/internal/catalog"
)

func TestARouteBelowTheRequestsFloorIsRefusedWithItsPinnedStatusAndBody(t *testing.T) {
	for _, c := range []struct {
		tier, floor catalog.Tier
		want        string
	}{
		{catalog.Anon, catalog.Private, `{"error":{"message":"This model is tier anon, below the request's provider.min_privacy of private. Choose a model of tier private or above from GET /v1/models, or lower min_privacy.","type":"invalid_request_error","param":null,"code":"privacy_floor_unmet"}}`},
		{catalog.Private, catalog.TEE, `{"error":{"message":"This model is tier private, below the request's provider.min_privacy of tee. Choose a model of tier tee or above from GET /v1/models, or lower min_privacy.","type":"invalid_request_error","param":null,"code":"privacy_floor_unmet"}}`},
	} {
		w := httptest.NewRecorder()
		refuse(context.Background(), w, chatRoute{tier: c.tier}.refuseBelow(c.floor))
		if w.Code != http.StatusBadRequest || w.Body.String() != c.want {
			t.Errorf("tier %s under floor %s answered %d %q, want 400 %q", c.tier, c.floor, w.Code, w.Body.String(), c.want)
		}
	}
	if err := (chatRoute{tier: catalog.TEE}).refuseBelow(catalog.Private); err != nil {
		t.Errorf("a route at or above the floor was refused: %v", err)
	}
}
