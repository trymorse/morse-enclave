package xai

import (
	"net/http"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/upstream"
)

const usdPerTick = "e-10"

func endpoint(baseURL, apiKey string, client *http.Client, confirm func(header func(string) string) error) upstream.Endpoint {
	return upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client, Confirm: confirm}
}

// Confirmation is the check every chat reply on a route kept under retention must pass, or nil for none.
func Confirmation(retention catalog.Retention) func(header func(string) string) error {
	if retention != catalog.RetentionZDR {
		return nil
	}
	return confirmZeroRetention
}

func confirmZeroRetention(header func(string) string) error {
	if header("X-Zero-Data-Retention") != "true" {
		return apierr.ErrUpstreamRetention
	}
	return nil
}

type usage struct {
	CostInUSDTicks *int64 `json:"cost_in_usd_ticks"`
}

func (u usage) cost() money.Reported {
	if u.CostInUSDTicks == nil {
		return money.Reported{}
	}
	return money.ReportedUSD(strconv.FormatInt(*u.CostInUSDTicks, 10) + usdPerTick)
}
