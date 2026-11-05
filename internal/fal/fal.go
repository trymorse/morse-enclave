package fal

import (
	"cmp"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

const (
	outputTTL = media.VendorKeep
	// A failed request also reports COMPLETED, with the error on the result. Status is not monotonic:
	// fal moves a request back to IN_QUEUE when it retries.
	completed        = "COMPLETED"
	contentPolicy    = "content_policy_violation"
	requestIDHeader  = "X-Fal-Request-Id"
	billableUnitsKey = "X-Fal-Billable-Units"
	unitDigits       = 12
	cancelTimeout    = 3 * time.Second
)

var (
	requestID     = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)
	billableUnits = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,20})?([eE]-[0-9]{1,2})?$`)
	lifecycle     = `{"expiration_duration_seconds":` + strconv.Itoa(int(outputTTL/time.Second)) + `}`
)

type client struct{ vendor upstream.Endpoint }

func newClient(baseURL, apiKey string, httpClient *http.Client) client {
	return client{upstream.Endpoint{BaseURL: baseURL, Auth: http.Header{"Authorization": {"Key " + apiKey}}, HTTP: httpClient, Refuse: func(r upstream.Reply) error {
		return failure(r.Status, r.Body)
	}}}
}

type queueStatus struct {
	Status string          `json:"status"`
	Error  json.RawMessage `json:"error"`
}

func (s queueStatus) failed() bool {
	e := strings.TrimSpace(string(s.Error))
	return e != "" && e != "null" && e != `""`
}

type vendorDetail struct {
	Type string `json:"type"`
}

type result struct {
	upstream.Reply
	cost money.Reported
}

func (c client) submit(ctx context.Context, endpoint string, input any, startBy time.Duration) (string, error) {
	h := http.Header{}
	h.Set("X-Fal-Store-IO", "0")
	h.Set("X-Fal-Object-Lifecycle-Preference", lifecycle)
	h.Set("X-App-Fal-Disable-Fallback", "true")
	h.Set("X-Fal-Request-Timeout", strconv.FormatInt(int64(startBy/time.Second), 10))
	var submitted struct {
		RequestID string `json:"request_id"`
	}
	if _, err := c.vendor.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: "/" + endpoint, Header: h, Body: jsonx.Encode(input)}, &submitted, media.MaxReplyBody); err != nil {
		return "", err
	}
	if !validID(submitted.RequestID) {
		return "", upstream.ErrMalformed
	}
	return submitted.RequestID, nil
}

func (c client) result(ctx context.Context, app, id string, limit int64, unit money.Micros) (result, error) {
	reply, err := c.vendor.Call(ctx, upstream.Request{Method: http.MethodGet, Path: requestPath(app, id)}, limit)
	if err != nil {
		return result{}, err
	}
	return result{Reply: reply, cost: cost(reply.Header.Get(billableUnitsKey), unit)}, nil
}

type outcome uint8

const (
	stillQueued outcome = iota
	finalFailure
	delivered
)

func (c client) await(ctx context.Context, app, id string, limit int64, unit money.Micros) (outcome, result, error) {
	var s queueStatus
	if _, err := c.vendor.JSON(ctx, upstream.Request{Method: http.MethodGet, Path: requestPath(app, id) + "/status"}, &s, media.MaxReplyBody); err != nil {
		return stillQueued, result{}, err
	}
	if s.Status != completed {
		return stillQueued, result{}, nil
	}
	r, err := c.result(ctx, app, id, limit, unit)
	switch {
	case err != nil:
		return stillQueued, result{}, err
	case r.ok():
		return delivered, r, nil
	case r.terminal(s.failed()):
		return finalFailure, r, failure(r.Status, r.Body)
	}
	return stillQueued, r, failure(r.Status, r.Body)
}

// fal never runs a cancelled request still in its queue; one already running may still finish and bill.
func (c client) cancel(ctx context.Context, app, id string) {
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
	defer stop()
	c.vendor.Call(ctx, upstream.Request{Method: http.MethodPut, Path: requestPath(app, id) + "/cancel"}, media.MaxReplyBody)
}

func requestPath(app, id string) string {
	return "/" + app + "/requests/" + url.PathEscape(id)
}

func (r result) ok() bool { return r.Status/100 == 2 }

func (r result) terminal(statusFailed bool) bool {
	switch {
	case statusFailed:
		return true
	case r.Status == http.StatusRequestTimeout || r.Status == http.StatusTooManyRequests:
		return false
	case r.Status/100 == 4:
		return true
	}
	return r.Header.Get(requestIDHeader) != ""
}

func failure(status int, body []byte) apierr.Error {
	var reply struct {
		Detail    json.RawMessage `json:"detail"`
		ErrorType string          `json:"error_type"`
	}
	json.Unmarshal(body, &reply)
	var details []vendorDetail
	json.Unmarshal(reply.Detail, &details)
	if reply.ErrorType == contentPolicy || slices.Contains(details, vendorDetail{Type: contentPolicy}) {
		return apierr.ErrContentFilter
	}
	if status == http.StatusForbidden || status == http.StatusNotFound {
		return apierr.ErrUpstreamUnavailable
	}
	return apierr.SanitizedUpstreamError(status, nil)
}

func app(endpoint string) string {
	parts := strings.SplitN(endpoint, "/", 3)
	return strings.Join(parts[:min(len(parts), 2)], "/")
}

func validID(id string) bool { return requestID.MatchString(id) }

func cost(units string, unit money.Micros) money.Reported {
	if !billableUnits.MatchString(units) {
		return money.Reported{}
	}
	return money.ReportedUnits(significant(units, unitDigits), unit)
}

func significant(units string, digits int) string {
	mantissa, exponent, _ := strings.Cut(strings.ToLower(units), "e")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	n, _ := new(big.Int).SetString(whole+fraction, 10)
	shift, _ := strconv.Atoi(cmp.Or(exponent, "0"))
	shift -= len(fraction)
	if drop := len(n.String()) - digits; drop > 0 {
		step := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(drop)), nil)
		q, rem := new(big.Int).QuoRem(n, step, new(big.Int))
		if half := rem.Lsh(rem, 1).Cmp(step); half > 0 || half == 0 && q.Bit(0) == 1 {
			q.Add(q, big.NewInt(1))
		}
		n, shift = q, shift+drop
	}
	return n.String() + "e" + strconv.Itoa(shift)
}

func startBy(deadline time.Time) time.Duration {
	return max(time.Until(deadline)/2, time.Second)
}
