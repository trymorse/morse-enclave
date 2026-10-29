package runware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/upstream"
)

var moderationMarkers = []string{"nsfw", "moderat", "safety", "contentpolicy", "content_policy", "prohibited"}

type result struct {
	TaskType        string      `json:"taskType"`
	TaskUUID        string      `json:"taskUUID"`
	Status          string      `json:"status"`
	Progress        int         `json:"progress"`
	ImageUUID       string      `json:"imageUUID"`
	ImageBase64Data string      `json:"imageBase64Data"`
	VideoUUID       string      `json:"videoUUID"`
	VideoURL        string      `json:"videoURL"`
	Cost            json.Number `json:"cost"`
}

type vendorError struct {
	Code string `json:"code"`
}

type reply struct {
	Data   []result      `json:"data"`
	Errors []vendorError `json:"errors"`
}

type getResponse struct {
	TaskType string `json:"taskType"`
	TaskUUID string `json:"taskUUID"`
}

func send(ctx context.Context, vendor upstream.Endpoint, task any, limit int64) (reply, error) {
	resp, err := vendor.Call(ctx, upstream.Request{Method: http.MethodPost, Path: "/v1", Body: jsonx.Encode([]any{task})}, limit)
	var r reply
	switch {
	case err != nil:
		return r, err
	case json.Unmarshal(resp.Body, &r) != nil && resp.Status/100 == 2:
		return reply{}, upstream.ErrMalformed
	case len(r.Errors) > 0 || resp.Status/100 != 2:
		return r, upstream.Refused{Status: resp.Status, Err: failure(resp.Status, r.Errors)}
	}
	return r, nil
}

func pollTask(taskUUID string) getResponse {
	return getResponse{TaskType: "getResponse", TaskUUID: taskUUID}
}

func moderated(errs []vendorError) bool {
	for _, e := range errs {
		code := strings.ToLower(e.Code)
		for _, p := range moderationMarkers {
			if strings.Contains(code, p) {
				return true
			}
		}
	}
	return false
}

func failure(status int, errs []vendorError) apierr.Error {
	switch {
	case moderated(errs):
		return apierr.ErrContentFilter
	case status/100 == 2:
		return apierr.ErrUpstream
	}
	return apierr.SanitizedUpstreamError(status, nil)
}

func cost(r result) money.Reported { return money.ReportedUSD(r.Cost.String()) }
