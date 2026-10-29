package apierr_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"morse/backend/internal/apierr"
)

const canary = "CANARY-7f3a91"

func TestSanitizedUpstreamErrorMapsStatusAndNeverCarriesVendorText(t *testing.T) {
	cases := []struct {
		status     int
		vendorBody string
		wantStatus int
		wantCode   string
	}{
		{400, `{"error":{"code":"context_length_exceeded","message":"` + canary + `"}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"type":"content_policy_violation","message":"` + canary + `"}}`, 400, "content_filter"},
		{400, `{"error":{"code":null,"message":"` + canary + `"}}`, 400, "invalid_request"},
		{400, `{"error":{"code":"invalid_prompt","message":"` + canary + `"}}`, 400, "content_filter"},
		{429, `{"error":{"code":"insufficient_quota","message":"` + canary + `"}}`, 502, "upstream_unavailable"},
		{401, `{"error":{"message":"key sk-...` + canary + `"}}`, 502, "upstream_unavailable"},
		{402, `{"errors":[{"code":"insufficientCredits","message":"top up ` + canary + `"}]}`, 502, "upstream_unavailable"},
		{403, ``, 502, "upstream_unavailable"},
		{404, `not json ` + canary, 502, "upstream_unavailable"},
		{413, ``, 413, "request_too_large"},
		{429, `{"error":{"message":"org-` + canary + ` TPM limit"}}`, 503, "upstream_busy"},
		{529, ``, 503, "upstream_busy"},
		{500, `<html>cf-ray ` + canary + `</html>`, 502, "upstream_error"},
		{502, `{"error":{"code":"context_length_exceeded"}}`, 502, "upstream_error"},
	}
	for _, tc := range cases {
		up := apierr.SanitizedUpstreamError(tc.status, []byte(tc.vendorBody))
		body := up.Envelope()
		var envelope struct {
			Error struct {
				Message string  `json:"message"`
				Type    string  `json:"type"`
				Param   *string `json:"param"`
				Code    string  `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("%d: body is not JSON: %s", tc.status, body)
		}
		if up.Status != tc.wantStatus || envelope.Error.Code != tc.wantCode || envelope.Error.Message == "" || envelope.Error.Type == "" {
			t.Errorf("%d: status %d envelope %+v", tc.status, up.Status, envelope)
		}
		if bytes.Contains(body, []byte(canary)) {
			t.Errorf("%d: vendor text reached the body: %s", tc.status, body)
		}
	}
}

func TestRefusalKeepsTheRefusalAnErrorCarriesAndFallsBackOtherwise(t *testing.T) {
	wrapped := fmt.Errorf("vendor said %s: %w", canary, apierr.ErrUpstreamBusy)
	if got, carried := apierr.Refusal(wrapped, apierr.ErrUpstream); !carried || got != apierr.ErrUpstreamBusy {
		t.Errorf("wrapped refusal: %v carried %t, want the busy refusal", got, carried)
	}
	if got, carried := apierr.Refusal(errors.New(canary), apierr.ErrUpstream); carried || got != apierr.ErrUpstream {
		t.Errorf("plain error: %v carried %t, want the fallback", got, carried)
	}
}

func TestTheConstructorsFixTheStatusAndTypeTheirFamilyShares(t *testing.T) {
	for name, c := range map[string]struct{ got, want apierr.Error }{
		"invalid":  {apierr.Invalid(404, "c", "m"), apierr.Error{Status: 404, Type: "invalid_request_error", Code: "c", Message: "m"}},
		"unfunded": {apierr.Unfunded("m"), apierr.Error{Status: 402, Type: "insufficient_balance", Code: "insufficient_balance", Message: "m"}},
		"limited":  {apierr.Limited("c", "m"), apierr.Error{Status: 429, Type: "requests", Code: "c", Message: "m"}},
	} {
		if c.got != c.want {
			t.Errorf("%s: %+v, want %+v", name, c.got, c.want)
		}
	}
}

func TestAnEnvelopeNamesItsParameterOnlyWhenAsked(t *testing.T) {
	e := apierr.Invalid(400, "invalid_request", "limit must be a whole number from 1 to 100.")
	const named = `{"error":{"message":"limit must be a whole number from 1 to 100.","type":"invalid_request_error","param":"limit","code":"invalid_request"}}`
	const unnamed = `{"error":{"message":"limit must be a whole number from 1 to 100.","type":"invalid_request_error","param":null,"code":"invalid_request"}}`
	if got := string(e.EnvelopeNaming("limit")); got != named {
		t.Errorf("EnvelopeNaming(limit) = %s, want %s", got, named)
	}
	if got := string(e.Envelope()); got != unnamed {
		t.Errorf("Envelope() = %s, want %s", got, unnamed)
	}
}
