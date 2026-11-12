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
		{429, `{"error":{"code":"credit_balance_exhausted","message":"` + canary + `"}}`, 502, "upstream_unavailable"},
		{401, `{"error":{"message":"key sk-...` + canary + `"}}`, 502, "upstream_unavailable"},
		{402, `{"errors":[{"code":"insufficientCredits","message":"top up ` + canary + `"}]}`, 502, "upstream_unavailable"},
		{403, ``, 502, "upstream_refused"},
		{404, `not json ` + canary, 502, "upstream_refused"},
		{403, `{"error":{"code":"insufficient_quota","message":"` + canary + `"}}`, 502, "upstream_unavailable"},
		{403, `{"error":{"code":"model_forbidden","message":"` + canary + `","type":"gateway_error"},"request_id":"iqr_x"}`, 502, "upstream_unavailable"},
		{422, `{"error":{"code":"model_zdr_not_supported","message":"` + canary + `"}}`, 502, "upstream_unavailable"},
		{422, `{"error":{"code":"other","message":"` + canary + `"}}`, 400, "invalid_request"},
		{413, ``, 413, "request_too_large"},
		{429, `{"error":{"message":"org-` + canary + ` TPM limit"}}`, 503, "upstream_busy"},
		{529, ``, 503, "upstream_busy"},
		{500, `<html>cf-ray ` + canary + `</html>`, 502, "upstream_error"},
		{502, `{"error":{"code":"context_length_exceeded"}}`, 502, "upstream_error"},
		{400, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 208310 tokens > 200000 maximum ` + canary + `"}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"code":400,"message":"The input token count exceeds the maximum number of tokens allowed 1237083. ` + canary + `","status":"INVALID_ARGUMENT"}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"code":400,"message":"The input token count (1196265) exceeds the maximum number of tokens allowed (1048575). ` + canary + `","status":"INVALID_ARGUMENT"}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"message":"This model's maximum context length is 131072 tokens. However, your prompt contains 140000 input tokens ` + canary + `","type":"BadRequestError","param":"input_tokens","code":400}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"message":"'max_tokens' or 'max_completion_tokens' is too large: 9000. This model's maximum context length is 131072 tokens ` + canary + `","type":"BadRequestError","code":400}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"message":"Input length (140000) exceeds model's maximum context length (131072). ` + canary + `","type":"BadRequestError","code":400}}`, 400, "context_length_exceeded"},
		{400, `{"object":"error","message":"The input (140000 tokens) is longer than the model's context length (131072 tokens). ` + canary + `","type":"BadRequest","param":null,"code":400}`, 400, "context_length_exceeded"},
		{400, `{"object":"error","message":"Requested token count exceeds the model's maximum context length of 131072 tokens. ` + canary + `","type":"BadRequestError","code":400}`, 400, "context_length_exceeded"},
		{400, `{"error":{"message":"This model's maximum context length is 131072 tokens ` + canary + `","type":"invalid_request_error"}}`, 400, "context_length_exceeded"},
		{400, `{"code":"Client specified an invalid argument","error":"This model's maximum prompt length is 131072 but the request contains 537812 tokens. ` + canary + `"}`, 400, "context_length_exceeded"},
		{400, `{"error":{"code":400,"message":"This endpoint's maximum context length is 131072 tokens. ` + canary + `","metadata":{"provider_name":"Together"}}}`, 400, "context_length_exceeded"},
		{400, `{"error":{"type":"invalid_request_error","message":"` + canary + ` prompt is too long"}}`, 400, "invalid_request"},
		{400, `{"code":"Client specified an invalid argument","error":"` + canary + `"}`, 400, "invalid_request"},
		{422, `{"error":{"message":"prompt is too long ` + canary + `"}}`, 400, "invalid_request"},
		{500, `{"error":{"message":"This model's maximum context length is 131072 tokens"}}`, 502, "upstream_error"},
		{400, `{"error":{"message":"Model 'morph-nope' is not served by this endpoint; accepted models: morph-v3-fast ` + canary + `","type":"invalid_request_error"}}`, 502, "upstream_refused"},
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
	if got := string(e.Naming("limit").Envelope()); got != named {
		t.Errorf("Naming(limit).Envelope() = %s, want %s", got, named)
	}
	if got := string(e.Envelope()); got != unnamed {
		t.Errorf("Envelope() = %s, want %s", got, unnamed)
	}
}

func TestStatedWindowIsTheLimitARefusalOfAPromptAsTooLongNames(t *testing.T) {
	cases := []struct {
		shape, body string
		status      int
		want        int
	}{
		{"anthropic", `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 208310 tokens > 200000 maximum ` + canary + `"}}`, 400, 200000},
		{"gemini, bare", `{"error":{"code":400,"message":"The input token count exceeds the maximum number of tokens allowed 1237083. ` + canary + `","status":"INVALID_ARGUMENT"}}`, 400, 1237083},
		{"gemini, counted", `{"error":{"code":400,"message":"The input token count (1196265) exceeds the maximum number of tokens allowed (1048575). ` + canary + `","status":"INVALID_ARGUMENT"}}`, 400, 1048575},
		{"vllm", `{"error":{"message":"This model's maximum context length is 131072 tokens. However, your prompt contains 140000 input tokens ` + canary + `","type":"BadRequestError","param":"input_tokens","code":400}}`, 400, 131072},
		{"vllm, output", `{"error":{"message":"'max_tokens' or 'max_completion_tokens' is too large: 9000. This model's maximum context length is 65536 tokens ` + canary + `","type":"BadRequestError","code":400}}`, 400, 65536},
		{"input length", `{"error":{"message":"Input length (140000) exceeds model's maximum context length (131072). ` + canary + `","type":"BadRequestError","code":400}}`, 400, 131072},
		{"sglang", `{"object":"error","message":"The input (140000 tokens) is longer than the model's context length (98304 tokens). ` + canary + `","type":"BadRequest","param":null,"code":400}`, 400, 98304},
		{"requested count", `{"object":"error","message":"Requested token count exceeds the model's maximum context length of 32768 tokens. ` + canary + `","type":"BadRequestError","code":400}`, 400, 32768},
		{"xai", `{"code":"Client specified an invalid argument","error":"This model's maximum prompt length is 131072 but the request contains 537812 tokens. ` + canary + `"}`, 400, 131072},
		{"together", `{"error":{"code":400,"message":"This endpoint's maximum context length is 163840 tokens. ` + canary + `","metadata":{"provider_name":"Together"}}}`, 400, 163840},
		{"openai code with a stated window", `{"error":{"code":"context_length_exceeded","message":"This model's maximum context length is 128000 tokens. ` + canary + `"}}`, 400, 128000},
		{"openai code alone", `{"error":{"code":"context_length_exceeded","message":"` + canary + `"}}`, 400, 0},
		{"anthropic, no figures", `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"}}`, 400, 0},
		{"a 500 naming a window", `{"error":{"message":"This model's maximum context length is 131072 tokens"}}`, 500, 0},
		{"another 400", `{"error":{"message":"` + canary + `","type":"invalid_request_error"}}`, 400, 0},
	}
	for _, tc := range cases {
		if got := apierr.StatedWindow(tc.status, []byte(tc.body)); got != tc.want {
			t.Errorf("%s: stated window %d, want %d", tc.shape, got, tc.want)
		}
	}
}
