package apierr_test

import (
	"net/http/httptest"
	"testing"

	"morse/backend/internal/apierr"
)

func TestARefusalAResendCannotFixSaysSoAndOneItMayFixDoesNot(t *testing.T) {
	for status, want := range map[int]string{400: "false", 401: "false", 403: "false", 404: "false", 413: "false", 422: "false", 402: "", 409: "", 429: "", 500: "", 502: "", 503: ""} {
		rec := httptest.NewRecorder()
		apierr.WriteError(rec, apierr.Error{Status: status, Type: "t", Code: "c", Message: "m"})
		if got := rec.Header().Get(apierr.HeaderShouldRetry); got != want || rec.Code != status {
			t.Errorf("status %d: %s = %q with status %d, want %q", status, apierr.HeaderShouldRetry, got, rec.Code, want)
		}
	}
}
