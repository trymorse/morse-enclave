package dialect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/dialect"
)

var marked = dialect.Dialect{
	Decode: func([]byte, func(string) bool) (dialect.Decoded, error) { return dialect.Decoded{}, nil },
	Envelope: func(e apierr.Error) []byte {
		return []byte(`{"type":"error","code":"` + e.Code + `","param":"` + e.Param + `"}`)
	},
}

func TestARefusalInTheDialectsEnvelopeStillSaysAResendCannotFixIt(t *testing.T) {
	rec := httptest.NewRecorder()
	apierr.WriteError(marked.Errors(rec), apierr.Invalid(http.StatusUnauthorized, "invalid_api_key", "Incorrect API key provided."))
	if got := rec.Header().Get(apierr.HeaderShouldRetry); got != "false" || rec.Code != http.StatusUnauthorized {
		t.Errorf("%s = %q with status %d, want false with 401", apierr.HeaderShouldRetry, got, rec.Code)
	}
	if got, want := rec.Body.String(), `{"type":"error","code":"invalid_api_key","param":""}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}
