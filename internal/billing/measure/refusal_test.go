package measure_test

import (
	"errors"
	"fmt"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
)

func TestARefusalIsStoredByItsListedCodeAndAnyOtherCodeAsOther(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"a content filter":            {apierr.ErrContentFilter, "content_filter"},
		"a wrapped vendor busy":       {fmt.Errorf("fal: %w", apierr.ErrUpstreamBusy), "upstream_busy"},
		"an invalid parameter":        {apierr.InvalidParameter("size"), "invalid_parameter"},
		"vendor code text":            {apierr.Error{Status: 400, Code: "Rate limit exceeded for org-123"}, "other"},
		"a code no refusal is stored": {apierr.ErrModelNotFound, "other"},
	} {
		if got := measure.RefusalCodeOf(tc.err).String(); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
	for _, err := range []error{nil, errors.New("connection reset")} {
		if got := measure.RefusalCodeOf(err); got != measure.NoRefusal {
			t.Errorf("%v: %s, want no refusal", err, got)
		}
	}
}
