package retryafter_test

import (
	"math"
	"net/http"
	"testing"
	"time"

	"morse/backend/internal/retryafter"
)

func TestParseReadsSecondsAndHTTPDatesAndNothingElse(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]struct {
		wait time.Duration
		ok   bool
	}{
		"30":                {30 * time.Second, true},
		" 7 ":               {7 * time.Second, true},
		"0":                 {0, true},
		"-5":                {0, false},
		"":                  {0, false},
		"soon":              {0, false},
		"1.5":               {0, false},
		"99999999999999999": {math.MaxInt64, true},
		now.Add(90 * time.Second).Format(http.TimeFormat): {90 * time.Second, true},
		now.Add(-time.Hour).Format(http.TimeFormat):       {0, true},
	} {
		wait, ok := retryafter.Parse(value, now)
		if wait != want.wait || ok != want.ok {
			t.Errorf("Parse(%q) = %v, %v, want %v, %v", value, wait, ok, want.wait, want.ok)
		}
	}
}

func TestWaitFallsBackToOtherwiseAndNeverPassesTheLimit(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		value            string
		otherwise, limit time.Duration
		want             time.Duration
	}{
		{"600", time.Second, 30 * time.Second, 30 * time.Second},
		{"", 7 * time.Second, 30 * time.Second, 7 * time.Second},
		{"garbage", 40 * time.Second, 30 * time.Second, 30 * time.Second},
		{"0", 7 * time.Second, 30 * time.Second, 0},
		{"604800", 0, 24 * time.Hour, 24 * time.Hour},
	} {
		if got := retryafter.Wait(c.value, now, c.otherwise, c.limit); got != c.want {
			t.Errorf("Wait(%q, otherwise %v, limit %v) = %v, want %v", c.value, c.otherwise, c.limit, got, c.want)
		}
	}
}
