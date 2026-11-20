package retryafter

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func Parse(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil {
		switch {
		case secs < 0:
			return 0, false
		case secs > int64(math.MaxInt64/time.Second):
			return math.MaxInt64, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}

func Wait(value string, now time.Time, otherwise, limit time.Duration) time.Duration {
	wait, ok := Parse(value, now)
	if !ok {
		wait = otherwise
	}
	return min(wait, limit)
}
