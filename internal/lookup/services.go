package lookup

import (
	"net/http"
	"net/url"
	"time"

	"morse/backend/internal/plans/limits"
)

// Service is one third-party JSON API the relay reaches. Paths are the exact paths the app's tools
// call and nothing broader: the relay is not an open proxy.
type Service struct {
	Base       string
	Paths      []string
	TTL        func(reply http.Header, now time.Time) time.Duration
	Limit      limits.SharedLimit
	AuthHeader http.Header
	AuthQuery  url.Values
}

type Keys struct {
	CoinGecko string
	OpenAlex  string
}

func Services(k Keys) map[string]Service {
	return map[string]Service{
		"wikipedia": {
			Base:  "https://en.wikipedia.org",
			Paths: []string{"/w/api.php"},
			TTL:   fixed(time.Hour),
			Limit: shared("wikipedia", 150),
		},
		"photon": {
			Base:  "https://photon.komoot.io",
			Paths: []string{"/api/"},
			TTL:   fixed(24 * time.Hour),
			Limit: shared("photon", 60),
		},
		"met": {
			Base:  "https://api.met.no",
			Paths: []string{"/weatherapi/locationforecast/2.0/complete"},
			// MET's terms ask clients not to refetch before the reply's Expires.
			TTL:   expiresOr(30 * time.Minute),
			Limit: shared("met", 600),
		},
		"frankfurter": {
			Base:  "https://api.frankfurter.dev",
			Paths: []string{"/v2/rates"},
			TTL:   fixed(time.Hour),
			Limit: shared("frankfurter", 120),
		},
		"coingecko": coinGecko(k.CoinGecko),
		"openalex":  openAlex(k.OpenAlex),
	}
}

var coinGeckoPaths = []string{"/api/v3/search", "/api/v3/simple/price", "/api/v3/coins/markets"}

func coinGecko(key string) Service {
	s := Service{Base: "https://api.coingecko.com", Paths: coinGeckoPaths, TTL: fixed(time.Minute), Limit: shared("coingecko", 10)}
	if key != "" {
		s.Base, s.Limit.RPM, s.AuthHeader = "https://pro-api.coingecko.com", 250, http.Header{"X-Cg-Pro-Api-Key": {key}}
	}
	return s
}

func openAlex(key string) Service {
	s := Service{Base: "https://api.openalex.org", Paths: []string{"/works"}, TTL: fixed(time.Hour), Limit: shared("openalex", 300)}
	if key != "" {
		s.AuthQuery = url.Values{"api_key": {key}}
	}
	return s
}

func shared(name string, rpm int) limits.SharedLimit {
	return limits.SharedLimit{Subject: "lookup/" + name, RPM: rpm}
}

func fixed(ttl time.Duration) func(http.Header, time.Time) time.Duration {
	return func(http.Header, time.Time) time.Duration { return ttl }
}

func expiresOr(fallback time.Duration) func(http.Header, time.Time) time.Duration {
	return func(reply http.Header, now time.Time) time.Duration {
		expires, err := http.ParseTime(reply.Get("Expires"))
		if err != nil {
			return fallback
		}
		return expires.Sub(now)
	}
}
