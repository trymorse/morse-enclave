package baseurl

import (
	"strings"
	"testing"
)

func TestABaseURLIsHTTPSExceptOnLoopbackAndCarriesNothingButAnOriginAndPath(t *testing.T) {
	for _, ok := range []string{"https://api.together.xyz", "https://vllm.internal:8443/v1", "http://localhost:8000", "http://127.0.0.1:9", "http://[::1]:8000"} {
		u, err := Parse("base_url", "https://api.together.xyz", ok)
		if err != nil || u.String() != ok {
			t.Errorf("%s: %v %v", ok, u, err)
		}
	}
	for bad, why := range map[string]string{
		"http://vllm:8000":                 "https",
		"http://10.0.0.5:8000":             "https",
		"http://127.0.0.1.example.com":     "https",
		"ftp://api.together.xyz":           "https",
		"https://user:pw@api.together.xyz": "credentials",
		"http://user@localhost:8000":       "credentials",
		"https://api.together.xyz?key=sk":  "query",
		"https://api.together.xyz?":        "query",
		"https://api.together.xyz#v1":      "fragment",
		"https://api.together.xyz#":        "fragment",
		"https:///v1":                      "absolute URL such as https://api.together.xyz",
		"api.together.xyz/v1":              "absolute URL such as https://api.together.xyz",
	} {
		_, err := Parse("base_url", "https://api.together.xyz", bad)
		if err == nil || !strings.HasPrefix(err.Error(), "base_url ") || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: err %v, want one naming base_url and %q", bad, err, why)
		}
	}
}
