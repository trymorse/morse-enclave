package media_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"morse/backend/internal/media"
)

func TestOnlyAnHTTPSURLOnAPortlessSubdomainOfTheVendorHostIsEverFetched(t *testing.T) {
	cases := map[string]bool{
		"https://v3b.HOST/files/b/0aac9be9/5UTyhFu8-0ZejBXvYb-Xo_minimax-h3.mp4": true,
		"https://v3.HOST/files/b/x.mp4":                                          true,
		"https://v3b.HOST/x.mp4?token=1#t=2":                                     true,
		"http://v3b.HOST/files/x.mp4":                                            false,
		"https://user:pw@v3b.HOST/x.mp4":                                         false,
		"https://user@v3b.HOST/x.mp4":                                            false,
		"https://v3b.HOST:443/x.mp4":                                             false,
		"https://v3b.HOST:8443/x.mp4":                                            false,
		"https://v3b.HOST:/x.mp4":                                                false,
		"https://HOST/x.mp4":                                                     false,
		"https://.HOST/x.mp4":                                                    false,
		"https://evilHOST/x.mp4":                                                 false,
		"https://HOST.attacker.example/x.mp4":                                    false,
		"https://v3b.HOST.attacker.example/x.mp4":                                false,
		"https://attacker.example/v3b.HOST/x.mp4":                                false,
		"https://attacker.example/x.mp4?h=v3b.HOST":                              false,
		"https://v3b.HOST./x.mp4":                                                false,
		"https://V3B.UPPERHOST/x.mp4":                                            false,
		"https://169.254.169.254/latest":                                         false,
		"https://[::1]/x.mp4":                                                    false,
		"ftp://v3b.HOST/x.mp4":                                                   false,
		"//v3b.HOST/x.mp4":                                                       false,
		"v3b.HOST/x.mp4":                                                         false,
		"https:v3b.HOST/x.mp4":                                                   false,
		"":                                                                       false,
		"https://v3b.HOST\x00/x.mp4":                                             false,
	}
	for _, host := range []string{"fal.media", "runware.ai"} {
		guard := media.VendorHosted{HostSuffix: "." + host}
		for raw, ok := range cases {
			url := strings.ReplaceAll(strings.ReplaceAll(raw, "UPPERHOST", strings.ToUpper(host)), "HOST", host)
			if guard.Accepts(url) != ok {
				t.Errorf("%s: %q: %v", host, url, !ok)
			}
		}
	}
}

func TestOpenVideoRefusesARejectedURLWithoutARequestAndDiscardIsANoOp(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	v := media.VendorHosted{Client: srv.Client(), HostSuffix: ".fal.media"}
	for _, raw := range []string{srv.URL + "/v.mp4", "http://v3b.fal.media/v.mp4", "https://user:key@v3b.fal.media/v.mp4", "https://v3b.fal.media:8443/v.mp4", ""} {
		if rc, _, err := v.OpenVideo(context.Background(), media.Output{URL: raw}); !errors.Is(err, media.ErrVideoGone) || rc != nil {
			t.Errorf("%q: open err %v", raw, err)
		}
	}
	if hits != 0 {
		t.Errorf("%d requests made for refused URLs", hits)
	}
}
