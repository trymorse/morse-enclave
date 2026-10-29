package media_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
)

const (
	promptCanary = "PROMPT-CANARY-5e1f"
	pngBase64    = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)

func parse(t *testing.T, body string) *media.ImageRequest {
	t.Helper()
	req, err := media.ParseImageRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return req
}

func TestParseAppliesDefaultsAndKeepsThePromptAndReferencesPrivate(t *testing.T) {
	req := parse(t, `{"model":"flux-2-pro","prompt":"`+promptCanary+`","images":["data:image/png;base64,`+pngBase64+`"]}`)
	if req.Model != "flux-2-pro" || req.N != 1 || req.Size != (media.Size{AspectRatio: "1:1", Resolution: "1k"}) || req.Quality != "" {
		t.Errorf("request %+v", req)
	}
	if req.Prompt() != promptCanary || len(req.References()) != 1 {
		t.Errorf("prompt %q references %d", req.Prompt(), len(req.References()))
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(format, req) + fmt.Sprintf(format, *req); strings.Contains(out, promptCanary) || strings.Contains(out, pngBase64) {
			t.Errorf("%s leaks the prompt or a reference: %s", format, out)
		}
	}
	full := parse(t, `{"model":"m","prompt":"p","n":4,"aspect_ratio":"16:9","resolution":"2k","quality":"low","response_format":"b64_json"}`)
	if full.N != 4 || full.Size != (media.Size{AspectRatio: "16:9", Resolution: "2k"}) || full.Quality != "low" {
		t.Errorf("request %+v", full)
	}
}

func TestReferencesAndFramesAreKeptWithALowercaseHeaderWhateverCaseTheClientSent(t *testing.T) {
	want := "data:image/png;base64," + pngBase64
	req := parse(t, `{"model":"m","prompt":"p","images":["DATA:Image/PNG;Base64,`+pngBase64+`","`+want+`"]}`)
	if refs := req.References(); len(refs) != 2 || refs[0] != want || refs[1] != want {
		t.Errorf("references %q", refs)
	}
	video := parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"image":"Data:image/png;BASE64,`+pngBase64+`","last_image":"DATA:IMAGE/PNG;BASE64,`+pngBase64+`"}`)
	if video.FirstFrame() != want || video.LastFrame() != want {
		t.Errorf("frames %q %q", video.FirstFrame(), video.LastFrame())
	}
}

func TestImageAndVideoBodiesRefuseRepeatedAndCaseVariantKeys(t *testing.T) {
	image := func(body string) error { _, err := media.ParseImageRequest(strings.NewReader(body)); return err }
	video := func(body string) error { _, err := media.ParseVideoRequest(strings.NewReader(body)); return err }
	for name, c := range map[string]struct {
		parse             func(string) error
		repeated, variant string
	}{
		"image": {image, `{"model":"m","prompt":"a","prompt":"b"}`, `{"model":"m","Prompt":"b"}`},
		"video": {video, `{"model":"m","prompt":"a","seconds":5,"prompt":"b"}`, `{"model":"m","Prompt":"b","seconds":5}`},
	} {
		if err := c.parse(c.repeated); !errors.Is(err, strictjson.ErrDuplicateKey) {
			t.Errorf("%s with a repeated prompt: err %v, want %v", name, err, strictjson.ErrDuplicateKey)
		}
		var invalid strictjson.Invalid
		if err := c.parse(c.variant); !errors.As(err, &invalid) || string(invalid) != `Unknown field "Prompt".` {
			t.Errorf("%s with a case-variant prompt: err %v, want it refused as an unknown field", name, err)
		}
	}
}

func TestParseRefusesWhatTheProxyCannotServe(t *testing.T) {
	for name, body := range map[string]string{
		"no model":           `{"prompt":"p"}`,
		"blank prompt":       `{"model":"m","prompt":"  "}`,
		"n zero":             `{"model":"m","prompt":"p","n":0}`,
		"n five":             `{"model":"m","prompt":"p","n":5}`,
		"openai size":        `{"model":"m","prompt":"p","size":"1024x1024"}`,
		"unknown ratio":      `{"model":"m","prompt":"p","aspect_ratio":"5:4"}`,
		"unknown resolution": `{"model":"m","prompt":"p","resolution":"4k"}`,
		"url output":         `{"model":"m","prompt":"p","response_format":"url"}`,
		"user field":         `{"model":"m","prompt":"p","user":"u-1"}`,
		"svg reference":      `{"model":"m","prompt":"p","images":["data:image/svg+xml;base64,PHN2Zz4="]}`,
		"bad base64":         `{"model":"m","prompt":"p","images":["data:image/png;base64,***"]}`,
		"two objects":        `{"model":"m","prompt":"p"}{}`,
	} {
		_, err := media.ParseImageRequest(strings.NewReader(body))
		var invalid strictjson.Invalid
		if !errors.As(err, &invalid) {
			t.Errorf("%s: err %v, want strictjson.Invalid", name, err)
		}
	}
	for _, ref := range []string{"https://cdn.example/cat.png?uid=1", "file:///etc/passwd", "UUID-1234"} {
		if _, err := media.ParseImageRequest(strings.NewReader(`{"model":"m","prompt":"p","images":["` + ref + `"]}`)); !errors.Is(err, apierr.ErrRemoteMedia) {
			t.Errorf("%s: err %v, want ErrRemoteMedia", ref, err)
		}
	}
	if _, err := media.ParseImageRequest(strings.NewReader(`{"model":`)); err == nil {
		t.Error("truncated JSON accepted")
	}
}

func TestSpecCheckLimitsReferencesAndQuality(t *testing.T) {
	spec := media.ImageSpec{MaxReferences: 1, Qualities: []string{"low", "high"}}
	ref := `"data:image/png;base64,` + pngBase64 + `"`
	if err := spec.CheckImages(parse(t, `{"model":"m","prompt":"p","quality":"high","images":[`+ref+`]}`)); err != nil {
		t.Errorf("valid request refused: %v", err)
	}
	for _, body := range []string{
		`{"model":"m","prompt":"p","images":[` + ref + `,` + ref + `]}`,
		`{"model":"m","prompt":"p","quality":"ultra"}`,
	} {
		if err := spec.CheckImages(parse(t, body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
	if err := (media.ImageSpec{MaxReferences: 1}).CheckImages(parse(t, `{"model":"m","prompt":"p","quality":"low"}`)); err == nil {
		t.Error("quality accepted by a model without one")
	}
}

func TestSpecCanRefuseEveryReferenceAndLimitResolutions(t *testing.T) {
	ref := `"data:image/png;base64,` + pngBase64 + `"`
	spec := media.ImageSpec{Resolutions: []string{"1k"}}
	if err := spec.CheckImages(parse(t, `{"model":"m","prompt":"p","aspect_ratio":"16:9"}`)); err != nil {
		t.Errorf("1k refused: %v", err)
	}
	for body, want := range map[string]string{
		`{"model":"m","prompt":"p","images":[` + ref + `]}`: "This model takes no reference images.",
		`{"model":"m","prompt":"p","resolution":"2k"}`:      "resolution must be one of 1k for this model.",
	} {
		var invalid strictjson.Invalid
		if err := spec.CheckImages(parse(t, body)); !errors.As(err, &invalid) || string(invalid) != want {
			t.Errorf("%s: err %v, want %q", body, err, want)
		}
	}
	if err := (media.ImageSpec{MaxReferences: 1}).CheckImages(parse(t, `{"model":"m","prompt":"p","resolution":"2k"}`)); err != nil {
		t.Errorf("2k refused by a spec without a resolution list: %v", err)
	}
}

func TestNewImageAcceptsOnlyRealImagesAndWriteImagesBuildsTheProxyEnvelope(t *testing.T) {
	img, err := media.NewImage(pngBase64)
	if err != nil || img.MIME() != "image/png" {
		t.Fatalf("png: %v %s", err, img.MIME())
	}
	for _, bad := range []string{base64.StdEncoding.EncodeToString([]byte("https://cdn.vendor/img.png")), "not base64", ""} {
		if _, err := media.NewImage(bad); !errors.Is(err, upstream.ErrMalformed) {
			t.Errorf("%q accepted", bad)
		}
	}
	raw, _ := base64.StdEncoding.DecodeString(pngBase64)
	if fromBytes, err := media.ImageOf(raw); err != nil || fromBytes.MIME() != "image/png" {
		t.Errorf("png bytes: %v", err)
	}
	if _, err := media.ImageOf([]byte(`{"error":"x"}`)); !errors.Is(err, upstream.ErrMalformed) {
		t.Error("JSON bytes accepted as an image")
	}
	var out bytes.Buffer
	if err := media.WriteImages(&out, time.Unix(1790000000, 0), []media.Image{img, img}); err != nil {
		t.Fatal(err)
	}
	want := `{"created":1790000000,"data":[{"b64_json":"` + pngBase64 + `","mime_type":"image/png"},{"b64_json":"` + pngBase64 + `","mime_type":"image/png"}]}`
	if out.String() != want {
		t.Errorf("envelope %s", out.String())
	}
	var parsed map[string]any
	if json.Unmarshal(out.Bytes(), &parsed) != nil {
		t.Error("envelope is not JSON")
	}
}

func pngOf(t *testing.T, w, h int) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestAnEditWithoutAnAspectRatioKeepsTheReferencesShape(t *testing.T) {
	for dims, want := range map[[2]int]string{{1280, 720}: "16:9", {720, 1280}: "9:16", {1000, 1000}: "1:1", {1200, 900}: "4:3", {1500, 1000}: "3:2", {3000, 1000}: "16:9"} {
		req := parse(t, `{"model":"m","prompt":"p","images":["`+pngOf(t, dims[0], dims[1])+`"]}`)
		if req.Size.AspectRatio != want {
			t.Errorf("%v: aspect ratio %s, want %s", dims, req.Size.AspectRatio, want)
		}
	}
	if req := parse(t, `{"model":"m","prompt":"p","aspect_ratio":"2:3","images":["`+pngOf(t, 1280, 720)+`"]}`); req.Size.AspectRatio != "2:3" {
		t.Errorf("explicit ratio overridden: %s", req.Size.AspectRatio)
	}
	if req := parse(t, `{"model":"m","prompt":"p","images":["data:image/webp;base64,UklGRg=="]}`); req.Size.AspectRatio != "1:1" {
		t.Errorf("undecodable reference: %s", req.Size.AspectRatio)
	}
}

func webpOf(t *testing.T, chunk string, w, h int) string {
	t.Helper()
	b := make([]byte, 30)
	copy(b, "RIFF")
	copy(b[8:], "WEBP")
	copy(b[12:], chunk)
	switch chunk {
	case "VP8X":
		for i, v := range []int{w - 1, h - 1} {
			b[24+3*i], b[25+3*i], b[26+3*i] = byte(v), byte(v>>8), byte(v>>16)
		}
	case "VP8L":
		b[20] = 0x2f
		bits := uint32(w-1) | uint32(h-1)<<14
		b[21], b[22], b[23], b[24] = byte(bits), byte(bits>>8), byte(bits>>16), byte(bits>>24)
	}
	return "data:image/webp;base64," + base64.StdEncoding.EncodeToString(b)
}

func TestWebPReferencesAlsoSetTheAspectRatio(t *testing.T) {
	if req := parse(t, `{"model":"m","prompt":"p","images":["`+webpOf(t, "VP8X", 720, 1280)+`"]}`); req.Size.AspectRatio != "9:16" {
		t.Errorf("VP8X: %s", req.Size.AspectRatio)
	}
	if req := parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"image":"`+webpOf(t, "VP8L", 1280, 720)+`"}`); req.AspectRatio != "16:9" {
		t.Errorf("VP8L: %s", req.AspectRatio)
	}
}

func TestADownloadFollowsNoRedirectAndCarriesNoGoUserAgent(t *testing.T) {
	followed := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed++ }))
	defer elsewhere.Close()
	var agents []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.Header.Get("User-Agent"))
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	if body, _, err := media.Stream(context.Background(), &http.Client{}, origin.URL+"/video.mp4", nil); err == nil {
		body.Close()
		t.Error("a redirected download was served")
	}
	if followed != 0 || len(agents) != 1 || agents[0] != "" {
		t.Errorf("followed %d redirects, user agents %q; want none followed and a blank agent", followed, agents)
	}
}
