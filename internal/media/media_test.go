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
		"n zero":             `{"model":"m","prompt":"p","n":0}`,
		"n five":             `{"model":"m","prompt":"p","n":5}`,
		"openai size":        `{"model":"m","prompt":"p","size":"1024x1024"}`,
		"unknown ratio":      `{"model":"m","prompt":"p","aspect_ratio":"7:3"}`,
		"unknown resolution": `{"model":"m","prompt":"p","resolution":"8k"}`,
		"negative seed":      `{"model":"m","prompt":"p","seed":-1}`,
		"seed past int32":    `{"model":"m","prompt":"p","seed":2147483648}`,
		"long negative":      `{"model":"m","prompt":"p","negative_prompt":"` + strings.Repeat("é", 2001) + `"}`,
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
	for _, body := range []string{`{"model":`, `{"model":"m","prompt":"p","seed":1.5}`, `{"model":"m","prompt":"p","seed":"7"}`} {
		if _, err := media.ParseImageRequest(strings.NewReader(body)); err == nil {
			t.Errorf("%s accepted", body)
		}
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
	spec := media.ImageSpec{AspectRatios: media.AspectRatios, Resolutions: []string{"1k"}}
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
	if err := (media.ImageSpec{MaxReferences: 1}).CheckImages(parse(t, `{"model":"m","prompt":"p","resolution":"2k"}`)); err == nil {
		t.Error("2k accepted by a spec that lists no resolution")
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
	for dims, want := range map[[2]int]string{{1280, 720}: "16:9", {720, 1280}: "9:16", {1000, 1000}: "1:1", {1200, 900}: "4:3", {1500, 1000}: "3:2", {3000, 1000}: "21:9", {2000, 1000}: "16:9", {800, 1000}: "4:5"} {
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

func refused(t *testing.T, err error, want string) {
	t.Helper()
	var invalid strictjson.Invalid
	if !errors.As(err, &invalid) || string(invalid) != want {
		t.Errorf("err %v, want %q", err, want)
	}
}

func TestSeedNegativePromptAndMaskReachOnlyTheModelsThatTakeThem(t *testing.T) {
	src := pngOf(t, 640, 480)
	mask := pngOf(t, 640, 480)
	full := parse(t, `{"model":"m","prompt":"p","seed":2147483647,"negative_prompt":"`+promptCanary+`","images":["`+src+`"],"mask":"`+mask+`"}`)
	if full.Seed == nil || *full.Seed != media.MaxSeed || full.NegativePrompt() != promptCanary || full.Mask() != mask {
		t.Errorf("seed %v negative %q mask %v", full.Seed, full.NegativePrompt(), full.Mask() == mask)
	}
	if out := fmt.Sprintf("%v %+v %#v", full, *full, full); strings.Contains(out, promptCanary) {
		t.Errorf("the request prints its negative prompt: %s", out)
	}
	if zero := parse(t, `{"model":"m","prompt":"p","seed":0}`); zero.Seed == nil || *zero.Seed != 0 {
		t.Errorf("seed 0 lost: %v", zero.Seed)
	}
	plain := media.ImageSpec{AspectRatios: media.AspectRatios, Resolutions: []string{"1k"}, MaxReferences: 1}
	for body, want := range map[string]string{
		`{"model":"m","prompt":"p","seed":7}`:                                       "This model takes no seed.",
		`{"model":"m","prompt":"p","negative_prompt":"blur"}`:                       "This model takes no negative_prompt.",
		`{"model":"m","prompt":"p","images":["` + src + `"],"mask":"` + mask + `"}`: "This model takes no mask.",
	} {
		refused(t, plain.CheckImages(parse(t, body)), want)
	}
	short := media.ImageSpec{AspectRatios: media.AspectRatios, Resolutions: []string{"1k"}, Seed: true, NegativePrompt: 5}
	if err := short.CheckImages(parse(t, `{"model":"m","prompt":"p","seed":7,"negative_prompt":"ééééé"}`)); err != nil {
		t.Errorf("five characters refused: %v", err)
	}
	refused(t, short.CheckImages(parse(t, `{"model":"m","prompt":"p","negative_prompt":"blurry"}`)), "negative_prompt must be at most 5 characters for this model.")
}

func TestAMaskIsAPNGTheSizeOfTheFirstImage(t *testing.T) {
	src := pngOf(t, 640, 480)
	for body, want := range map[string]string{
		`{"model":"m","prompt":"p","mask":"` + pngOf(t, 640, 480) + `"}`:                                      "mask needs the image it masks in images.",
		`{"model":"m","prompt":"p","images":["` + src + `"],"mask":"` + pngOf(t, 480, 640) + `"}`:             "mask is 480x640 and must be the size of the first image, 640x480.",
		`{"model":"m","prompt":"p","images":["` + src + `"],"mask":"data:image/jpeg;base64,` + jpegB64 + `"}`: "mask must be a base64 data URL of a PNG image.",
		`{"model":"m","prompt":"p","images":["` + src + `"],"mask":"data:image/png;base64,iVBORw0K"}`:         "mask must be a base64 data URL of a PNG image.",
	} {
		_, err := media.ParseImageRequest(strings.NewReader(body))
		refused(t, err, want)
	}
	if _, err := media.ParseImageRequest(strings.NewReader(`{"model":"m","prompt":"p","images":["` + src + `"],"mask":"https://cdn.example/m.png"}`)); !errors.Is(err, apierr.ErrRemoteMedia) {
		t.Errorf("remote mask: %v", err)
	}
}

const jpegB64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q=="

func TestEachSpecFillsInTheSizeItTakesAndRefusesOneItDoesNot(t *testing.T) {
	grok := media.GrokImagine2
	if req := parse(t, `{"model":"m","prompt":"p","images":["`+pngOf(t, 800, 1000)+`"]}`); grok.CheckImages(req) != nil || req.Size.AspectRatio != "3:4" {
		t.Errorf("a 4:5 reference on a model without 4:5: %s", req.Size.AspectRatio)
	}
	if req := parse(t, `{"model":"m","prompt":"p","images":["`+pngOf(t, 800, 1000)+`"]}`); media.Flux2Pro.CheckImages(req) != nil || req.Size.AspectRatio != "4:5" {
		t.Errorf("a 4:5 reference on FLUX.2: %s", req.Size.AspectRatio)
	}
	refused(t, grok.CheckImages(parse(t, `{"model":"m","prompt":"p","aspect_ratio":"5:4"}`)), "aspect_ratio must be one of 1:1, 16:9, 9:16, 4:3, 3:4, 3:2, 2:3, 21:9 for this model.")
	refused(t, media.Flux2Pro.CheckImages(parse(t, `{"model":"m","prompt":"p","resolution":"4k"}`)), "resolution must be one of 1k, 2k for this model.")
	if req := parse(t, `{"model":"m","prompt":"p","aspect_ratio":"21:9","resolution":"4k"}`); media.NanoBananaPro.CheckImages(req) != nil || req.Size != (media.Size{AspectRatio: "21:9", Resolution: "4k"}) {
		t.Errorf("4k 21:9 on Nano Banana Pro: %+v", req.Size)
	}
	refused(t, media.Flux2Pro.CheckImages(parse(t, `{"model":"m"}`)), "prompt is required.")
	refused(t, media.Flux2Pro.CheckImages(parse(t, `{"model":"m","prompt":"  "}`)), "prompt is required.")
}

func TestToolsTakeOneImageAndDrawAtItsSize(t *testing.T) {
	small, big := pngOf(t, 1000, 750), pngOf(t, 2400, 1600)
	for spec, cases := range map[*media.ImageSpec]map[string]string{
		&media.RemoveBackground: {
			`{"model":"m"}`: "This model takes exactly one image.",
			`{"model":"m","images":["` + small + `","` + small + `"]}`:      "This model takes exactly one image.",
			`{"model":"m","n":2,"images":["` + small + `"]}`:                "This model makes one image a request; n must be 1.",
			`{"model":"m","aspect_ratio":"1:1","images":["` + small + `"]}`: "This model takes no aspect_ratio.",
			`{"model":"m","resolution":"2k","images":["` + small + `"]}`:    "This model takes no resolution.",
			`{"model":"m","seed":1,"images":["` + small + `"]}`:             "This model takes no seed.",
		},
		&media.Inpaint: {
			`{"model":"m","images":["` + small + `"],"mask":"` + pngOf(t, 1000, 750) + `"}`: "prompt is required.",
			`{"model":"m","prompt":"a cat","images":["` + small + `"]}`:                     "mask is required.",
		},
		&media.Upscale: {
			`{"model":"m","images":["` + big + `"]}`:                     "The image is already 2048 pixels or more on its long edge; ask for a larger resolution.",
			`{"model":"m","resolution":"1k","images":["` + small + `"]}`: "resolution must be one of 2k, 4k for this model.",
			`{"model":"m","images":["data:image/webp;base64,UklGRg=="]}`: "The image's size could not be read.",
		},
	} {
		for body, want := range cases {
			refused(t, spec.CheckImages(parse(t, body)), want)
		}
	}
	bg := parse(t, `{"model":"m","prompt":"ignored","images":["`+small+`"]}`)
	if err := media.RemoveBackground.CheckImages(bg); err != nil || bg.Prompt() != "" || bg.Size.Resolution != "1k" {
		t.Errorf("remove background: %v, prompt %q, priced at %s", err, bg.Prompt(), bg.Size.Resolution)
	}
	fill := parse(t, `{"model":"m","prompt":"a cat","seed":3,"images":["`+big+`"],"mask":"`+pngOf(t, 2400, 1600)+`"}`)
	if err := media.Inpaint.CheckImages(fill); err != nil || fill.Size.Resolution != "2k" || fill.Prompt() != "a cat" {
		t.Errorf("inpaint: %v, priced at %s", err, fill.Size.Resolution)
	}
	up := parse(t, `{"model":"m","images":["`+big+`"]}`)
	up4 := parse(t, `{"model":"m","resolution":"4k","images":["`+big+`"]}`)
	up2 := parse(t, `{"model":"m","images":["`+small+`"]}`)
	if media.Upscale.CheckImages(up) == nil || media.Upscale.CheckImages(up4) != nil || up4.Size.Resolution != "4k" || media.Upscale.CheckImages(up2) != nil || up2.Size.Resolution != "2k" {
		t.Errorf("upscale sizes: %s %s", up4.Size.Resolution, up2.Size.Resolution)
	}
	for dims, want := range map[[2]int]string{{1024, 1024}: "1k", {1025, 1024}: "2k", {2048, 2048}: "2k", {2049, 2048}: "4k"} {
		req := parse(t, `{"model":"m","images":["`+pngOf(t, dims[0], dims[1])+`"]}`)
		if err := media.RemoveBackground.CheckImages(req); err != nil || req.Size.Resolution != want {
			t.Errorf("%v: %v, priced at %s, want %s", dims, err, req.Size.Resolution, want)
		}
	}
}

func TestAnUpscaleTheFactorLimitCannotReachIsRefused(t *testing.T) {
	refused(t, media.Upscale.CheckImages(parse(t, `{"model":"m","resolution":"4k","images":["`+pngOf(t, 200, 100)+`"]}`)), "The image is too small to upscale to 4k; it can grow at most 10 times, to 2000 pixels on its long edge, short of every resolution this model offers.")
	refused(t, media.Upscale.CheckImages(parse(t, `{"model":"m","resolution":"4k","images":["`+pngOf(t, 300, 300)+`"]}`)), "The image is too small to upscale to 4k; the largest resolution it can reach is 2k.")
	for _, c := range []struct {
		w, h       int
		resolution string
	}{{410, 205, "4k"}, {205, 410, "2k"}} {
		req := parse(t, fmt.Sprintf(`{"model":"m","resolution":%q,"images":["%s"]}`, c.resolution, pngOf(t, c.w, c.h)))
		if err := media.Upscale.CheckImages(req); err != nil || req.Size.Resolution != c.resolution {
			t.Errorf("%dx%d at %s: %v, at %s", c.w, c.h, c.resolution, err, req.Size.Resolution)
		}
	}
}

func TestAToolThatDrawsAtItsImagesSizeRefusesAnImageOverMaxToolPixels(t *testing.T) {
	for _, spec := range []media.ImageSpec{media.RemoveBackground, media.Inpaint} {
		for dims, ok := range map[[2]int]bool{{4096, 4096}: true, {8192, 2048}: true, {4097, 4096}: false, {5000, 4000}: false} {
			image := pngOf(t, dims[0], dims[1])
			req := parse(t, `{"model":"m","prompt":"a cat","images":["`+image+`"],"mask":"`+image+`"}`)
			if spec.Tool == media.ToolRemoveBackground {
				req = parse(t, `{"model":"m","images":["`+image+`"]}`)
			}
			err := spec.CheckImages(req)
			if ok && (err != nil || req.Size.Resolution != "4k") {
				t.Errorf("%s at %v: %v, priced at %s, want taken at 4k", spec.Tool, dims, err, req.Size.Resolution)
			}
			if !ok {
				refused(t, err, fmt.Sprintf("The image is %dx%d; this model takes an image of at most 16777216 pixels, such as 4096x4096.", dims[0], dims[1]))
			}
		}
	}
}
