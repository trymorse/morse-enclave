package media_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/frameconsent"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
)

func parseVideo(t *testing.T, body string) *media.VideoRequest {
	t.Helper()
	req, err := media.ParseVideoRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return req
}

func TestVideoParseAcceptsSecondsAsANumberOrAStringAndKeepsTheFramesPrivate(t *testing.T) {
	frame := pngOf(t, 720, 1280)
	req := parseVideo(t, `{"model":"kling","prompt":"`+promptCanary+`","seconds":"8","image":"`+frame+`","last_image":"`+frame+`","audio":false}`)
	if req.Model != "kling" || req.Seconds != 8 || req.AspectRatio != "9:16" || req.Resolution != "" || req.Audio == nil || *req.Audio {
		t.Errorf("request %+v", req)
	}
	if req.Prompt() != promptCanary || req.FirstFrame() != frame || req.LastFrame() != frame {
		t.Error("prompt or frames lost")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(format, req) + fmt.Sprintf(format, *req); strings.Contains(out, promptCanary) || strings.Contains(out, "base64") {
			t.Errorf("%s leaks: %s", format, out)
		}
	}
	if req := parseVideo(t, `{"model":"m","prompt":"p","seconds":5}`); req.AspectRatio != "16:9" || req.Seconds != 5 || req.Audio != nil {
		t.Errorf("defaults %+v", req)
	}
}

func TestVideoParseRefusesWhatNoModelCanServe(t *testing.T) {
	frame := pngOf(t, 64, 64)
	for name, body := range map[string]string{
		"no seconds":      `{"model":"m","prompt":"p"}`,
		"zero seconds":    `{"model":"m","prompt":"p","seconds":0}`,
		"fraction":        `{"model":"m","prompt":"p","seconds":2.5}`,
		"no prompt":       `{"model":"m","seconds":5}`,
		"last alone":      `{"model":"m","prompt":"p","seconds":5,"last_image":"` + frame + `"}`,
		"square-ish 4:3":  `{"model":"m","prompt":"p","seconds":5,"aspect_ratio":"4:3"}`,
		"reference video": `{"model":"m","prompt":"p","seconds":5,"video":"data:video/mp4;base64,AAAA"}`,
		"svg first frame": `{"model":"m","prompt":"p","seconds":5,"image":"data:image/svg+xml;base64,PHN2Zz4="}`,
		"size":            `{"model":"m","prompt":"p","seconds":5,"size":"1280x720"}`,
	} {
		var invalid strictjson.Invalid
		if _, err := media.ParseVideoRequest(strings.NewReader(body)); !errors.As(err, &invalid) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if _, err := media.ParseVideoRequest(strings.NewReader(`{"model":"m","prompt":"p","seconds":5,"image":"https://cdn.example/f.png"}`)); !errors.Is(err, apierr.ErrRemoteMedia) {
		t.Errorf("remote frame: %v", err)
	}
}

func TestVideoSpecResolvesTheLowestResolutionAndBoundsTheRest(t *testing.T) {
	spec := media.VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"480p", "720p"}}
	req := parseVideo(t, `{"model":"m","prompt":"p","seconds":4}`)
	resolved, err := spec.ResolveVideo(*req)
	if err != nil || resolved.Resolution != "480p" || req.Resolution != "" {
		t.Errorf("err %v resolved %s parsed %s", err, resolved.Resolution, req.Resolution)
	}
	frame := pngOf(t, 64, 64)
	for _, body := range []string{
		`{"model":"m","prompt":"p","seconds":3}`,
		`{"model":"m","prompt":"p","seconds":16}`,
		`{"model":"m","prompt":"p","seconds":5,"resolution":"1080p"}`,
		`{"model":"m","prompt":"p","seconds":5,"audio":true}`,
		`{"model":"m","prompt":"p","seconds":5,"image":"` + frame + `","last_image":"` + frame + `"}`,
	} {
		if _, err := spec.ResolveVideo(*parseVideo(t, body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
	both := media.VideoSpec{MinSeconds: 1, MaxSeconds: 5, Resolutions: []string{"720p"}, Audio: true, LastFrame: true}
	if _, err := both.ResolveVideo(*parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"audio":false,"image":"`+frame+`","last_image":"`+frame+`"}`)); err != nil {
		t.Errorf("audio switch or last frame refused: %v", err)
	}
}

func TestStatusAndFailureNamesRoundTripAndRejectStrangers(t *testing.T) {
	for _, s := range []jobs.Status{jobs.Queued, jobs.Running, jobs.Completed, jobs.Failed, jobs.Expired} {
		if got, ok := media.Statuses.Parse(media.Statuses.String(s)); !ok || got != s {
			t.Errorf("status %d parsed as %d %v", s, got, ok)
		}
	}
	for _, f := range []jobs.Failure{jobs.UpstreamError, jobs.ContentFilter, jobs.Timeout} {
		if got, ok := jobs.ParseFailure(f.String()); !ok || got != f {
			t.Errorf("failure %s parsed as %s %v", f, got, ok)
		}
	}
	if got := media.Statuses.String(jobs.Status(9)) + " " + jobs.Failure(9).String(); got != "jobs.Status(9) jobs.Failure(9)" {
		t.Errorf("unnamed values print as %s", got)
	}
	if got := jobs.Failure(0).String(); got != "" {
		t.Errorf("a job with no failure prints error code %q, want none", got)
	}
	for _, name := range []string{"", "done", "invalid_request", "EXPIRED"} {
		if _, ok := media.Statuses.Parse(name); ok {
			t.Errorf("status %q accepted", name)
		}
		if _, ok := jobs.ParseFailure(name); ok {
			t.Errorf("failure %q accepted", name)
		}
	}
}

func TestEachFrameIsKnownByTheSHA256OfTheFileItsDataURLCarries(t *testing.T) {
	first, last := pngOf(t, 64, 64), pngOf(t, 32, 64)
	req := parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"image":"`+first+`","last_image":"`+last+`"}`)
	var want []frameconsent.Digest
	for _, frame := range []string{first, last} {
		data, err := base64.StdEncoding.DecodeString(frame[strings.Index(frame, ",")+1:])
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, sha256.Sum256(data))
	}
	if got := req.FrameDigests(); !slices.Equal(got, want) {
		t.Errorf("digests %v, want the SHA-256 of each frame's bytes, first then last: %v", got, want)
	}
	if got := parseVideo(t, `{"model":"m","prompt":"p","seconds":5}`).FrameDigests(); len(got) != 0 {
		t.Errorf("a clip from its prompt alone has digests %v", got)
	}
}

func TestAVideoSpecWithItsOwnRatiosRefusesAnotherOnlyWithoutAFrame(t *testing.T) {
	frame := "data:image/png;base64," + pngBase64
	spec := media.GeminiOmniFlash12
	if _, err := spec.ResolveVideo(*parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"aspect_ratio":"1:1"}`)); err == nil || !strings.Contains(err.Error(), "aspect_ratio must be one of 16:9, 9:16") {
		t.Errorf("1:1 on a model without it: err %v", err)
	}
	for _, body := range []string{
		`{"model":"m","prompt":"p","seconds":5}`,
		`{"model":"m","prompt":"p","seconds":5,"aspect_ratio":"9:16"}`,
		`{"model":"m","prompt":"p","seconds":5,"aspect_ratio":"1:1","image":"` + frame + `"}`,
	} {
		if _, err := spec.ResolveVideo(*parseVideo(t, body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
	if !slices.Equal(media.Seedance20Fast.Ratios(), media.VideoAspectRatios) {
		t.Errorf("a spec that names no ratios takes %v, want every video ratio", media.Seedance20Fast.Ratios())
	}
}

func TestAClipWithALastFrameOnOmniFlash12RunsThreeToTenSeconds(t *testing.T) {
	first, last := "data:image/png;base64,"+pngBase64, "data:image/png;base64,"+pngBase64
	spec := media.GeminiOmniFlash12
	for seconds, ok := range map[int]bool{3: true, 5: true, 10: true, 11: false, 15: false} {
		body := fmt.Sprintf(`{"model":"m","prompt":"p","seconds":%d,"image":"%s","last_image":"%s"}`, seconds, first, last)
		_, err := spec.ResolveVideo(*parseVideo(t, body))
		if (err == nil) != ok {
			t.Errorf("%d s with a last frame: err %v, want ok %v", seconds, err, ok)
		}
		if _, err := spec.ResolveVideo(*parseVideo(t, fmt.Sprintf(`{"model":"m","prompt":"p","seconds":%d,"image":"%s"}`, seconds, first))); err != nil {
			t.Errorf("%d s with a first frame only: %v", seconds, err)
		}
	}
}

func TestAClipTakesReferencePicturesUpToTheModelsLimitAndNeverBesideFrames(t *testing.T) {
	pic := "data:image/png;base64," + pngBase64
	refs := func(n int) string {
		return strings.TrimSuffix(strings.Repeat(`"`+pic+`",`, n), ",")
	}
	body := func(seconds, n int) string {
		return fmt.Sprintf(`{"model":"m","prompt":"p","seconds":%d,"reference_images":[%s]}`, seconds, refs(n))
	}
	seedance := media.Seedance25
	seedance.MaxReferenceImages = media.MostReferencePictures
	two := media.VideoSpec{MinSeconds: 1, MaxSeconds: 15, Resolutions: []string{"720p"}, MaxReferenceImages: 2}
	for _, c := range []struct {
		spec    media.VideoSpec
		seconds int
		n       int
		refused string
	}{
		{two, 5, 2, ""},
		{two, 5, 3, "at most 2 pictures"},
		{media.VideoSpec{MinSeconds: 1, MaxSeconds: 15, Resolutions: []string{"720p"}}, 5, 1, "no reference_images"},
		{media.GeminiOmniFlash12, 10, 10, ""},
		{media.GeminiOmniFlash12, 11, 1, "at most 10 with reference_images"},
		{media.GeminiOmniFlash12, 5, 11, "at most 10 pictures"},
		{seedance, 30, 30, ""},
		{media.HeyGenVideo1, 15, 1, ""},
		{media.HeyGenVideo1, 16, 1, "at most 15 with reference_images"},
		{media.HeyGenVideo1, 30, 0, ""},
	} {
		_, err := c.spec.ResolveVideo(*parseVideo(t, body(c.seconds, c.n)))
		if (err == nil) != (c.refused == "") || (err != nil && !strings.Contains(err.Error(), c.refused)) {
			t.Errorf("%d s with %d pictures: err %v, want %q", c.seconds, c.n, err, c.refused)
		}
	}
	req, err := two.ResolveVideo(*parseVideo(t, body(5, 2)))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.ReferenceImages(); len(got) != 2 || got[0] != pic {
		t.Errorf("reference images %d", len(got))
	}
	if got := req.FrameDigests(); len(got) != 2 || got[0] != frameconsent.Of(mustDecode(t, pngBase64)) {
		t.Errorf("a reference picture is an uploaded file for consent: %v", got)
	}
	var invalid strictjson.Invalid
	// why: a model's own count is checked before any picture is read, so these unreadable entries are refused for their number, not as pictures.
	_, err = two.ResolveVideo(*parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"reference_images":["x","x","x"]}`))
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "at most 2 pictures") {
		t.Errorf("three unreadable entries on a model taking two: %v", err)
	}
	_, err = two.ResolveVideo(*parseVideo(t, `{"model":"m","prompt":"p","seconds":5,"reference_images":["data:image/gif;base64,AAAA"]}`))
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "must be base64 data URLs") {
		t.Errorf("one unreadable entry: %v", err)
	}
	// why: past the most any model takes, the count is refused before a picture is read, so these unreadable entries never reach the decoder.
	_, err = media.ParseVideoRequest(strings.NewReader(`{"model":"m","prompt":"p","seconds":5,"reference_images":[` + strings.TrimSuffix(strings.Repeat(`"x",`, media.MostReferencePictures+1), ",") + `]}`))
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "at most 30 pictures") {
		t.Errorf("31 pictures: %v", err)
	}
	_, err = media.ParseVideoRequest(strings.NewReader(`{"model":"m","prompt":"p","seconds":5,"image":"` + pic + `","reference_images":["` + pic + `"]}`))
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "not both") {
		t.Errorf("a first frame beside reference pictures: %v", err)
	}
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
