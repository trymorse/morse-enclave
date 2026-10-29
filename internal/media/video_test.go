package media_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
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
