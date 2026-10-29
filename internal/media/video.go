package media

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"morse/backend/internal/upstream"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"morse/backend/internal/enum"
	"morse/backend/internal/jobs"
	"morse/backend/internal/strictjson"
)

const VideoKeep = time.Hour

const VendorKeep = VideoKeep + 3*time.Minute

var (
	VideoAspectRatios = []string{"16:9", "9:16", "1:1"}
	ErrVideoGone      = errors.New("media: the video is no longer stored")
)

type VideoRequest struct {
	Model   string
	Seconds int
	Size
	Audio  *bool
	prompt string
	first  string
	last   string
}

func (r VideoRequest) ModelName() string  { return r.Model }
func (r VideoRequest) Prompt() string     { return r.prompt }
func (r VideoRequest) FirstFrame() string { return r.first }
func (r VideoRequest) LastFrame() string  { return r.last }
func (r VideoRequest) String() string {
	return fmt.Sprintf("media.VideoRequest(%s, %ds, %s %s)", r.Model, r.Seconds, r.AspectRatio, r.Resolution)
}
func (r VideoRequest) GoString() string { return r.String() }

func ParseVideoRequest(body io.Reader) (*VideoRequest, error) {
	var wire struct {
		Model, Prompt, AspectRatio, Resolution, Image, LastImage string
		Seconds                                                  json.RawMessage
		Audio                                                    *bool
	}
	if err := strictjson.Decode(body, map[string]any{
		"model": &wire.Model, "prompt": &wire.Prompt, "seconds": &wire.Seconds, "aspect_ratio": &wire.AspectRatio,
		"resolution": &wire.Resolution, "image": &wire.Image, "last_image": &wire.LastImage, "audio": &wire.Audio,
	}); err != nil {
		return nil, err
	}
	req := &VideoRequest{Model: wire.Model, Size: Size{AspectRatio: wire.AspectRatio, Resolution: wire.Resolution}, Audio: wire.Audio, prompt: wire.Prompt, first: wire.Image, last: wire.LastImage}
	seconds, err := strconv.Atoi(strings.Trim(string(wire.Seconds), `"`))
	req.Seconds = seconds
	switch {
	case req.Model == "":
		return nil, strictjson.Invalid("model is required.")
	case strings.TrimSpace(req.prompt) == "":
		return nil, strictjson.Invalid("prompt is required.")
	case err != nil || seconds <= 0:
		return nil, strictjson.Invalid("seconds must be a positive whole number.")
	case req.last != "" && req.first == "":
		return nil, strictjson.Invalid("last_image needs image as the first frame.")
	}
	for i, frame := range []*string{&req.first, &req.last} {
		if *frame == "" {
			continue
		}
		canonical, data, err := inlineImage(*frame)
		if err != nil {
			return nil, err
		}
		*frame = canonical.String()
		if i == 0 && req.AspectRatio == "" {
			req.AspectRatio = closestOf(VideoAspectRatios, data)
		}
	}
	req.AspectRatio = cmp.Or(req.AspectRatio, VideoAspectRatios[0])
	if !slices.Contains(VideoAspectRatios, req.AspectRatio) {
		return nil, strictjson.Invalid("aspect_ratio must be one of " + strings.Join(VideoAspectRatios, ", ") + ".")
	}
	return req, nil
}

type VideoSpec struct {
	MinSeconds  int
	MaxSeconds  int
	Resolutions []string
	Audio       bool
	LastFrame   bool
}

func (s VideoSpec) ResolveVideo(r VideoRequest) (VideoRequest, error) {
	r.Resolution = cmp.Or(r.Resolution, s.Resolutions[0])
	switch {
	case r.Seconds < s.MinSeconds || r.Seconds > s.MaxSeconds:
		return VideoRequest{}, strictjson.Invalid(fmt.Sprintf("seconds must be between %d and %d for this model.", s.MinSeconds, s.MaxSeconds))
	case !slices.Contains(s.Resolutions, r.Resolution):
		return VideoRequest{}, strictjson.Invalid("resolution must be one of " + strings.Join(s.Resolutions, ", ") + " for this model.")
	case r.Audio != nil && !s.Audio:
		return VideoRequest{}, strictjson.Invalid("This model has no audio setting.")
	case r.last != "" && !s.LastFrame:
		return VideoRequest{}, strictjson.Invalid("This model takes no last_image.")
	}
	return r, nil
}

type Submission struct {
	Deadline  time.Time
	UploadURL string
}

type Submitted struct{ VendorID string }

var Statuses = enum.Names[jobs.Status]{jobs.Queued: "queued", jobs.Running: "in_progress", jobs.Completed: "completed", jobs.Failed: "failed", jobs.Expired: "expired"}

type Output struct{ URL string }

type VideoGenerator interface {
	ResolveVideo(req VideoRequest) (VideoRequest, error)
	SubmitVideo(ctx context.Context, req *VideoRequest, s Submission) (Submitted, error)
	PollVideo(ctx context.Context, vendorID string) (jobs.Poll, error)
	OpenVideo(ctx context.Context, out Output) (io.ReadCloser, int64, error)
}

type VendorHosted struct {
	Client     *http.Client
	HostSuffix string
}

func (v VendorHosted) Accepts(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() {
		return false
	}
	sub, ok := strings.CutSuffix(u.Hostname(), v.HostSuffix)
	return ok && sub != ""
}

var vendorGone = []int{http.StatusNotFound, http.StatusForbidden, http.StatusGone}

func (v VendorHosted) OpenVideo(ctx context.Context, out Output) (io.ReadCloser, int64, error) {
	if !v.Accepts(out.URL) {
		return nil, 0, ErrVideoGone
	}
	return Stream(ctx, v.Client, out.URL, vendorGone)
}

func Stream(ctx context.Context, client *http.Client, location string, gone []int) (io.ReadCloser, int64, error) {
	resp, err := upstream.Endpoint{BaseURL: location, HTTP: client, Refuse: func(r upstream.Reply) error {
		if slices.Contains(gone, r.Status) {
			return ErrVideoGone
		}
		return upstream.ErrUnreachable
	}}.Open(ctx, upstream.Request{Method: http.MethodGet})
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}
