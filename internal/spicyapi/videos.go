package spicyapi

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"morse/backend/internal/dataurl"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
	"morse/backend/internal/uuid"
)

const expired = "expired"

const (
	noAsset          = "no_asset"
	assetUnavailable = "asset_unavailable"
	untrustedLink    = "untrusted_link"
)

type videoModel struct {
	media.VideoSpec
	sendsExpansion bool
	sendsThinking  bool
	fromFrames     string
}

// why: GET https://api.spicyapi.ai/api/v1/models/{model} (2026-11-17) lists the only fields each takes, and H3 bills
// double past 15 s; a route holds each resolution at its own price, so the first is the default. Each image-to-video
// endpoint costs what its text-to-video one does (catalog, 2026-11-18), and H3's takes no aspect_ratio.
var videoModels = map[string]videoModel{
	"minimax/h3/text-to-video": {
		VideoSpec:      media.VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"768p", "480p"}, LastFrame: true},
		sendsExpansion: true,
		fromFrames:     "minimax/h3/image-to-video",
	},
	"alibaba/wan-3.0/text-to-video": {
		VideoSpec:      media.VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true},
		sendsExpansion: true,
		sendsThinking:  true,
		fromFrames:     "alibaba/wan-3.0/image-to-video",
	},
	"bytedance/seedance-2.5/text-to-video": {
		VideoSpec:  media.VideoSpec{MinSeconds: 4, MaxSeconds: 30, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true},
		fromFrames: "bytedance/seedance-2.5/image-to-video",
	},
	"bytedance/seedance-2.0-fast/text-to-video": {
		VideoSpec:  media.VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true},
		fromFrames: "bytedance/seedance-2.0-fast/image-to-video",
	},
	"bytedance/seedance-2.0-mini/text-to-video": {
		VideoSpec:  media.VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true},
		fromFrames: "bytedance/seedance-2.0-mini/image-to-video",
	},
	"pruna-ai/p-video-2-pro/text-to-video": {
		VideoSpec:  media.VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"768p", "480p"}, LastFrame: true},
		fromFrames: "pruna-ai/p-video-2-pro/image-to-video",
	},
	// why: the adult fine-tunes are image-to-video only, each at most 15 s here though some take 30, and their schemas
	// (GET https://api.spicyapi.ai/api/v1/models/{model}, 2026-11-22) list prompt expansion only on Wan 3.0 Spicy.
	"alibaba/wan-3.0-spicy/image-to-video": {
		VideoSpec:      media.VideoSpec{MinSeconds: 2, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true, FirstFrameRequired: true},
		sendsExpansion: true,
	},
	"bytedance/seedance-2.5-spicy/image-to-video": {
		VideoSpec: media.VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true, LastFrame: true, FirstFrameRequired: true},
	},
	"minimax/h3-spicy/image-to-video": {
		VideoSpec: media.VideoSpec{MinSeconds: 3, MaxSeconds: 15, Resolutions: []string{"768p", "480p"}, LastFrame: true, FirstFrameRequired: true},
	},
	"lightricks/ltx-2.3-spicy/image-to-video": {
		VideoSpec: media.VideoSpec{MinSeconds: 3, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, FirstFrameRequired: true},
	},
	"vidu/q3-spicy/image-to-video": {
		VideoSpec: media.VideoSpec{MinSeconds: 1, MaxSeconds: 15, Resolutions: []string{"720p", "540p"}, Audio: true, FirstFrameRequired: true},
	},
}

type Videos struct {
	client
	videoModel
	model string
}

func NewVideos(baseURL, apiKey, model string, httpClient *http.Client) (*Videos, error) {
	info, err := media.Lookup(videoModels, media.VideoModel, model, "spicyapi")
	if err != nil {
		return nil, err
	}
	return &Videos{client: newClient(baseURL, apiKey, httpClient), videoModel: info, model: model}, nil
}

// why: these models run uncensored, and spicyapi.ai's policy leaves a real person's consent to their likeness to Morse
// (https://docs.spicyapi.ai/docs/policy), so a frame goes to them only with the owner's consent to its exact bytes.
func (p *Videos) FramesNeedConsent() bool { return true }

func (p *Videos) ResolveVideo(req media.VideoRequest) (media.VideoRequest, error) {
	if utf8.RuneCountInString(req.Prompt()) > maxPrompt {
		return media.VideoRequest{}, strictjson.Invalid(fmt.Sprintf("prompt must be at most %d characters for this model.", maxPrompt))
	}
	frames, err := framesOf(req)
	if err != nil {
		return media.VideoRequest{}, err
	}
	if p.FirstFrameRequired && req.FirstFrame() == "" {
		return media.VideoRequest{}, strictjson.Invalid("This model makes a clip only from a first frame; send image.")
	}
	for _, frame := range frames {
		if base64.StdEncoding.DecodedLen(len(frame.Base64)) > maxReference {
			return media.VideoRequest{}, strictjson.Invalid(fmt.Sprintf("image and last_image must be at most %d MiB each for this model.", maxReference>>20))
		}
	}
	return p.VideoSpec.ResolveVideo(req)
}

func framesOf(req media.VideoRequest) ([]dataurl.URL, error) {
	var frames []dataurl.URL
	for _, raw := range []string{req.FirstFrame(), req.LastFrame()} {
		if raw == "" {
			continue
		}
		frame, err := dataurl.Parse(raw)
		if err != nil {
			return nil, strictjson.Invalid("image and last_image must be base64 data URLs of PNG, JPEG, or WebP images.")
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

type videoInput struct {
	Prompt                string `json:"prompt"`
	Resolution            string `json:"resolution"`
	AspectRatio           string `json:"aspect_ratio,omitempty"`
	DurationSeconds       int    `json:"duration_seconds"`
	ImageURL              string `json:"image_url,omitempty"`
	LastImageURL          string `json:"last_image_url,omitempty"`
	GenerateAudio         *bool  `json:"generate_audio,omitempty"`
	EnablePromptExpansion *bool  `json:"enable_prompt_expansion,omitempty"`
	EnableThinking        *bool  `json:"enable_thinking,omitempty"`
}

// why: a video runs for minutes, past createTask's longest wait, so the task is created without one, and spicyapi.ai
// keeps it until a few minutes after Morse would have dropped it (https://docs.spicyapi.ai/docs/tasks#wait).
func (p *Videos) SubmitVideo(ctx context.Context, req *media.VideoRequest, _ media.Submission) (media.Submitted, error) {
	in := videoInput{
		Prompt: req.Prompt(), Resolution: req.Resolution, AspectRatio: req.AspectRatio, DurationSeconds: req.Seconds,
		GenerateAudio: req.Audio,
	}
	if p.sendsExpansion {
		in.EnablePromptExpansion = off
	}
	if p.sendsThinking {
		in.EnableThinking = off
	}
	model := p.model
	frames, err := framesOf(*req)
	if err != nil {
		return media.Submitted{}, err
	}
	if len(frames) > 0 {
		uris, err := p.uploadAll(ctx, frames)
		if err != nil {
			return media.Submitted{}, err
		}
		model, in.AspectRatio, in.ImageURL = cmp.Or(p.fromFrames, p.model), "", uris[0]
		if len(uris) > 1 {
			in.LastImageURL = uris[1]
		}
	}
	rec, err := p.create(ctx, task{Model: model, Input: in}, uuid.Format(uuid.New()), 0, media.VendorKeep)
	if err != nil {
		return media.Submitted{}, err
	}
	return media.Submitted{VendorID: rec.TaskID}, nil
}

// why: a task's cost is final only once settled, so a finished task stays running here until it is
// (https://docs.spicyapi.ai/docs/tasks).
func (p *Videos) PollVideo(ctx context.Context, vendorID string) (jobs.Poll, error) {
	rec, err := p.record(ctx, vendorID)
	switch {
	case err != nil:
		return jobs.Poll{}, err
	case rec.State == "queued":
		return jobs.Poll{Status: jobs.Queued}, nil
	case !rec.done() || !rec.Settled:
		return jobs.Poll{Status: jobs.Running}, nil
	case rec.State != succeeded:
		return jobs.Poll{Status: jobs.Failed, Failure: videoFailure(rec), Cost: rec.cost(), Why: stateReason(rec)}, nil
	}
	if _, why := p.result(rec); why != "" {
		return jobs.Poll{Status: jobs.Failed, Failure: jobs.UpstreamError, Cost: rec.cost(), Why: why}, nil
	}
	return jobs.Poll{Status: jobs.Completed, Cost: rec.cost()}, nil
}

func videoFailure(rec record) jobs.Failure {
	switch {
	case rec.ErrorCode == contentRejected:
		return jobs.ContentFilter
	case rec.State == expired:
		return jobs.Timeout
	}
	return jobs.UpstreamError
}

func stateReason(rec record) string {
	switch {
	case rec.ErrorCode == contentRejected:
		return contentRejected
	case rec.State == "failed", rec.State == expired, rec.State == "canceled":
		return "state_" + rec.State
	}
	return "state_unknown"
}

func (p *Videos) result(rec record) (link, why string) {
	why = noAsset
	for _, a := range rec.Output.Assets {
		switch {
		case a.Unavailable:
			why = assetUnavailable
		case !p.holdsResult(a.URL):
			why = untrustedLink
		default:
			return a.URL, ""
		}
	}
	return "", why
}

// why: a result link lasts about 20 minutes and Morse keeps a video for an hour, so each download reads the task
// again for a fresh link (https://docs.spicyapi.ai/docs/tasks#deadlines).
func (p *Videos) OpenVideo(ctx context.Context, out media.Output) (io.ReadCloser, int64, error) {
	rec, err := p.record(ctx, out.VendorID)
	if err != nil {
		if upstream.Final(err, upstream.UnusableEnds) {
			return nil, 0, media.ErrVideoGone
		}
		return nil, 0, err
	}
	link, why := p.result(rec)
	if rec.State != succeeded || why != "" {
		return nil, 0, media.ErrVideoGone
	}
	return media.Stream(ctx, p.storage, link, []int{http.StatusNotFound, http.StatusForbidden, http.StatusGone})
}

// why: purge destroys only a final task and never cancels one, and a task spicyapi.ai still runs past Morse's own
// deadline is billed when it succeeds, so it is read again until it ends (https://docs.spicyapi.ai/docs/retention).
func (p *Videos) DiscardVideo(ctx context.Context, vendorID string) error {
	if !taskID.MatchString(vendorID) {
		return nil
	}
	rec, err := p.record(ctx, vendorID)
	switch {
	case err != nil && upstream.Final(err, upstream.UnusableEnds):
		return nil
	case err != nil:
		return err
	case !rec.done():
		return media.ErrVideoRunning
	case rec.cleared(time.Now()):
		return nil
	}
	return p.purge(ctx, vendorID)
}
