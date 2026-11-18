package spicyapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
	"morse/backend/internal/uuid"
)

const expired = "expired"

type videoModel struct {
	media.VideoSpec
	sendsThinking bool
}

// why: GET https://api.spicyapi.ai/api/v1/models/{model} (2026-11-17) lists the only fields each takes, and H3 bills
// double past 15 s; a route holds at its first resolution's price, so the cheaper 480p follows it.
var videoModels = map[string]videoModel{
	"minimax/h3/text-to-video": {
		VideoSpec: media.VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"768p", "480p"}},
	},
	"alibaba/wan-3.0/text-to-video": {
		VideoSpec:     media.VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"720p", "480p"}, Audio: true},
		sendsThinking: true,
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

// why: these models run uncensored, and Morse cannot yet tell a picture Studio made for the account from an upload of
// a real person, so a clip is made from its prompt alone until that is decided.
func (p *Videos) ResolveVideo(req media.VideoRequest) (media.VideoRequest, error) {
	switch {
	case req.FirstFrame() != "":
		return media.VideoRequest{}, strictjson.Invalid("This model takes no image or last_image: it makes a video from the prompt alone.")
	case utf8.RuneCountInString(req.Prompt()) > maxPrompt:
		return media.VideoRequest{}, strictjson.Invalid(fmt.Sprintf("prompt must be at most %d characters for this model.", maxPrompt))
	}
	return p.VideoSpec.ResolveVideo(req)
}

type videoInput struct {
	Prompt                string `json:"prompt"`
	Resolution            string `json:"resolution"`
	AspectRatio           string `json:"aspect_ratio"`
	DurationSeconds       int    `json:"duration_seconds"`
	GenerateAudio         *bool  `json:"generate_audio,omitempty"`
	EnablePromptExpansion *bool  `json:"enable_prompt_expansion"`
	EnableThinking        *bool  `json:"enable_thinking,omitempty"`
}

// why: a video runs for minutes, past createTask's longest wait, so the task is created without one, and spicyapi.ai
// keeps it until a few minutes after Morse would have dropped it (https://docs.spicyapi.ai/docs/tasks#wait).
func (p *Videos) SubmitVideo(ctx context.Context, req *media.VideoRequest, _ media.Submission) (media.Submitted, error) {
	in := videoInput{
		Prompt: req.Prompt(), Resolution: req.Resolution, AspectRatio: req.AspectRatio, DurationSeconds: req.Seconds,
		GenerateAudio: req.Audio, EnablePromptExpansion: off,
	}
	if p.sendsThinking {
		in.EnableThinking = off
	}
	rec, err := p.create(ctx, task{Model: p.model, Input: in}, uuid.Format(uuid.New()), 0, media.VendorKeep)
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
		return jobs.Poll{Status: jobs.Failed, Failure: videoFailure(rec), Cost: rec.cost()}, nil
	case p.result(rec) == "":
		return jobs.Poll{Status: jobs.Failed, Failure: jobs.UpstreamError, Cost: rec.cost()}, nil
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

func (p *Videos) result(rec record) string {
	for _, a := range rec.Output.Assets {
		if !a.Unavailable && p.results.holds(a.URL) {
			return a.URL
		}
	}
	return ""
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
	link := p.result(rec)
	if rec.State != succeeded || link == "" {
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
