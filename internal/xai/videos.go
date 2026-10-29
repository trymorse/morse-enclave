package xai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"morse/backend/internal/jobs"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

var videoModels = map[string]media.VideoSpec{
	"grok-imagine-video-1.5": {MinSeconds: 1, MaxSeconds: 15, Resolutions: []string{"480p", "720p", "1080p"}},
}

type Videos struct {
	vendor upstream.Endpoint
	media.VideoSpec
	model string
}

func NewVideos(baseURL, apiKey, model string, httpClient *http.Client) (*Videos, error) {
	spec, err := media.Lookup(videoModels, media.VideoModel, model, "xai")
	if err != nil {
		return nil, err
	}
	return &Videos{vendor: endpoint(baseURL, apiKey, httpClient, confirmZeroRetention), VideoSpec: spec, model: model}, nil
}

type uploadTarget struct {
	UploadURL string `json:"upload_url"`
}

type videoRequest struct {
	Model       string       `json:"model"`
	Prompt      string       `json:"prompt"`
	Duration    int          `json:"duration"`
	Resolution  string       `json:"resolution"`
	AspectRatio string       `json:"aspect_ratio"`
	Image       *imageRef    `json:"image,omitempty"`
	Output      uploadTarget `json:"output"`
}

type videoPoll struct {
	Status   string `json:"status"`
	Progress int    `json:"progress"`
	Video    *struct {
		RespectModeration *bool `json:"respect_moderation"`
	} `json:"video"`
	Usage usage `json:"usage"`
}

func (p *Videos) SubmitVideo(ctx context.Context, req *media.VideoRequest, s media.Submission) (media.Submitted, error) {
	body := videoRequest{
		Model: p.model, Prompt: req.Prompt(), Duration: req.Seconds, Resolution: req.Resolution, AspectRatio: req.AspectRatio,
		Output: uploadTarget{UploadURL: s.UploadURL},
	}
	if first := req.FirstFrame(); first != "" {
		body.Image = &imageRef{URL: first}
	}
	var reply struct {
		RequestID string `json:"request_id"`
	}
	if _, err := p.vendor.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: "/v1/videos/generations", Body: jsonx.Encode(body)}, &reply, media.MaxReplyBody); err != nil {
		return media.Submitted{}, err
	}
	if reply.RequestID == "" {
		return media.Submitted{}, upstream.ErrMalformed
	}
	return media.Submitted{VendorID: reply.RequestID}, nil
}

func (p *Videos) PollVideo(ctx context.Context, vendorID string) (jobs.Poll, error) {
	resp, err := p.vendor.JSON(ctx, upstream.Request{Method: http.MethodGet, Path: "/v1/videos/" + url.PathEscape(vendorID)}, nil, media.MaxReplyBody)
	if err != nil {
		return jobs.Poll{}, err
	}
	if resp.Status == http.StatusAccepted && len(resp.Body) == 0 {
		return jobs.Poll{Status: jobs.Running}, nil
	}
	var reply videoPoll
	if json.Unmarshal(resp.Body, &reply) != nil {
		return jobs.Poll{}, upstream.ErrMalformed
	}
	poll := jobs.Poll{Status: jobs.Running, Progress: min(max(reply.Progress, 0), 99), Cost: reply.Usage.cost()}
	switch reply.Status {
	case "done":
		poll.Status, poll.Progress = jobs.Completed, 100
		if reply.Video != nil && reply.Video.RespectModeration != nil && !*reply.Video.RespectModeration {
			poll.Status, poll.Failure = jobs.Failed, jobs.ContentFilter
		}
	case "failed", "expired":
		poll.Status, poll.Failure = jobs.Failed, jobs.UpstreamError
	}
	return poll, nil
}

var onlyAMissingObjectIsGone = []int{http.StatusNotFound}

func (p *Videos) OpenVideo(ctx context.Context, out media.Output) (io.ReadCloser, int64, error) {
	return media.Stream(ctx, p.vendor.HTTP, out.URL, onlyAMissingObjectIsGone)
}
