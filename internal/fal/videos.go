package fal

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
)

const outputHost = ".fal.media"

type resolutionRule uint8

const (
	resolutionVerbatim resolutionRule = iota
	resolutionUpper
	resolutionOmitted
)

type videoModel struct {
	media.VideoSpec
	i2v             string
	unit            money.Micros
	stringDuration  bool
	resolution      resolutionRule
	startImageURL   bool
	audioSwitch     bool
	promptExpansion string
}

var videoModels = map[string]videoModel{
	"fal-ai/kling-video/v3/pro/text-to-video": {
		i2v:       "fal-ai/kling-video/v3/pro/image-to-video",
		VideoSpec: media.KlingV3Pro, unit: 140_000,
		stringDuration: true, resolution: resolutionOmitted, startImageURL: true,
	},
	"bytedance/seedance-2.5/text-to-video": {
		i2v:       "bytedance/seedance-2.5/image-to-video",
		VideoSpec: media.Seedance25, unit: 21_400,
		stringDuration: true,
	},
	"bytedance/seedance-2.0/fast/text-to-video": {
		i2v:       "bytedance/seedance-2.0/fast/image-to-video",
		VideoSpec: media.Seedance20Fast, unit: 11_200,
		stringDuration: true,
	},
	"minimax/h3-max/text-to-video": {
		i2v:       "minimax/h3-max/image-to-video",
		VideoSpec: media.MiniMaxH3Max, unit: 25_000,
		resolution: resolutionUpper, promptExpansion: "balanced",
	},
	"alibaba/wan-3.0/text-to-video": {
		i2v:       "alibaba/wan-3.0/image-to-video",
		VideoSpec: media.Wan30, unit: 50_000,
		startImageURL: true, audioSwitch: true,
	},
}

type Videos struct {
	client
	videoModel
	media.VendorHosted
	model string
}

func NewVideos(baseURL, apiKey, model string, httpClient *http.Client) (*Videos, error) {
	info, err := media.Lookup(videoModels, media.VideoModel, model, "fal")
	if err != nil {
		return nil, err
	}
	return &Videos{client: newClient(baseURL, apiKey, httpClient), videoModel: info, VendorHosted: media.VendorHosted{Client: httpClient, HostSuffix: outputHost}, model: model}, nil
}

type duration struct {
	seconds  int
	asString bool
}

func (d duration) MarshalJSON() ([]byte, error) {
	if d.asString {
		return json.Marshal(strconv.Itoa(d.seconds))
	}
	return json.Marshal(d.seconds)
}

type videoInput struct {
	Prompt              string   `json:"prompt"`
	Duration            duration `json:"duration"`
	Resolution          string   `json:"resolution,omitempty"`
	AspectRatio         string   `json:"aspect_ratio,omitempty"`
	ImageURL            string   `json:"image_url,omitempty"`
	StartImageURL       string   `json:"start_image_url,omitempty"`
	EndImageURL         string   `json:"end_image_url,omitempty"`
	GenerateAudio       *bool    `json:"generate_audio,omitempty"`
	Audio               *bool    `json:"audio,omitempty"`
	PromptExpansionMode string   `json:"prompt_expansion_mode,omitempty"`
}

type videoOutput struct {
	Video struct {
		URL string `json:"url"`
	} `json:"video"`
}

func (p *Videos) input(req *media.VideoRequest) (string, videoInput) {
	in := videoInput{
		Prompt: req.Prompt(), Duration: duration{seconds: req.Seconds, asString: p.stringDuration},
		PromptExpansionMode: p.promptExpansion,
	}
	switch p.resolution {
	case resolutionVerbatim:
		in.Resolution = req.Resolution
	case resolutionUpper:
		in.Resolution = strings.ToUpper(req.Resolution)
	}
	if p.audioSwitch {
		in.Audio = req.Audio
	} else {
		in.GenerateAudio = req.Audio
	}
	first := req.FirstFrame()
	if first == "" {
		in.AspectRatio = req.AspectRatio
		return p.model, in
	}
	if p.startImageURL {
		in.StartImageURL = first
	} else {
		in.ImageURL = first
	}
	if last := req.LastFrame(); last != "" {
		in.EndImageURL = last
	}
	return p.i2v, in
}

func (p *Videos) SubmitVideo(ctx context.Context, req *media.VideoRequest, s media.Submission) (media.Submitted, error) {
	endpoint, in := p.input(req)
	id, err := p.submit(ctx, endpoint, in, startBy(s.Deadline))
	if err != nil {
		return media.Submitted{}, err
	}
	return media.Submitted{VendorID: id}, nil
}

func (p *Videos) PollVideo(ctx context.Context, vendorID string) (jobs.Poll, error) {
	if !validID(vendorID) {
		return jobs.Unserved, nil
	}
	o, r, err := p.await(ctx, app(p.model), vendorID, media.MaxReplyBody, p.unit)
	if o == stillQueued {
		if err != nil {
			return jobs.Poll{}, err
		}
		return jobs.Poll{Status: jobs.Running}, nil
	}
	failed := jobs.FailedBy(err)
	failed.Cost = r.cost
	var out videoOutput
	if o == finalFailure || json.Unmarshal(r.Body, &out) != nil || !p.Accepts(out.Video.URL) {
		return failed, nil
	}
	return jobs.Poll{Status: jobs.Completed, OutputURL: out.Video.URL, Cost: r.cost}, nil
}
