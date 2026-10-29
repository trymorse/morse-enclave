package runware

import (
	"context"
	"net/http"
	"time"

	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
	"morse/backend/internal/uuid"
)

const (
	videoTTL   = int(media.VendorKeep / time.Second)
	outputHost = ".runware.ai"
)

type videoModel struct {
	media.VideoSpec
	sizes           map[media.Size]media.Dims
	frameResolution bool
	klingSound      bool
}

var videoModels = map[string]videoModel{
	"klingai:kling-video@3-pro": {
		VideoSpec:  media.KlingV3Pro,
		sizes:      media.SizeTable(map[string][2]int{"16:9 1080p": {1920, 1080}, "9:16 1080p": {1080, 1920}, "1:1 1080p": {1440, 1440}}),
		klingSound: true,
	},
	"bytedance:seedance@2.5": {
		VideoSpec: media.Seedance25,
		sizes: media.SizeTable(map[string][2]int{
			"16:9 480p": {854, 480}, "9:16 480p": {480, 854}, "1:1 480p": {640, 640},
			"16:9 720p": {1280, 720}, "9:16 720p": {720, 1280}, "1:1 720p": {960, 960},
			"16:9 1080p": {1920, 1080}, "9:16 1080p": {1080, 1920}, "1:1 1080p": {1440, 1440},
		}),
		frameResolution: true,
	},
	"minimax:h3@max": {
		VideoSpec: media.MiniMaxH3Max,
		sizes: media.SizeTable(map[string][2]int{
			"16:9 480p": {832, 480}, "9:16 480p": {480, 832}, "1:1 480p": {480, 480},
			"16:9 768p": {1344, 768}, "9:16 768p": {768, 1344}, "1:1 768p": {768, 768},
		}),
		frameResolution: true,
	},
	"alibaba:wan@3.0": {
		VideoSpec: media.Wan30,
		sizes: media.SizeTable(map[string][2]int{
			"16:9 480p": {832, 480}, "9:16 480p": {480, 832}, "1:1 480p": {624, 624},
			"16:9 720p": {1280, 720}, "9:16 720p": {720, 1280}, "1:1 720p": {960, 960},
			"16:9 1080p": {1920, 1080}, "9:16 1080p": {1080, 1920}, "1:1 1080p": {1440, 1440},
		}),
		frameResolution: true,
	},
	"bytedance:seedance@2.0-fast": {
		VideoSpec: media.Seedance20Fast,
		sizes: media.SizeTable(map[string][2]int{
			"16:9 480p": {864, 496}, "9:16 480p": {496, 864}, "1:1 480p": {640, 640},
			"16:9 720p": {1280, 720}, "9:16 720p": {720, 1280}, "1:1 720p": {960, 960},
		}),
		frameResolution: true,
	},
}

type Videos struct {
	vendor upstream.Endpoint
	videoModel
	media.VendorHosted
	model string
}

func NewVideos(baseURL, apiKey, model string, httpClient *http.Client) (*Videos, error) {
	info, err := media.Lookup(videoModels, media.VideoModel, model, "runware")
	if err != nil {
		return nil, err
	}
	return &Videos{vendor: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: httpClient}, videoModel: info, VendorHosted: media.VendorHosted{Client: httpClient, HostSuffix: outputHost}, model: model}, nil
}

type frameImage struct {
	Image string `json:"image"`
	Frame string `json:"frame"`
}

type videoInputs struct {
	FrameImages []frameImage `json:"frameImages"`
}

type videoSettings struct {
	Audio *bool `json:"audio"`
}

type klingSettings struct {
	Sound *bool `json:"sound"`
}

type videoProviderSettings struct {
	Klingai klingSettings `json:"klingai"`
}

type videoTask struct {
	TaskType         string                 `json:"taskType"`
	TaskUUID         string                 `json:"taskUUID"`
	Model            string                 `json:"model"`
	PositivePrompt   string                 `json:"positivePrompt"`
	Duration         int                    `json:"duration"`
	Width            int                    `json:"width,omitempty"`
	Height           int                    `json:"height,omitempty"`
	Resolution       string                 `json:"resolution,omitempty"`
	NumberResults    int                    `json:"numberResults"`
	OutputType       string                 `json:"outputType"`
	OutputFormat     string                 `json:"outputFormat"`
	IncludeCost      bool                   `json:"includeCost"`
	DeliveryMethod   string                 `json:"deliveryMethod"`
	TTL              int                    `json:"ttl"`
	Inputs           *videoInputs           `json:"inputs,omitempty"`
	Settings         *videoSettings         `json:"settings,omitempty"`
	ProviderSettings *videoProviderSettings `json:"providerSettings,omitempty"`
}

func (p *Videos) SubmitVideo(ctx context.Context, req *media.VideoRequest, _ media.Submission) (media.Submitted, error) {
	task := videoTask{
		TaskType: "videoInference", TaskUUID: uuid.Format(uuid.New()), Model: p.model, PositivePrompt: req.Prompt(), Duration: req.Seconds,
		NumberResults: 1, OutputType: "URL", OutputFormat: "MP4", IncludeCost: true, DeliveryMethod: "async", TTL: videoTTL,
	}
	if first := req.FirstFrame(); first != "" {
		task.Inputs = &videoInputs{FrameImages: []frameImage{{Image: first, Frame: "first"}}}
		if last := req.LastFrame(); last != "" {
			task.Inputs.FrameImages = append(task.Inputs.FrameImages, frameImage{Image: last, Frame: "last"})
		}
		if p.frameResolution {
			task.Resolution = req.Resolution
		}
	} else {
		dims := p.sizes[req.Size]
		task.Width, task.Height = dims.Width, dims.Height
	}
	switch {
	case req.Audio == nil:
	case p.klingSound:
		task.ProviderSettings = &videoProviderSettings{Klingai: klingSettings{Sound: req.Audio}}
	default:
		task.Settings = &videoSettings{Audio: req.Audio}
	}
	if _, err := send(ctx, p.vendor, task, media.MaxReplyBody); err != nil {
		return media.Submitted{}, err
	}
	return media.Submitted{VendorID: task.TaskUUID}, nil
}

func (p *Videos) PollVideo(ctx context.Context, vendorID string) (jobs.Poll, error) {
	r, err := send(ctx, p.vendor, pollTask(vendorID), media.MaxReplyBody)
	if err != nil {
		return jobs.Poll{}, err
	}
	poll := jobs.Poll{Status: jobs.Running}
	for _, item := range r.Data {
		switch item.Status {
		case "success":
			poll.Cost = cost(item)
			if !p.Accepts(item.VideoURL) {
				poll.Status, poll.Failure = jobs.Failed, jobs.UpstreamError
				return poll, nil
			}
			poll.Status, poll.OutputURL = jobs.Completed, item.VideoURL
			return poll, nil
		case "processing":
			poll.Progress = max(poll.Progress, min(item.Progress, 99))
		}
	}
	return poll, nil
}
