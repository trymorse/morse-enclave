package runware

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
	"morse/backend/internal/uuid"
)

type imageModel struct {
	media.ImageSpec
	dims media.ImageDims
	checkpoint
	maxPrompt int
}

type checkpoint struct {
	steps     int
	cfg       float64
	scheduler string
	tags      string
}

func (c checkpoint) prompt(prompt string) string {
	first, _, _ := strings.Cut(c.tags, ",")
	if c.tags == "" || strings.Contains(strings.ToLower(prompt), first) {
		return prompt
	}
	return c.tags + ", " + prompt
}

var sdxlSizes = media.SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1344, 768}, "9:16 1k": {768, 1344}, "4:3 1k": {1216, 896},
	"3:4 1k": {896, 1216}, "3:2 1k": {1216, 832}, "2:3 1k": {832, 1216},
})

var sdxl = media.ImageDims{Base: sdxlSizes}

// Runware takes Seedream 5.0 Lite only at its listed sizes, and Seedream 4.5 at its recommended 2K ones, so both
// draw those at 1k and 2k alike, at one price.
var seedream5LiteSizes = twoKOnly(map[string][2]int{
	"1:1": {2048, 2048}, "16:9": {2848, 1600}, "9:16": {1600, 2848}, "4:3": {2304, 1728},
	"3:4": {1728, 2304}, "3:2": {2496, 1664}, "2:3": {1664, 2496},
})

var seedream45Sizes = twoKOnly(map[string][2]int{
	"1:1": {2048, 2048}, "16:9": {2560, 1440}, "9:16": {1440, 2560}, "4:3": {2304, 1728},
	"3:4": {1728, 2304}, "3:2": {2496, 1664}, "2:3": {1664, 2496},
})

func twoKOnly(byRatio map[string][2]int) map[media.Size]media.Dims {
	sizes := map[string][2]int{}
	for ratio, d := range byRatio {
		sizes[ratio+" 1k"], sizes[ratio+" 2k"] = d, d
	}
	return media.SizeTable(sizes)
}

var imageModels = map[string]imageModel{
	"bfl:7@1":                     {ImageSpec: media.Flux2Max, dims: media.ImageDims{Base: media.StandardSizes}},
	"bfl:5@1":                     {ImageSpec: media.Flux2Pro, dims: media.ImageDims{Base: media.StandardSizes}},
	"bytedance:seedream@5.0-pro":  {ImageSpec: media.Seedream5Pro, dims: media.ImageDims{Base: media.StandardSizes}},
	"bytedance:seedream@5.0-lite": {ImageSpec: media.Seedream5Lite, dims: media.ImageDims{Base: seedream5LiteSizes}, maxPrompt: 3_000},
	"bytedance:seedream@4.5":      {ImageSpec: media.Seedream45, dims: media.ImageDims{Base: seedream45Sizes}, maxPrompt: 3_000},
	"alibaba:qwen-image@3.0-pro":  {ImageSpec: media.QwenImage3, dims: media.ImageDims{Base: media.StandardSizes}},
	"ideogram:4.5@0":              {ImageSpec: media.Ideogram45, dims: media.ImageDims{Base: media.StandardSizes, Text: media.IdeogramSizes}},
	"civitai:312530@1457203":      {ImageSpec: media.SDXLCheckpoint, dims: sdxl, checkpoint: checkpoint{steps: 30, cfg: 4, scheduler: "DPM++ 2M SDE Karras"}},
	"civitai:139562@789646":       {ImageSpec: media.SDXLCheckpoint, dims: sdxl, checkpoint: checkpoint{steps: 30, scheduler: "DPM++ SDE Karras"}},
	"civitai:1125067@1471829": {ImageSpec: media.SDXLCheckpoint, dims: sdxl, checkpoint: checkpoint{
		steps: 30, cfg: 4.5, scheduler: "DPM++ 2M Karras", tags: "masterpiece, best quality, high quality, ultra-detailed, realistic",
	}},
	"civitai:140272@1617798": {ImageSpec: media.SDXLCheckpoint, dims: sdxl, checkpoint: checkpoint{
		steps: 28, cfg: 6, scheduler: "Euler a", tags: "masterpiece, best quality",
	}},
}

type Images struct {
	vendor upstream.Endpoint
	imageModel
	model string
	Poll  time.Duration
}

func NewImages(baseURL, apiKey, model string, httpClient *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "runware")
	if err != nil {
		return nil, err
	}
	return &Images{vendor: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: httpClient}, imageModel: info, model: model}, nil
}

func (p *Images) CheckImages(req *media.ImageRequest) error {
	if err := p.ImageSpec.CheckImages(req); err != nil {
		return err
	}
	if p.maxPrompt > 0 && utf8.RuneCountInString(req.Prompt()) > p.maxPrompt {
		return strictjson.Invalid(fmt.Sprintf("prompt must be at most %d characters for this model.", p.maxPrompt))
	}
	return nil
}

type imageInputs struct {
	ReferenceImages []string `json:"referenceImages"`
}

type imageSettings struct {
	Quality string `json:"quality"`
}

type imageTask struct {
	TaskType       string         `json:"taskType"`
	TaskUUID       string         `json:"taskUUID"`
	Model          string         `json:"model"`
	PositivePrompt string         `json:"positivePrompt"`
	Width          int            `json:"width"`
	Height         int            `json:"height"`
	Steps          int            `json:"steps,omitempty"`
	CFGScale       float64        `json:"CFGScale,omitempty"`
	Scheduler      string         `json:"scheduler,omitempty"`
	NumberResults  int            `json:"numberResults"`
	OutputType     string         `json:"outputType"`
	OutputFormat   string         `json:"outputFormat"`
	IncludeCost    bool           `json:"includeCost"`
	DeliveryMethod string         `json:"deliveryMethod"`
	Inputs         *imageInputs   `json:"inputs,omitempty"`
	Settings       *imageSettings `json:"settings,omitempty"`
}

func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	dims := p.dims.For(req)
	task := imageTask{
		TaskType: "imageInference", TaskUUID: uuid.Format(uuid.New()), Model: p.model, PositivePrompt: p.prompt(req.Prompt()),
		Width: dims.Width, Height: dims.Height, Steps: p.steps, CFGScale: p.cfg, Scheduler: p.scheduler, NumberResults: req.N,
		// Runware prices by compute, not by request: the same request cost $0.0013 and then $0.0019
		// (2026-10-03).
		OutputType: "base64Data", OutputFormat: "JPG", IncludeCost: true, DeliveryMethod: "async",
	}
	if refs := req.References(); len(refs) > 0 {
		task.Inputs = &imageInputs{ReferenceImages: refs}
	}
	if req.Quality != "" {
		task.Settings = &imageSettings{Quality: req.Quality}
	}
	if _, err := send(ctx, p.vendor, task, media.MaxImagesBody); err != nil {
		return media.Images{}, err
	}
	var out media.Images
	seen := map[string]bool{}
	err := media.PollUntil(ctx, p.Poll, func(ctx context.Context) (bool, error) {
		r, err := send(ctx, p.vendor, pollTask(task.TaskUUID), media.MaxImagesBody)
		final := upstream.Final(err, upstream.UnusableEnds)
		if err != nil && !final {
			return false, nil
		}
		for _, item := range r.Data {
			key := cmp.Or(item.ImageUUID, item.ImageBase64Data)
			if item.Status != "success" || seen[key] {
				continue
			}
			seen[key] = true
			img, err := media.NewImage(item.ImageBase64Data)
			if err != nil {
				return true, err
			}
			out.List = append(out.List, img)
			out.Cost = out.Cost.Add(cost(item).Delivered())
		}
		return final || len(out.List) >= req.N, err
	})
	return out.Partial(req.N, err)
}
