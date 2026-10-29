package fal

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/dataurl"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

type imageModel struct {
	media.ImageSpec
	dims        media.ImageDims
	edit        string
	unit        money.Micros
	numImages   bool
	format      string
	sourceImage bool
}

// FLUX bills whole megapixels rounded up, so 16:9 at 1k is 1360x768 (1 MP) and not 1376x768,
// which bills 2 MP (measured 2026-10-03). Both are multiples of 16, which FLUX.2 needs.
var fluxSizes = media.SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1360, 768}, "9:16 1k": {768, 1360}, "4:3 1k": {1152, 864},
	"3:4 1k": {864, 1152}, "3:2 1k": {1248, 832}, "2:3 1k": {832, 1248},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2048, 1152}, "9:16 2k": {1152, 2048}, "4:3 2k": {2048, 1536},
	"3:4 2k": {1536, 2048}, "3:2 2k": {1920, 1280}, "2:3 2k": {1280, 1920},
})

var seedreamSizes = media.SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1376, 768}, "9:16 1k": {768, 1376}, "4:3 1k": {1216, 912},
	"3:4 1k": {912, 1216}, "3:2 1k": {1296, 864}, "2:3 1k": {864, 1296},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2048, 1152}, "9:16 2k": {1152, 2048}, "4:3 2k": {2048, 1536},
	"3:4 2k": {1536, 2048}, "3:2 2k": {1920, 1280}, "2:3 2k": {1280, 1920},
})

var imageModels = map[string]imageModel{
	"fal-ai/flux-2-max": {
		edit: "fal-ai/flux-2-max/edit", ImageSpec: media.Flux2Max, dims: media.ImageDims{Base: fluxSizes}, unit: 70_000, format: "jpeg",
	},
	"fal-ai/flux-2-pro": {
		edit: "fal-ai/flux-2-pro/edit", ImageSpec: media.Flux2Pro, dims: media.ImageDims{Base: fluxSizes}, unit: 30_000, format: "jpeg",
	},
	"bytedance/seedream/v5/pro/text-to-image": {
		edit: "bytedance/seedream/v5/pro/edit", ImageSpec: media.Seedream5Pro, dims: media.ImageDims{Base: seedreamSizes}, unit: 67_500, numImages: true, format: "jpeg",
	},
	"ideogram/v4.5": {
		edit: "ideogram/v4.5/edit", ImageSpec: media.Ideogram45, dims: media.ImageDims{Base: media.StandardSizes, Text: media.IdeogramSizes}, unit: 1_000, numImages: true, sourceImage: true,
	},
	"alibaba/qwen-image-3/text-to-image": {
		edit: "alibaba/qwen-image-3/edit", ImageSpec: media.QwenImage3, dims: media.ImageDims{Base: media.StandardSizes}, unit: 10_000, numImages: true, format: "jpeg",
	},
	"fal-ai/z-image/turbo": {
		ImageSpec: media.ZImageTurbo, dims: media.ImageDims{Base: fluxSizes}, unit: 5_000, numImages: true, format: "jpeg",
	},
}

type Images struct {
	client
	imageModel
	model string
	Poll  time.Duration
}

func NewImages(baseURL, apiKey, model string, httpClient *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "fal")
	if err != nil {
		return nil, err
	}
	return &Images{client: newClient(baseURL, apiKey, httpClient), imageModel: info, model: model}, nil
}

type imageSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type imageInput struct {
	Prompt             string    `json:"prompt"`
	ImageSize          imageSize `json:"image_size"`
	NumImages          int       `json:"num_images,omitempty"`
	OutputFormat       string    `json:"output_format,omitempty"`
	Quality            string    `json:"quality,omitempty"`
	SyncMode           bool      `json:"sync_mode"`
	ImageURLs          []string  `json:"image_urls,omitempty"`
	ImageURL           string    `json:"image_url,omitempty"`
	ReferenceImageURLs []string  `json:"reference_image_urls,omitempty"`
}

type imageOutput struct {
	Images []struct {
		URL string `json:"url"`
	} `json:"images"`
	HasNSFWConcepts []bool `json:"has_nsfw_concepts"`
}

func (p *Images) input(req *media.ImageRequest) (string, imageInput) {
	refs := req.References()
	dims := p.dims.For(req)
	in := imageInput{
		Prompt: req.Prompt(), ImageSize: imageSize{Width: dims.Width, Height: dims.Height},
		OutputFormat: p.format, Quality: req.Quality, SyncMode: true,
	}
	if p.numImages {
		in.NumImages = req.N
	}
	if len(refs) == 0 {
		return p.model, in
	}
	if p.sourceImage {
		in.ImageURL, in.ReferenceImageURLs = refs[0], refs[1:]
	} else {
		in.ImageURLs = refs
	}
	return p.edit, in
}

type run struct {
	out   media.Images
	err   error
	final bool
}

func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	return p.GenerateImagesUntil(ctx, nil, req)
}

func (p *Images) GenerateImagesUntil(ctx context.Context, left <-chan struct{}, req *media.ImageRequest) (media.Images, error) {
	select {
	case <-left:
		return media.Images{}, context.Canceled
	default:
	}
	untilCallerLeaves, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-left:
			stop()
		case <-untilCallerLeaves.Done():
		}
	}()
	deadline, _ := ctx.Deadline()
	endpoint, in := p.input(req)
	runs := make([]run, 1)
	if !p.numImages {
		runs = make([]run, req.N)
	}
	var wg sync.WaitGroup
	for i := range runs {
		wg.Go(func() { runs[i] = p.generate(ctx, untilCallerLeaves, endpoint, in, startBy(deadline)) })
	}
	wg.Wait()
	var out media.Images
	var final, retried error
	for _, r := range runs {
		out.List = append(out.List, r.out.List...)
		out.Cost = out.Cost.Add(r.out.Cost)
		if r.final {
			final = cmp.Or(final, r.err)
		} else {
			retried = cmp.Or(retried, r.err)
		}
	}
	return out.Partial(req.N, cmp.Or(final, retried, untilCallerLeaves.Err()))
}

// fal may still finish, and bill, a request it had started before its caller left, so after the cancel the request
// waits for fal's last word while ctx lasts.
func (p *Images) generate(ctx, untilCallerLeaves context.Context, endpoint string, in imageInput, startBy time.Duration) run {
	id, err := p.submit(ctx, endpoint, in, startBy)
	if err != nil {
		return run{err: err, final: true}
	}
	var r run
	app := app(p.model)
	poll := func(ctx context.Context) {
		media.PollUntil(ctx, p.Poll, func(ctx context.Context) (bool, error) {
			done, err := p.collect(ctx, app, id, &r.out)
			if done || err != nil && ctx.Err() == nil {
				r.final, r.err = done, err
			}
			return done, nil
		})
	}
	poll(untilCallerLeaves)
	if !r.final {
		p.cancel(ctx, app, id)
		poll(ctx)
	}
	return r
}

var _ media.Canceller = (*Images)(nil)

func (p *Images) collect(ctx context.Context, app, id string, out *media.Images) (bool, error) {
	o, r, err := p.await(ctx, app, id, media.MaxImagesBody, p.unit)
	switch o {
	case stillQueued:
		return upstream.Final(err, upstream.UnusableEnds), err
	case finalFailure:
		out.Cost = out.Cost.Add(r.cost)
		return true, err
	}
	out.Cost = out.Cost.Add(r.cost.Delivered())
	imgs, err := decodeImages(r.Body)
	out.List = append(out.List, imgs...)
	return true, err
}

func decodeImages(body []byte) ([]media.Image, error) {
	var reply imageOutput
	if json.Unmarshal(body, &reply) != nil || len(reply.Images) == 0 {
		return nil, upstream.ErrMalformed
	}
	var imgs []media.Image
	for i, item := range reply.Images {
		if i < len(reply.HasNSFWConcepts) && reply.HasNSFWConcepts[i] {
			continue
		}
		inline, err := dataurl.Parse(item.URL)
		if err != nil {
			return imgs, upstream.ErrMalformed
		}
		img, err := media.NewImage(inline.Base64)
		if err != nil {
			return imgs, err
		}
		imgs = append(imgs, img)
	}
	if len(imgs) == 0 {
		return nil, apierr.ErrContentFilter
	}
	return imgs, nil
}
