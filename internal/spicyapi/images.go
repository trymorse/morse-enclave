package spicyapi

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"unicode/utf8"

	"morse/backend/internal/dataurl"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/uuid"
)

const (
	maxPrompt    = 5_000
	maxReference = 10 << 20
)

type imageModel struct {
	media.ImageSpec
	edit           string
	sendsExpansion bool
	sendsThinking  bool
	sizes          map[media.Size]media.Dims
	editsOne       bool
}

// why: spicyapi.ai's catalog (GET /console/v1/catalog/models/{model}, inputSchema, 2026-11-17) refuses a field a schema
// does not list, and turns on prompt expansion (Qwen 3) and thinking (Qwen 2.1 Turbo, Seedream), which rewrite the prompt.
var imageModels = map[string]imageModel{
	"alibaba/qwen-image-2.1-turbo/text-to-image": {
		ImageSpec: unchecked(10), edit: "alibaba/qwen-image-2.1-turbo/edit", sendsExpansion: true, sendsThinking: true,
	},
	"alibaba/qwen-image-3.0-pro/text-to-image": {
		ImageSpec: unchecked(3), edit: "alibaba/qwen-image-3.0-pro/edit", sendsExpansion: true,
	},
	"alibaba/qwen-image-3.0/text-to-image": {
		ImageSpec: unchecked(3), edit: "alibaba/qwen-image-3.0/edit", sendsExpansion: true,
	},
	"bytedance/seedream-5.0-pro/text-to-image": {
		ImageSpec: unchecked(10), edit: "bytedance/seedream-5.0-pro/edit", sendsThinking: true,
	},
	"krea/2-turbo-lora/text-to-image": {ImageSpec: unchecked(0)},
	"bytedance/seedream-5.5/text-to-image": {
		ImageSpec: media.ImageSpec{AspectRatios: append(slices.Clone(media.SevenRatios), "21:9"), Resolutions: media.UpTo2K, MaxReferences: 10},
		edit:      "bytedance/seedream-5.5/edit",
	},
	"circlestone-labs/anima-turbo/text-to-image": {ImageSpec: media.ImageSpec{AspectRatios: media.AspectRatios, Resolutions: []string{"1k"}}},
	// why: the adult fine-tunes' inputSchema (GET https://api.spicyapi.ai/api/v1/models/{model}, 2026-11-22) takes width and
	// height, at most 1536 on Z-Image Spicy and 2560 on its Pro, and Qwen Image Edit Spicy one image_url and no size, so
	// its edit keeps the shape of the image it edits.
	"alibaba/z-image-spicy/text-to-image": {
		ImageSpec: media.ImageSpec{AspectRatios: media.SevenRatios, Resolutions: []string{"1k"}}, sizes: media.StandardSizes, sendsExpansion: true,
	},
	"alibaba/z-image-spicy-pro/text-to-image": {
		ImageSpec: media.ImageSpec{AspectRatios: media.AspectRatios, Resolutions: media.UpTo2K}, sizes: media.StandardSizes, sendsExpansion: true,
	},
	"alibaba/qwen-image-spicy-edit/edit": {
		ImageSpec: media.ImageSpec{AspectRatios: media.SevenRatios, Resolutions: []string{"1k"}, MaxReferences: 1}, editsOne: true,
	},
}

func unchecked(references int) media.ImageSpec {
	return media.ImageSpec{AspectRatios: media.SevenRatios, Resolutions: media.UpTo2K, MaxReferences: references}
}

type Images struct {
	client
	imageModel
	model string
}

func NewImages(baseURL, apiKey, model string, httpClient *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "spicyapi")
	if err != nil {
		return nil, err
	}
	return &Images{client: newClient(baseURL, apiKey, httpClient), imageModel: info, model: model}, nil
}

// why: every spicyapi image route is uncensored, and each asks the photo promise before it takes an uploaded picture.
func (p *Images) FramesNeedConsent() bool { return true }

func (p *Images) CheckImages(req *media.ImageRequest) error {
	if err := p.ImageSpec.CheckImages(req); err != nil {
		return err
	}
	if utf8.RuneCountInString(req.Prompt()) > maxPrompt {
		return strictjson.Invalid(fmt.Sprintf("prompt must be at most %d characters for this model.", maxPrompt))
	}
	if p.editsOne && len(req.ReferenceImages()) != 1 {
		return strictjson.Invalid("This model takes exactly one image.")
	}
	for _, ref := range req.ReferenceImages() {
		if base64.StdEncoding.DecodedLen(len(ref.Base64)) > maxReference {
			return strictjson.Invalid(fmt.Sprintf("Reference images must be at most %d MiB each for this model.", maxReference>>20))
		}
	}
	return nil
}

// why: every model's resolution enum on https://api.spicyapi.ai/console/v1/catalog/models/{model}?locale=en
// (2026-11-17) spells 1K and 2K as Morse does, "1k" and "2k".
type input struct {
	Prompt                string   `json:"prompt"`
	AspectRatio           string   `json:"aspect_ratio,omitempty"`
	Resolution            string   `json:"resolution,omitempty"`
	Width                 int      `json:"width,omitempty"`
	Height                int      `json:"height,omitempty"`
	ImageURL              string   `json:"image_url,omitempty"`
	ImageURLs             []string `json:"image_urls,omitempty"`
	EnablePromptExpansion *bool    `json:"enable_prompt_expansion,omitempty"`
	EnableThinking        *bool    `json:"enable_thinking,omitempty"`
}

var off = new(bool)

func (p *Images) task(req *media.ImageRequest, refs []string) task {
	in := input{Prompt: req.Prompt()}
	switch {
	case p.editsOne:
		in.ImageURL = refs[0]
	case p.sizes != nil:
		d := p.sizes[req.Size]
		in.Width, in.Height = d.Width, d.Height
	default:
		in.AspectRatio, in.Resolution, in.ImageURLs = req.Size.AspectRatio, req.Size.Resolution, refs
	}
	if p.sendsExpansion {
		in.EnablePromptExpansion = off
	}
	if p.sendsThinking {
		in.EnableThinking = off
	}
	model := p.model
	if len(refs) > 0 && p.edit != "" {
		model = p.edit
	}
	return task{Model: model, Input: in}
}

func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	runs := make([]media.Images, req.N)
	errs := make([]error, req.N)
	var wg sync.WaitGroup
	for i := range req.N {
		wg.Go(func() { runs[i], errs[i] = p.run(ctx, req) })
	}
	wg.Wait()
	var out media.Images
	for _, r := range runs {
		out.List = append(out.List, r.List...)
		out.Cost = out.Cost.Add(r.Cost)
	}
	return out.Partial(req.N, cmp.Or(errs...))
}

func (c client) uploadAll(ctx context.Context, images []dataurl.URL) ([]string, error) {
	uris := make([]string, len(images))
	errs := make([]error, len(images))
	var wg sync.WaitGroup
	for i, image := range images {
		wg.Go(func() {
			data, err := base64.StdEncoding.DecodeString(image.Base64)
			if err != nil {
				errs[i] = strictjson.Invalid("Reference images must be base64 data URLs of PNG, JPEG, or WebP images.")
				return
			}
			uris[i], errs[i] = c.upload(ctx, image.MediaType, data)
		})
	}
	wg.Wait()
	if err := cmp.Or(errs...); err != nil {
		return nil, err
	}
	return uris, nil
}

func (p *Images) run(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	refs, err := p.uploadAll(ctx, req.ReferenceImages())
	if err != nil {
		return media.Images{}, err
	}
	rec, err := p.create(ctx, p.task(req, refs), uuid.Format(uuid.New()), waitSeconds, retention)
	if err != nil {
		return media.Images{}, err
	}
	defer p.purge(ctx, rec.TaskID)
	rec, err = p.await(ctx, rec)
	if err != nil {
		return media.Images{}, err
	}
	if rec.State != succeeded {
		return media.Images{Cost: p.settle(ctx, rec).cost()}, failure(rec.ErrorCode)
	}
	var imgs []media.Image
	for _, a := range rec.Output.Assets {
		if a.Unavailable || a.URL == "" {
			continue
		}
		img, err := p.fetch(ctx, a.URL)
		if err != nil {
			return p.delivered(ctx, rec, imgs), err
		}
		imgs = append(imgs, img)
	}
	if len(imgs) == 0 {
		return media.Images{}, media.ErrNoImages
	}
	return p.delivered(ctx, rec, imgs), nil
}

func (p *Images) delivered(ctx context.Context, rec record, imgs []media.Image) media.Images {
	if len(imgs) == 0 {
		return media.Images{}
	}
	return media.Images{List: imgs, Cost: p.settle(ctx, rec).cost().Delivered()}
}
