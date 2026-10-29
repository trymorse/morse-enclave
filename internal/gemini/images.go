package gemini

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/completions"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

const modalityImage = "IMAGE"

// rates are Google's list prices in micros per million tokens: the prompt, text and thinking out, and image out.
type rates struct{ prompt, text, image money.Micros }

type imageModel struct {
	media.ImageSpec
	rates rates
}

// https://ai.google.dev/gemini-api/docs/pricing, checked 2026-10-09. The dearest image a route draws is 1,120
// tokens on Pro at 1K or 2K ($0.134), 1,680 on Nano Banana 2 at 2K ($0.101) and 1,120 on Lite at 1K ($0.0336).
var imageModels = map[string]imageModel{
	"gemini-3-pro-image":          {ImageSpec: media.NanoBananaPro, rates: rates{prompt: 2_000_000, text: 12_000_000, image: 120_000_000}},
	"gemini-3.1-flash-image":      {ImageSpec: media.NanoBanana2, rates: rates{prompt: 500_000, text: 3_000_000, image: 60_000_000}},
	"gemini-3.1-flash-lite-image": {ImageSpec: media.NanoBanana2Lite, rates: rates{prompt: 250_000, text: 1_500_000, image: 30_000_000}},
}

type Images struct {
	vendor upstream.Endpoint
	imageModel
	model string
}

func NewImages(baseURL, apiKey, model string, client *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "gemini")
	if err != nil {
		return nil, err
	}
	return &Images{vendor: endpoint(baseURL, apiKey, client), imageModel: info, model: model}, nil
}

type imageConfig struct {
	AspectRatio string `json:"aspectRatio"`
	ImageSize   string `json:"imageSize"`
}

func imageBody(req *media.ImageRequest) []byte {
	parts := []part{{Text: req.Prompt()}}
	for _, image := range req.ReferenceImages() {
		parts = append(parts, part{InlineData: &blob{MIMEType: image.MediaType, Data: image.Base64}})
	}
	return jsonx.Encode(request{
		Contents: []content{{Role: roleUser, Parts: parts}},
		GenerationConfig: generationConfig{
			ResponseModalities: []string{modalityImage},
			ImageConfig:        &imageConfig{AspectRatio: req.Size.AspectRatio, ImageSize: strings.ToUpper(req.Size.Resolution)},
		},
	})
}

// Gemini makes one image a request, so n images are n requests at once.
func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	body := imageBody(req)
	runs := make([]media.Images, req.N)
	errs := make([]error, req.N)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Go(func() { runs[i], errs[i] = p.generate(ctx, body) })
	}
	wg.Wait()
	var out media.Images
	for _, r := range runs {
		out.List = append(out.List, r.List...)
		out.Cost = out.Cost.Add(r.Cost)
	}
	return out.Partial(req.N, cmp.Or(errs...))
}

// The stream sends the reply's headers before the image is drawn, which can take Pro past the proxy's
// two-minute wait for a vendor's headers.
func (p *Images) generate(ctx context.Context, body []byte) (media.Images, error) {
	resp, err := p.vendor.Open(ctx, upstream.Request{Method: http.MethodPost, Path: streamPath(p.model), Header: http.Header{"Accept": {streamAccept}}, Body: body})
	if err != nil {
		return media.Images{}, err
	}
	defer resp.Body.Close()
	var d drawing
	err = sse.Each(resp.Body, media.MaxImagesBody, sse.Refuse, func(data []byte) (bool, error) {
		var e streamChunk
		if err := json.Unmarshal(data, &e); err != nil {
			return false, upstream.ErrMalformed
		}
		return false, d.chunk(e)
	})
	return d.result(p.rates, err)
}

type drawing struct {
	out     media.Images
	usage   *usageWire
	ended   bool
	refused bool
}

func (d *drawing) chunk(e streamChunk) error {
	d.usage = cmp.Or(e.UsageMetadata, d.usage)
	if e.Error != nil {
		return e.Error.refusal()
	}
	for _, p := range e.parts() {
		if p.InlineData == nil || p.Thought || !strings.HasPrefix(p.InlineData.MIMEType, "image/") {
			continue
		}
		img, err := media.NewImage(p.InlineData.Data)
		if err != nil {
			return err
		}
		d.out.List = append(d.out.List, img)
	}
	if finish, ended := e.end(); ended {
		d.ended, d.refused = true, d.refused || finish == completions.FinishContentFilter
	}
	return nil
}

func (d *drawing) result(r rates, err error) (media.Images, error) {
	if d.ended && errors.Is(err, sse.ErrTruncated) {
		err = nil
	}
	d.out.Cost = r.cost(d.usage)
	switch {
	case len(d.out.List) > 0:
		d.out.Cost = d.out.Cost.Delivered()
	case err == nil && d.refused:
		err = apierr.ErrContentFilter
	case err == nil:
		err = media.ErrNoImages
	}
	return d.out, err
}

func (r rates) cost(u *usageWire) money.Reported {
	if u == nil {
		return money.Reported{}
	}
	image := u.CandidatesTokenCount
	if u.CandidatesTokensDetails != nil {
		image = 0
		for _, d := range u.CandidatesTokensDetails {
			if d.Modality == modalityImage {
				image += d.TokenCount
			}
		}
	}
	text := u.CandidatesTokenCount - image + u.ThoughtsTokenCount
	perMillion := money.Micros(u.PromptTokenCount)*r.prompt + money.Micros(text)*r.text + money.Micros(image)*r.image
	return money.ReportedCost(money.PerMTok(perMillion))
}
