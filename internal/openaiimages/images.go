package openaiimages

import (
	"context"
	"fmt"
	"net/http"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

type rates struct{ textIn, imageIn, imageOut money.Micros }

type imageModel struct {
	media.ImageSpec
	sizes    map[media.Size]media.Dims
	perImage money.Micros
	rates    rates
}

// why: Meta bills Muse Image $0.01 an image and reads size as an aspect ratio only (dev.meta.ai/docs/image-generation,
// 2026-11-22); OpenAI bills GPT Image 2.6 $5/M text in, $8/M image in, $30/M image out (developers.openai.com/api/docs/pricing),
// and took 1376x768 and 2048x2048 from the standard sizes in probes that day.
var imageModels = map[string]imageModel{
	"muse-image-1.0":         {ImageSpec: media.MuseImage, sizes: media.StandardSizes, perImage: 10_000},
	"gpt-image-2.6-sunburst": {ImageSpec: media.GPTImage26, sizes: media.StandardSizes, rates: rates{textIn: 5_000_000, imageIn: 8_000_000, imageOut: 30_000_000}},
}

type Images struct {
	vendor upstream.Endpoint
	imageModel
	model string
}

func NewImages(baseURL, apiKey, model string, client *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "the OpenAI images API")
	if err != nil {
		return nil, err
	}
	vendor := upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}
	return &Images{vendor: vendor, imageModel: info, model: model}, nil
}

type imageRef struct {
	ImageURL string `json:"image_url"`
}

type imageRequest struct {
	Model   string     `json:"model"`
	Prompt  string     `json:"prompt"`
	N       int        `json:"n"`
	Size    string     `json:"size"`
	Quality string     `json:"quality,omitempty"`
	Images  []imageRef `json:"images,omitempty"`
}

type tokens struct {
	Text  int64 `json:"text_tokens"`
	Image int64 `json:"image_tokens"`
}

type usage struct {
	OutputTokens int64   `json:"output_tokens"`
	InputDetails *tokens `json:"input_tokens_details"`
}

type imageReply struct {
	Data []struct {
		B64JSON string `json:"b64_json"`
	} `json:"data"`
	Usage *usage `json:"usage"`
}

func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	dims, ok := p.sizes[req.Size]
	if !ok {
		return media.Images{}, fmt.Errorf("openaiimages: %s has no size for %s at %s", p.model, req.Size.AspectRatio, req.Size.Resolution)
	}
	body := imageRequest{Model: p.model, Prompt: req.Prompt(), N: req.N, Size: fmt.Sprintf("%dx%d", dims.Width, dims.Height), Quality: req.Quality}
	path := "/v1/images/generations"
	for _, ref := range req.References() {
		body.Images, path = append(body.Images, imageRef{ImageURL: ref}), "/v1/images/edits"
	}
	var reply imageReply
	if _, err := p.vendor.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: path, Body: jsonx.Encode(body)}, &reply, media.MaxImagesBody); err != nil {
		return media.Images{}, err
	}
	out := media.Images{Cost: p.cost(len(reply.Data), reply.Usage)}
	for _, d := range reply.Data {
		img, err := media.NewImage(d.B64JSON)
		if err != nil {
			return out, err
		}
		out.List = append(out.List, img)
	}
	return out.Partial(req.N, nil)
}

func (p *Images) cost(generated int, u *usage) money.Reported {
	if p.perImage > 0 {
		return money.ReportedCost(money.Micros(generated) * p.perImage)
	}
	if u == nil || u.InputDetails == nil {
		if generated == 0 {
			return money.Reported{}
		}
		return money.Reported{}.Delivered()
	}
	perMillion := money.Micros(u.InputDetails.Text)*p.rates.textIn + money.Micros(u.InputDetails.Image)*p.rates.imageIn + money.Micros(u.OutputTokens)*p.rates.imageOut
	return money.ReportedCost(money.PerMTok(perMillion))
}
