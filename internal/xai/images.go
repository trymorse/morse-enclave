package xai

import (
	"context"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

var imageModels = map[string]media.ImageSpec{
	"grok-imagine-image-2.0": {MaxReferences: 5, Qualities: []string{"low", "medium"}},
}

type Images struct {
	vendor upstream.Endpoint
	media.ImageSpec
	model string
}

func NewImages(baseURL, apiKey, model string, httpClient *http.Client) (*Images, error) {
	spec, err := media.Lookup(imageModels, media.ImageModel, model, "xai")
	if err != nil {
		return nil, err
	}
	return &Images{vendor: endpoint(baseURL, apiKey, httpClient, confirmZeroRetention), ImageSpec: spec, model: model}, nil
}

type imageRef struct {
	URL string `json:"url"`
}

type imageRequest struct {
	Model          string     `json:"model"`
	Prompt         string     `json:"prompt"`
	N              int        `json:"n"`
	ResponseFormat string     `json:"response_format"`
	AspectRatio    string     `json:"aspect_ratio"`
	Resolution     string     `json:"resolution"`
	Quality        string     `json:"quality,omitempty"`
	Image          *imageRef  `json:"image,omitempty"`
	Images         []imageRef `json:"images,omitempty"`
}

type imageReply struct {
	Data []struct {
		B64JSON           string `json:"b64_json"`
		RespectModeration *bool  `json:"respect_moderation"`
	} `json:"data"`
	Usage usage `json:"usage"`
}

func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	body := imageRequest{
		Model: p.model, Prompt: req.Prompt(), N: req.N, ResponseFormat: "b64_json",
		AspectRatio: req.Size.AspectRatio, Resolution: req.Size.Resolution, Quality: req.Quality,
	}
	path := "/v1/images/generations"
	if refs := req.References(); len(refs) == 1 {
		body.Image, path = &imageRef{URL: refs[0]}, "/v1/images/edits"
	} else if len(refs) > 1 {
		for _, ref := range refs {
			body.Images = append(body.Images, imageRef{URL: ref})
		}
		path = "/v1/images/edits"
	}
	var reply imageReply
	if _, err := p.vendor.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: path, Body: jsonx.Encode(body)}, &reply, media.MaxImagesBody); err != nil {
		return media.Images{}, err
	}
	var out media.Images
	out.Cost = reply.Usage.cost()
	for _, d := range reply.Data {
		if d.RespectModeration != nil && !*d.RespectModeration {
			return out, apierr.ErrContentFilter
		}
		img, err := media.NewImage(d.B64JSON)
		if err != nil {
			return out, err
		}
		out.List = append(out.List, img)
	}
	if len(out.List) == 0 {
		return out, upstream.ErrMalformed
	}
	return out, nil
}
