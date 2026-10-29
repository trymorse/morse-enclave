package venice

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
)

const (
	contentPolicy = "CONTENT_POLICY_VIOLATION"
	generatePath  = "/v1/image/generate"
	editPath      = "/v1/image/multi-edit"
)

type perImage struct{ oneK, twoK money.Micros }

func (p perImage) at(resolution string) money.Micros {
	if resolution == "2k" {
		return p.twoK
	}
	return p.oneK
}

// edit is the Venice model that takes a request's reference images, all in one call. It draws as its text model
// does, at its price, with each reference past the first included at perReference.
type edit struct {
	model        string
	references   int
	included     int
	perReference money.Micros
}

type imageModel struct {
	ratios    []string
	maxPrompt int
	price     perImage
	edit
}

var (
	noFourThree = []string{"1:1", "3:2", "16:9", "21:9", "9:16", "2:3", "3:4", "4:5"}
	seedream5   = []string{"1:1", "3:2", "16:9", "9:16", "2:3", "3:4", "4:3"}
)

// Venice's list price per image at its 1K and 2K tiers and the ratios each model takes, from GET /models?type=image,
// and its edit model's from ?type=inpaint, on 2026-10-29. Qwen 3's edit models list no maxInputImages, which Venice's
// docs read as three.
var imageModels = map[string]imageModel{
	"seedream-v5-pro":      {ratios: seedream5, maxPrompt: 10_000, price: perImage{60_000, 110_000}, edit: edit{"seedream-v5-pro-edit", 6, 1, 3_450}},
	"qwen-image-3-pro":     {ratios: noFourThree, maxPrompt: 10_000, price: perImage{50_000, 90_000}, edit: edit{"qwen-image-3-pro-edit", 3, 0, 3_450}},
	"qwen-image-3":         {ratios: noFourThree, maxPrompt: 10_000, price: perImage{40_000, 40_000}, edit: edit{"qwen-image-3-edit", 3, 0, 3_450}},
	"qwen-image-2-1-turbo": {ratios: noFourThree, maxPrompt: 10_000, price: perImage{20_000, 20_000}, edit: edit{"qwen-image-2-1-turbo-edit", 6, 0, 0}},
	"krea-2-turbo":         {ratios: noFourThree, maxPrompt: 5_000, price: perImage{40_000, 60_000}},
}

// Images draws on Venice's /image/generate, or with reference images on /image/multi-edit, with safe mode off, so
// Venice blurs nothing it returns. Venice prices each image by its list alone and reports no cost, so the cost is
// that list price.
type Images struct {
	vendor upstream.Endpoint
	imageModel
	model string
}

func NewImages(baseURL, apiKey, model string, client *http.Client) (*Images, error) {
	info, err := media.Lookup(imageModels, media.ImageModel, model, "venice")
	if err != nil {
		return nil, err
	}
	vendor := upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client, Refuse: refusal}
	return &Images{vendor: vendor, imageModel: info, model: model}, nil
}

func (p *Images) CheckImages(req *media.ImageRequest) error {
	if err := (media.ImageSpec{MaxReferences: p.references}).CheckImages(req); err != nil {
		return err
	}
	if utf8.RuneCountInString(req.Prompt()) > p.maxPrompt {
		return strictjson.Invalid(fmt.Sprintf("prompt must be at most %d characters for this model.", p.maxPrompt))
	}
	return nil
}

type generateRequest struct {
	Model         string `json:"model"`
	Prompt        string `json:"prompt"`
	AspectRatio   string `json:"aspect_ratio"`
	Resolution    string `json:"resolution"`
	Format        string `json:"format"`
	SafeMode      bool   `json:"safe_mode"`
	HideWatermark bool   `json:"hide_watermark"`
	ReturnBinary  bool   `json:"return_binary"`
}

type editRequest struct {
	ModelID      string   `json:"modelId"`
	Prompt       string   `json:"prompt"`
	Images       []string `json:"images"`
	AspectRatio  string   `json:"aspect_ratio"`
	Resolution   string   `json:"resolution"`
	OutputFormat string   `json:"output_format"`
	SafeMode     bool     `json:"safe_mode"`
}

type draw struct {
	path  string
	body  []byte
	read  func([]byte) (media.Image, error)
	price money.Micros
}

func (p *Images) draw(req *media.ImageRequest) draw {
	ratio, resolution := nearest(req.Size.AspectRatio, p.ratios), strings.ToUpper(req.Size.Resolution)
	price := p.price.at(req.Size.Resolution)
	refs := req.References()
	if len(refs) == 0 {
		body := generateRequest{Model: p.model, Prompt: req.Prompt(), AspectRatio: ratio, Resolution: resolution, Format: "png", HideWatermark: true}
		return draw{path: generatePath, body: jsonx.Encode(body), read: generated, price: price}
	}
	body := editRequest{ModelID: p.edit.model, Prompt: req.Prompt(), Images: refs, AspectRatio: ratio, Resolution: resolution, OutputFormat: "png"}
	price += money.Micros(max(len(refs)-p.included, 0)) * p.perReference
	return draw{path: editPath, body: jsonx.Encode(body), read: media.ImageOf, price: price}
}

// One request draws one image, so n images are n requests at once.
func (p *Images) GenerateImages(ctx context.Context, req *media.ImageRequest) (media.Images, error) {
	d := p.draw(req)
	runs := make([]media.Images, req.N)
	errs := make([]error, req.N)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Go(func() { runs[i], errs[i] = p.generate(ctx, d) })
	}
	wg.Wait()
	var out media.Images
	for _, r := range runs {
		out.List = append(out.List, r.List...)
		out.Cost = out.Cost.Add(r.Cost)
	}
	return out.Partial(req.N, cmp.Or(errs...))
}

// The edit endpoint answers with the image's bytes, and the generate endpoint with them in JSON.
func (p *Images) generate(ctx context.Context, d draw) (media.Images, error) {
	r, err := p.vendor.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: d.path, Header: http.Header{"Accept": {"*/*"}}, Body: d.body}, nil, media.MaxImagesBody)
	switch {
	case err != nil:
		return media.Images{}, err
	case r.Header.Get("X-Venice-Is-Content-Violation") == "true" || r.Header.Get("X-Venice-Is-Blurred") == "true":
		return media.Images{}, apierr.ErrContentFilter
	}
	img, err := d.read(r.Body)
	if err != nil {
		return media.Images{}, err
	}
	return media.Images{List: []media.Image{img}, Cost: money.ReportedCost(d.price)}, nil
}

func generated(body []byte) (media.Image, error) {
	var reply struct {
		Images []string `json:"images"`
	}
	if json.Unmarshal(body, &reply) != nil || len(reply.Images) != 1 {
		return media.Image{}, upstream.ErrMalformed
	}
	return media.NewImage(reply.Images[0])
}

// Venice answers a ratio a model lacks with a square image, so it is asked for the nearest ratio the model has.
func nearest(ratio string, ratios []string) string {
	if slices.Contains(ratios, ratio) {
		return ratio
	}
	want := logRatio(ratio)
	best := ratios[0]
	for _, r := range ratios[1:] {
		if math.Abs(logRatio(r)-want) < math.Abs(logRatio(best)-want) {
			best = r
		}
	}
	return best
}

func logRatio(ratio string) float64 {
	var w, h float64
	fmt.Sscanf(ratio, "%g:%g", &w, &h)
	return math.Log(w / h)
}

func refusal(r upstream.Reply) error {
	var body struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	json.Unmarshal(r.Body, &body)
	if strings.EqualFold(body.Code, contentPolicy) || r.Status == http.StatusUnprocessableEntity && strings.Contains(strings.ToLower(body.Error), "content polic") {
		return apierr.ErrContentFilter
	}
	return apierr.SanitizedUpstreamError(r.Status, r.Body)
}
