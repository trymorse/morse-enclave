package media

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/dataurl"
	"morse/backend/internal/frameconsent"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
)

const (
	MaxImages         = 4
	MaxImagesBody     = 64 << 20
	MaxReplyBody      = 1 << 20
	MaxSeed           = math.MaxInt32
	MaxNegativePrompt = 2000
	MaxToolPixels     = 4096 * 4096
)

var (
	AspectRatios = []string{"1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3", "21:9", "4:5", "5:4"}
	Resolutions  = []string{"1k", "2k", "4k"}

	errNotImage = fmt.Errorf("%w: something other than a base64 PNG, JPEG, or WebP image", upstream.ErrMalformed)
)

type Size struct{ AspectRatio, Resolution string }

type Dims struct{ Width, Height int }

func SizeTable(dims map[string][2]int) map[Size]Dims {
	out := make(map[Size]Dims, len(dims))
	for key, d := range dims {
		ratio, resolution, _ := strings.Cut(key, " ")
		out[Size{AspectRatio: ratio, Resolution: resolution}] = Dims{Width: d[0], Height: d[1]}
	}
	return out
}

type ImageRequest struct {
	Model         string
	N             int
	Size          Size
	Quality       string
	Seed          *int64
	prompt        string
	images        []dataurl.URL
	dims          []Dims
	digests       []frameconsent.Digest
	negative      string
	promptCheck   bool
	mask          dataurl.URL
	sizedByClient Size
}

func (r ImageRequest) ModelName() string              { return r.Model }
func (r ImageRequest) Prompt() string                 { return r.prompt }
func (r ImageRequest) NegativePrompt() string         { return r.negative }
func (r ImageRequest) ReferenceImages() []dataurl.URL { return r.images }

// why: a filtered route's prompt reaches Morse's prompt check only when the person's own app asks for it in the
// sealed body, so the relay alone can never send a filtered prompt to the checker.
func (r ImageRequest) AsksPromptCheck() bool { return r.promptCheck }

func (r ImageRequest) ReferenceDigests() []frameconsent.Digest { return slices.Clone(r.digests) }

func (r ImageRequest) Mask() string {
	if r.mask.Base64 == "" {
		return ""
	}
	return r.mask.String()
}

func (r ImageRequest) Source() (Dims, bool) {
	if len(r.dims) == 0 || r.dims[0] == (Dims{}) {
		return Dims{}, false
	}
	return r.dims[0], true
}
func (r ImageRequest) References() []string {
	var urls []string
	for _, image := range r.images {
		urls = append(urls, image.String())
	}
	return urls
}
func (r ImageRequest) String() string {
	return fmt.Sprintf("media.ImageRequest(%s, n=%d, %d references)", r.Model, r.N, len(r.images))
}
func (r ImageRequest) GoString() string { return r.String() }

func ParseImageRequest(body io.Reader) (*ImageRequest, error) {
	var wire struct {
		Model, Prompt, NegativePrompt, AspectRatio, Resolution, Quality, ResponseFormat, Mask string
		N                                                                                     *int
		Seed                                                                                  *int64
		PromptCheck                                                                           bool
		Images                                                                                []string
	}
	if err := strictjson.Decode(body, map[string]any{
		"model": &wire.Model, "prompt": &wire.Prompt, "n": &wire.N, "aspect_ratio": &wire.AspectRatio, "resolution": &wire.Resolution,
		"quality": &wire.Quality, "images": &wire.Images, "response_format": &wire.ResponseFormat, "seed": &wire.Seed,
		"negative_prompt": &wire.NegativePrompt, "mask": &wire.Mask, "prompt_check": &wire.PromptCheck,
	}); err != nil {
		return nil, err
	}
	req := &ImageRequest{
		Model: wire.Model, N: 1, Quality: wire.Quality, Seed: wire.Seed, prompt: wire.Prompt, negative: wire.NegativePrompt,
		promptCheck:   wire.PromptCheck,
		Size:          Size{AspectRatio: cmp.Or(wire.AspectRatio, "1:1"), Resolution: cmp.Or(wire.Resolution, "1k")},
		sizedByClient: Size{AspectRatio: wire.AspectRatio, Resolution: wire.Resolution},
	}
	if wire.N != nil {
		req.N = *wire.N
	}
	switch {
	case req.Model == "":
		return nil, strictjson.Invalid("model is required.")
	case req.N < 1 || req.N > MaxImages:
		return nil, strictjson.Invalid(fmt.Sprintf("n must be between 1 and %d.", MaxImages))
	case !slices.Contains(AspectRatios, req.Size.AspectRatio):
		return nil, strictjson.Invalid("aspect_ratio must be one of " + strings.Join(AspectRatios, ", ") + ".")
	case !slices.Contains(Resolutions, req.Size.Resolution):
		return nil, strictjson.Invalid("resolution must be one of " + strings.Join(Resolutions, ", ") + ".")
	case wire.ResponseFormat != "" && wire.ResponseFormat != "b64_json":
		return nil, strictjson.Invalid("response_format must be b64_json: images are always returned inline.")
	case req.Seed != nil && (*req.Seed < 0 || *req.Seed > MaxSeed):
		return nil, strictjson.Invalid(fmt.Sprintf("seed must be between 0 and %d.", MaxSeed))
	case utf8.RuneCountInString(req.negative) > MaxNegativePrompt:
		return nil, strictjson.Invalid(fmt.Sprintf("negative_prompt must be at most %d characters.", MaxNegativePrompt))
	}
	for _, ref := range wire.Images {
		image, data, err := inlineImage(ref)
		if err != nil {
			return nil, err
		}
		req.images = append(req.images, image)
		req.dims = append(req.dims, dimsOf(data))
		req.digests = append(req.digests, frameconsent.Of(data))
	}
	if src, ok := req.Source(); ok && wire.AspectRatio == "" {
		req.Size.AspectRatio = closestOf(AspectRatios, src)
	}
	if wire.Mask != "" {
		if err := req.takeMask(wire.Mask); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (r *ImageRequest) takeMask(raw string) error {
	const refused = strictjson.Invalid("mask must be a base64 data URL of a PNG image.")
	mask, data, err := inlineImage(raw)
	switch {
	case errors.Is(err, apierr.ErrRemoteMedia):
		return err
	case err != nil || mask.MediaType != "image/png":
		return refused
	case len(r.images) == 0:
		return strictjson.Invalid("mask needs the image it masks in images.")
	}
	size, src := dimsOf(data), r.dims[0]
	switch {
	case size == (Dims{}):
		return refused
	case size != src:
		return strictjson.Invalid(fmt.Sprintf("mask is %dx%d and must be the size of the first image, %dx%d.", size.Width, size.Height, src.Width, src.Height))
	}
	r.mask = mask
	return nil
}

func dimsOf(data []byte) Dims {
	w, h, ok := imageSize(data)
	if !ok {
		return Dims{}
	}
	return Dims{Width: w, Height: h}
}

func imageSize(data []byte) (int, int, bool) {
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(data)); err == nil {
		return cfg.Width, cfg.Height, cfg.Width > 0 && cfg.Height > 0
	}
	if len(data) < 30 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0, 0, false
	}
	switch string(data[12:16]) {
	case "VP8X":
		return int(le24(data[24:27])) + 1, int(le24(data[27:30])) + 1, true
	case "VP8L":
		bits := binary.LittleEndian.Uint32(data[21:25])
		return int(bits&0x3fff) + 1, int(bits>>14&0x3fff) + 1, data[20] == 0x2f
	case "VP8 ":
		w, h := binary.LittleEndian.Uint16(data[26:28])&0x3fff, binary.LittleEndian.Uint16(data[28:30])&0x3fff
		return int(w), int(h), string(data[23:26]) == "\x9d\x01\x2a" && w > 0 && h > 0
	}
	return 0, 0, false
}

func le24(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 }

func closestOf(ratios []string, d Dims) string {
	if d == (Dims{}) {
		return ratios[0]
	}
	want := math.Log(float64(d.Width) / float64(d.Height))
	best, bestGap := ratios[0], math.Inf(1)
	for _, ratio := range ratios {
		var w, h float64
		fmt.Sscanf(ratio, "%g:%g", &w, &h)
		if gap := math.Abs(math.Log(w/h) - want); gap < bestGap {
			best, bestGap = ratio, gap
		}
	}
	return best
}

func inlineImage(ref string) (dataurl.URL, []byte, error) {
	const refused = strictjson.Invalid("Reference images must be base64 data URLs of PNG, JPEG, or WebP images.")
	image, err := dataurl.Parse(ref)
	switch {
	case errors.Is(err, apierr.ErrRemoteMedia):
		return dataurl.URL{}, nil, err
	case err != nil || strippers[image.MediaType] == nil:
		return dataurl.URL{}, nil, refused
	}
	data, err := base64.StdEncoding.DecodeString(image.Base64)
	if err != nil {
		return dataurl.URL{}, nil, refused
	}
	return image, data, nil
}

type PromptUse string

const (
	PromptRequired PromptUse = "required"
	PromptNone     PromptUse = "none"
)

type Tool string

const (
	ToolUpscale          Tool = "upscale"
	ToolRemoveBackground Tool = "remove_background"
	ToolInpaint          Tool = "inpaint"
)

type ImageSpec struct {
	AspectRatios   []string
	Resolutions    []string
	Qualities      []string
	MaxReferences  int
	Seed           bool
	NegativePrompt int
	Mask           bool
	Prompt         PromptUse
	Tool           Tool
}

func (s ImageSpec) Spec() ImageSpec { return s }

func (s ImageSpec) PromptUse() PromptUse { return cmp.Or(s.Prompt, PromptRequired) }

type ImageDims struct{ Base, Text map[Size]Dims }

func (d ImageDims) For(r *ImageRequest) Dims {
	if d.Text != nil && len(r.images) == 0 {
		return d.Text[r.Size]
	}
	return d.Base[r.Size]
}

func oneOf(field string, allowed []string) strictjson.Invalid {
	if len(allowed) == 0 {
		return strictjson.Invalid("This model takes no " + field + ".")
	}
	return strictjson.Invalid(field + " must be one of " + strings.Join(allowed, ", ") + " for this model.")
}

func (s ImageSpec) CheckImages(r *ImageRequest) error {
	switch {
	case s.Tool != "" && len(r.images) != 1:
		return strictjson.Invalid("This model takes exactly one image.")
	case s.Tool != "" && r.N != 1:
		return strictjson.Invalid("This model makes one image a request; n must be 1.")
	case len(r.images) > 0 && s.MaxReferences == 0:
		return strictjson.Invalid("This model takes no reference images.")
	case len(r.images) > s.MaxReferences:
		return strictjson.Invalid(fmt.Sprintf("This model takes at most %d reference images.", s.MaxReferences))
	case s.PromptUse() == PromptRequired && strings.TrimSpace(r.prompt) == "":
		return strictjson.Invalid("prompt is required.")
	case r.sizedByClient.AspectRatio != "" && !slices.Contains(s.AspectRatios, r.sizedByClient.AspectRatio):
		return oneOf("aspect_ratio", s.AspectRatios)
	case r.sizedByClient.Resolution != "" && !slices.Contains(s.Resolutions, r.sizedByClient.Resolution):
		return oneOf("resolution", s.Resolutions)
	case r.Quality != "" && len(s.Qualities) == 0:
		return strictjson.Invalid("This model has no quality setting.")
	case r.Quality != "" && !slices.Contains(s.Qualities, r.Quality):
		return strictjson.Invalid("quality must be one of " + strings.Join(s.Qualities, ", ") + " for this model.")
	case r.Seed != nil && !s.Seed:
		return strictjson.Invalid("This model takes no seed.")
	case r.negative != "" && s.NegativePrompt == 0:
		return strictjson.Invalid("This model takes no negative_prompt.")
	case utf8.RuneCountInString(r.negative) > s.NegativePrompt:
		return strictjson.Invalid(fmt.Sprintf("negative_prompt must be at most %d characters for this model.", s.NegativePrompt))
	case r.Mask() != "" && !s.Mask:
		return strictjson.Invalid("This model takes no mask.")
	case s.Mask && r.Mask() == "":
		return strictjson.Invalid("mask is required.")
	}
	if s.PromptUse() == PromptNone {
		r.prompt = ""
	}
	if r.sizedByClient.AspectRatio == "" && len(s.AspectRatios) > 0 {
		r.Size.AspectRatio = s.AspectRatios[0]
		if slices.Contains(s.AspectRatios, "1:1") {
			r.Size.AspectRatio = "1:1"
		}
		if src, ok := r.Source(); ok {
			r.Size.AspectRatio = closestOf(s.AspectRatios, src)
		}
	}
	if r.sizedByClient.Resolution == "" && len(s.Resolutions) > 0 && !slices.Contains(s.Resolutions, "1k") {
		r.Size.Resolution = s.Resolutions[0]
	}
	if s.Tool != "" && len(s.Resolutions) == 0 {
		if src, ok := r.Source(); ok && src.Width*src.Height > MaxToolPixels {
			return strictjson.Invalid(fmt.Sprintf("The image is %dx%d; this model takes an image of at most %d pixels, such as 4096x4096.", src.Width, src.Height, MaxToolPixels))
		}
		r.Size.Resolution = sizeClass(r)
	}
	if s.Tool == ToolUpscale {
		return s.checkUpscale(r)
	}
	return nil
}

func sizeClass(r *ImageRequest) string {
	src, ok := r.Source()
	switch area := src.Width * src.Height; {
	case !ok:
		return "4k"
	case area <= 1024*1024:
		return "1k"
	case area <= 2048*2048:
		return "2k"
	}
	return "4k"
}

const MaxUpscaleFactor = 10

func (s ImageSpec) checkUpscale(r *ImageRequest) error {
	src, ok := r.Source()
	long := max(src.Width, src.Height)
	switch target := LongEdge(r.Size.Resolution); {
	case !ok:
		return strictjson.Invalid("The image's size could not be read.")
	case long >= target:
		return strictjson.Invalid(fmt.Sprintf("The image is already %d pixels or more on its long edge; ask for a larger resolution.", target))
	case long*MaxUpscaleFactor < target:
		reach := ""
		for _, resolution := range s.Resolutions {
			if edge := LongEdge(resolution); long < edge && long*MaxUpscaleFactor >= edge {
				reach = resolution
			}
		}
		if reach == "" {
			return strictjson.Invalid(fmt.Sprintf("The image is too small to upscale to %s; it can grow at most %d times, to %d pixels on its long edge, short of every resolution this model offers.", r.Size.Resolution, MaxUpscaleFactor, long*MaxUpscaleFactor))
		}
		return strictjson.Invalid(fmt.Sprintf("The image is too small to upscale to %s; the largest resolution it can reach is %s.", r.Size.Resolution, reach))
	}
	return nil
}

type Image struct{ data []byte }

func NewImage(b64 string) (Image, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Image{}, errNotImage
	}
	return ImageOf(data)
}

// ImageOf is NewImage for a vendor that sends an image's bytes rather than their base64.
func ImageOf(data []byte) (Image, error) {
	strip := strippers[http.DetectContentType(data)]
	if strip == nil {
		return Image{}, errNotImage
	}
	stripped, signed, ok := strip(data)
	switch {
	case !ok:
		return Image{}, errUnwalkable
	case signed:
		return Image{data: data}, nil
	}
	return Image{data: stripped}, nil
}

// Qwen on fal labelled PNG bytes image/jpeg.
func (i Image) MIME() string { return http.DetectContentType(i.data) }

type Images struct {
	List []Image
	Cost money.Reported
}

const (
	ImageTimeout   = 10 * time.Minute
	imagePollEvery = time.Second
)

var ErrNoImages = errors.New("media: the generation finished without an image")

func PollUntil(ctx context.Context, every time.Duration, step func(context.Context) (done bool, err error)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cmp.Or(every, imagePollEvery)):
		}
		if done, err := step(ctx); done || err != nil {
			return err
		}
	}
}

func (out Images) Partial(n int, err error) (Images, error) {
	if len(out.List) > 0 {
		out.List = out.List[:min(len(out.List), n)]
		return out, nil
	}
	return out, cmp.Or(err, ErrNoImages)
}

type ImageGenerator interface {
	Spec() ImageSpec
	CheckImages(req *ImageRequest) error
	GenerateImages(ctx context.Context, req *ImageRequest) (Images, error)
}

// A Canceller cancels its vendor's work once left closes, which says the caller is gone, then waits for the vendor's
// last word while ctx lasts. Any other generator's vendor runs on to the end.
type Canceller interface {
	ImageGenerator
	GenerateImagesUntil(ctx context.Context, left <-chan struct{}, req *ImageRequest) (Images, error)
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func WriteImages(w io.Writer, created time.Time, imgs []Image) error {
	out := &errWriter{w: w}
	fmt.Fprintf(out, `{"created":%d,"data":[`, created.Unix())
	for i, img := range imgs {
		if i > 0 {
			io.WriteString(out, ",")
		}
		io.WriteString(out, `{"b64_json":"`)
		enc := base64.NewEncoder(base64.StdEncoding, out)
		enc.Write(img.data)
		enc.Close()
		fmt.Fprintf(out, `","mime_type":%q}`, img.MIME())
	}
	io.WriteString(out, "]}")
	return out.err
}
