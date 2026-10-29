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

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/dataurl"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
)

const (
	MaxImages     = 4
	MaxImagesBody = 64 << 20
	MaxReplyBody  = 1 << 20
)

var (
	AspectRatios = []string{"1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3"}
	Resolutions  = []string{"1k", "2k"}

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
	Model   string
	N       int
	Size    Size
	Quality string
	prompt  string
	images  []dataurl.URL
}

func (r ImageRequest) ModelName() string              { return r.Model }
func (r ImageRequest) Prompt() string                 { return r.prompt }
func (r ImageRequest) ReferenceImages() []dataurl.URL { return r.images }
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
		Model, Prompt, AspectRatio, Resolution, Quality, ResponseFormat string
		N                                                               *int
		Images                                                          []string
	}
	if err := strictjson.Decode(body, map[string]any{
		"model": &wire.Model, "prompt": &wire.Prompt, "n": &wire.N, "aspect_ratio": &wire.AspectRatio, "resolution": &wire.Resolution,
		"quality": &wire.Quality, "images": &wire.Images, "response_format": &wire.ResponseFormat,
	}); err != nil {
		return nil, err
	}
	req := &ImageRequest{
		Model: wire.Model, N: 1, Quality: wire.Quality, prompt: wire.Prompt,
		Size: Size{AspectRatio: cmp.Or(wire.AspectRatio, "1:1"), Resolution: cmp.Or(wire.Resolution, "1k")},
	}
	if wire.N != nil {
		req.N = *wire.N
	}
	switch {
	case req.Model == "":
		return nil, strictjson.Invalid("model is required.")
	case strings.TrimSpace(req.prompt) == "":
		return nil, strictjson.Invalid("prompt is required.")
	case req.N < 1 || req.N > MaxImages:
		return nil, strictjson.Invalid(fmt.Sprintf("n must be between 1 and %d.", MaxImages))
	case !slices.Contains(AspectRatios, req.Size.AspectRatio):
		return nil, strictjson.Invalid("aspect_ratio must be one of " + strings.Join(AspectRatios, ", ") + ".")
	case !slices.Contains(Resolutions, req.Size.Resolution):
		return nil, strictjson.Invalid("resolution must be one of " + strings.Join(Resolutions, ", ") + ".")
	case wire.ResponseFormat != "" && wire.ResponseFormat != "b64_json":
		return nil, strictjson.Invalid("response_format must be b64_json: images are always returned inline.")
	}
	for i, ref := range wire.Images {
		image, data, err := inlineImage(ref)
		if err != nil {
			return nil, err
		}
		req.images = append(req.images, image)
		if i == 0 && wire.AspectRatio == "" {
			req.Size.AspectRatio = closestOf(AspectRatios, data)
		}
	}
	return req, nil
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

func closestOf(ratios []string, data []byte) string {
	width, height, ok := imageSize(data)
	if !ok {
		return ratios[0]
	}
	want := math.Log(float64(width) / float64(height))
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

type ImageSpec struct {
	MaxReferences int
	Qualities     []string
	Resolutions   []string
}

type ImageDims struct{ Base, Text map[Size]Dims }

func (d ImageDims) For(r *ImageRequest) Dims {
	if d.Text != nil && len(r.images) == 0 {
		return d.Text[r.Size]
	}
	return d.Base[r.Size]
}

func (s ImageSpec) CheckImages(r *ImageRequest) error {
	switch {
	case len(r.images) > 0 && s.MaxReferences == 0:
		return strictjson.Invalid("This model takes no reference images.")
	case len(r.images) > s.MaxReferences:
		return strictjson.Invalid(fmt.Sprintf("This model takes at most %d reference images.", s.MaxReferences))
	case s.Resolutions != nil && !slices.Contains(s.Resolutions, r.Size.Resolution):
		return strictjson.Invalid("resolution must be one of " + strings.Join(s.Resolutions, ", ") + " for this model.")
	case r.Quality != "" && len(s.Qualities) == 0:
		return strictjson.Invalid("This model has no quality setting.")
	case r.Quality != "" && !slices.Contains(s.Qualities, r.Quality):
		return strictjson.Invalid("quality must be one of " + strings.Join(s.Qualities, ", ") + " for this model.")
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
	stripped, ok := strip(data)
	if !ok {
		return Image{}, errUnwalkable
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
