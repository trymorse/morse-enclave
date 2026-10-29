package media_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/media"
)

func aspect(ar string) float64 {
	var w, h float64
	for i, part := range strings.Split(ar, ":") {
		var v float64
		json.Unmarshal([]byte(part), &v)
		if i == 0 {
			w = v
		} else {
			h = v
		}
	}
	return w / h
}

func TestCatalogSizesCoverEveryRatioAndResolutionWithinEachModelsBounds(t *testing.T) {
	for name, table := range map[string]map[media.Size]media.Dims{"standard": media.StandardSizes, "ideogram": media.IdeogramSizes} {
		if len(table) != len(media.AspectRatios)*len(media.Resolutions) {
			t.Errorf("%s: %d sizes", name, len(table))
		}
		for _, ar := range media.AspectRatios {
			for _, res := range media.Resolutions {
				d, ok := table[media.Size{AspectRatio: ar, Resolution: res}]
				if got := float64(d.Width) / float64(d.Height) / aspect(ar); !ok || got < 0.97 || got > 1.03 {
					t.Errorf("%s %s %s: %v missing or off-ratio", name, ar, res, d)
				}
			}
		}
	}
	for size, d := range media.StandardSizes {
		area, r := d.Width*d.Height, float64(d.Width)/float64(d.Height)
		switch {
		case d.Width%32 != 0 || d.Height%32 != 0 || d.Width < 256 || d.Height < 256 || d.Width > 2048 || d.Height > 2048:
			t.Errorf("%v %v: outside FLUX.2 and Ideogram-with-references bounds", size, d)
		case area < 921_600 || area > 4_194_304 || r < 0.125 || r > 8:
			t.Errorf("%v %v: outside Seedream or Qwen area and ratio bounds", size, d)
		}
	}
	ideogram := [][2]int{{720, 1280}, {720, 1440}, {800, 1280}, {832, 1248}, {864, 1152}, {896, 1120}, {1024, 1024}, {1120, 896}, {1152, 864}, {1248, 832}, {1280, 720}, {1280, 800}, {1440, 720}, {1440, 2560}, {1600, 2560}, {1664, 2496}, {1728, 2304}, {2048, 2048}, {2304, 1728}, {2496, 1664}, {2560, 1440}, {2560, 1600}}
	for size, d := range media.IdeogramSizes {
		if !slices.Contains(ideogram, [2]int{d.Width, d.Height}) {
			t.Errorf("%v %v is not an Ideogram 4.5 preset", size, d)
		}
	}
	for _, c := range []struct {
		table map[media.Size]media.Dims
		size  string
		want  media.Dims
	}{
		{media.StandardSizes, "16:9 1k", media.Dims{Width: 1376, Height: 768}},
		{media.IdeogramSizes, "9:16 2k", media.Dims{Width: 1440, Height: 2560}},
	} {
		ar, res, _ := strings.Cut(c.size, " ")
		if got := c.table[media.Size{AspectRatio: ar, Resolution: res}]; got != c.want {
			t.Errorf("%s: %v, want %v", c.size, got, c.want)
		}
	}
}

func TestEveryImageSpecHasAReferenceLimit(t *testing.T) {
	for name, spec := range map[string]media.ImageSpec{"flux max": media.Flux2Max, "flux pro": media.Flux2Pro, "seedream": media.Seedream5Pro, "ideogram": media.Ideogram45, "qwen": media.QwenImage3} {
		if spec.MaxReferences == 0 {
			t.Errorf("%s: spec %+v lacks a reference limit", name, spec)
		}
	}
}

func TestTextPresetsApplyOnlyWithoutReferences(t *testing.T) {
	ref := `"data:image/png;base64,` + pngBase64 + `"`
	text := parse(t, `{"model":"m","prompt":"p","aspect_ratio":"16:9"}`)
	edit := parse(t, `{"model":"m","prompt":"p","aspect_ratio":"16:9","images":[`+ref+`]}`)
	presets := media.ImageDims{Base: media.StandardSizes, Text: media.IdeogramSizes}
	plain := media.ImageDims{Base: media.StandardSizes}
	for _, c := range []struct {
		name string
		dims media.ImageDims
		req  *media.ImageRequest
		want media.Dims
	}{
		{"presets, text-to-image", presets, text, media.Dims{Width: 1280, Height: 720}},
		{"presets, with a reference", presets, edit, media.Dims{Width: 1376, Height: 768}},
		{"no presets, text-to-image", plain, text, media.Dims{Width: 1376, Height: 768}},
		{"no presets, with a reference", plain, edit, media.Dims{Width: 1376, Height: 768}},
	} {
		if got := c.dims.For(c.req); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
