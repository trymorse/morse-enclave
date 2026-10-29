package media_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"slices"
	"testing"
	"time"

	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

const vendorCanary = "VENDOR-CANARY-9c2a"

var onePixelVP8L = mustBase64("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")[20:]

func mustBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func gradient() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := range 8 {
		for x := range 8 {
			img.Set(x, y, color.RGBA{uint8(x * 32), uint8(y * 32), 128, 255})
		}
	}
	return img
}

func pngChunk(typ string, payload []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	out = append(out, typ...)
	out = append(out, payload...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[4:]))
}

func pngChunks(t *testing.T, data []byte) []string {
	t.Helper()
	var types []string
	for pos := 8; pos < len(data); {
		n := int(binary.BigEndian.Uint32(data[pos:]))
		types = append(types, string(data[pos+4:pos+8]))
		pos += 12 + n
	}
	return types
}

func taggedPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, gradient()); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()
	ihdrEnd := 8 + 12 + 13
	var out []byte
	out = append(out, clean[:ihdrEnd]...)
	out = append(out, pngChunk("tEXt", []byte("Software\x00"+vendorCanary))...)
	out = append(out, pngChunk("zTXt", []byte("Comment\x00\x00"+vendorCanary))...)
	out = append(out, pngChunk("iTXt", []byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00<x:xmpmeta>"+vendorCanary+"</x:xmpmeta>"))...)
	out = append(out, pngChunk("eXIf", []byte("Exif\x00\x00MM\x00*"+vendorCanary))...)
	out = append(out, pngChunk("tIME", []byte{7, 234, 10, 6, 12, 0, 0})...)
	out = append(out, pngChunk("caBX", []byte("jumb"+vendorCanary))...)
	out = append(out, pngChunk("gAMA", []byte{0, 0, 0xb1, 0x8f})...)
	out = append(out, clean[ihdrEnd:]...)
	return append(out, vendorCanary...)
}

func jpegSegment(marker byte, payload []byte) []byte {
	out := []byte{0xff, marker}
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)+2))
	return append(out, payload...)
}

func jpegMarkers(t *testing.T, data []byte) []string {
	t.Helper()
	var markers []string
	for pos := 0; pos < len(data); {
		if data[pos] != 0xff {
			t.Fatalf("byte %#x at %d where a marker should start", data[pos], pos)
		}
		marker := data[pos+1]
		switch {
		case marker == 0xff:
			pos++
			continue
		case marker == 0xd8 || marker == 0xd9 || marker >= 0xd0 && marker <= 0xd7:
			markers = append(markers, string([]byte{marker}))
			pos += 2
			continue
		}
		n := int(binary.BigEndian.Uint16(data[pos+2:]))
		name := string([]byte{marker})
		if marker >= 0xe0 && marker <= 0xef {
			payload := data[pos+4 : pos+2+n]
			if end := bytes.IndexByte(payload, 0); end >= 0 {
				payload = payload[:end]
			}
			name += ":" + string(payload)
		}
		markers = append(markers, name)
		pos += 2 + n
		if marker == 0xda {
			for pos < len(data) && !(data[pos] == 0xff && data[pos+1] != 0 && !(data[pos+1] >= 0xd0 && data[pos+1] <= 0xd7)) {
				pos++
			}
		}
	}
	return markers
}

func taggedJPEG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, gradient(), &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()
	out := []byte{0xff, 0xd8}
	out = append(out, jpegSegment(0xe0, []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"))...)
	out = append(out, jpegSegment(0xe1, []byte("Exif\x00\x00MM\x00*"+vendorCanary))...)
	out = append(out, jpegSegment(0xe1, []byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>"+vendorCanary+"</x:xmpmeta>"))...)
	out = append(out, jpegSegment(0xe2, []byte("ICC_PROFILE\x00\x01\x01profile"))...)
	out = append(out, jpegSegment(0xe2, []byte("MPF\x00"+vendorCanary))...)
	out = append(out, jpegSegment(0xeb, []byte("JP\x00\x00jumb"+vendorCanary))...)
	out = append(out, jpegSegment(0xed, []byte("Photoshop 3.0\x008BIM"+vendorCanary))...)
	out = append(out, jpegSegment(0xee, []byte("Adobe\x00d\x00\x00\x00\x00\x01"))...)
	out = append(out, jpegSegment(0xfe, []byte(vendorCanary))...)
	out = append(out, clean[2:]...)
	return append(out, vendorCanary...)
}

func webpChunk(fourcc string, payload []byte) []byte {
	out := binary.LittleEndian.AppendUint32([]byte(fourcc), uint32(len(payload)))
	out = append(out, payload...)
	if len(payload)%2 == 1 {
		out = append(out, 0)
	}
	return out
}

func webp(chunks ...[]byte) []byte {
	body := []byte("WEBP")
	for _, c := range chunks {
		body = append(body, c...)
	}
	out := binary.LittleEndian.AppendUint32([]byte("RIFF"), uint32(len(body)))
	return append(out, body...)
}

func vp8x(flags byte) []byte {
	return webpChunk("VP8X", []byte{flags, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func webpChunks(t *testing.T, data []byte) []string {
	t.Helper()
	var names []string
	for pos := 12; pos < len(data); {
		n := int(binary.LittleEndian.Uint32(data[pos+4:]))
		names = append(names, string(data[pos:pos+4]))
		pos += 8 + n + n%2
	}
	return names
}

func stripped(t *testing.T, data []byte) []byte {
	t.Helper()
	img, err := media.NewImage(base64.StdEncoding.EncodeToString(data))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := media.WriteImages(&out, time.Unix(0, 0), []media.Image{img}); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Data []struct {
			B64JSON string `json:"b64_json"`
		}
	}
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return mustBase64(reply.Data[0].B64JSON)
}

func samePixels(t *testing.T, before, after []byte) {
	t.Helper()
	was, _, err := image.Decode(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	now, _, err := image.Decode(bytes.NewReader(after))
	if err != nil {
		t.Fatalf("the stripped image no longer decodes: %v", err)
	}
	if was.Bounds() != now.Bounds() {
		t.Fatalf("bounds %v became %v", was.Bounds(), now.Bounds())
	}
	for y := was.Bounds().Min.Y; y < was.Bounds().Max.Y; y++ {
		for x := was.Bounds().Min.X; x < was.Bounds().Max.X; x++ {
			if was.At(x, y) != now.At(x, y) {
				t.Fatalf("pixel %d,%d %v became %v", x, y, was.At(x, y), now.At(x, y))
			}
		}
	}
}

func TestNewImageDropsVendorMetadataAndKeepsThePixels(t *testing.T) {
	cases := map[string]struct {
		in     []byte
		chunks func(*testing.T, []byte) []string
		want   []string
	}{
		"png": {
			in: taggedPNG(t), chunks: pngChunks,
			want: []string{"IHDR", "gAMA", "IDAT", "IEND"},
		},
		"jpeg": {
			in: taggedJPEG(t), chunks: jpegMarkers,
			want: []string{"\xd8", "\xe0:JFIF", "\xe2:ICC_PROFILE", "\xee:Adobe", "\xdb", "\xc0", "\xc4", "\xda", "\xd9"},
		},
		"webp": {
			in: append(webp(vp8x(0x20|0x08|0x04), webpChunk("ICCP", []byte("profile")), webpChunk("EXIF", []byte("MM\x00*"+vendorCanary)),
				webpChunk("XMP ", []byte("<x:xmpmeta>"+vendorCanary+"</x:xmpmeta>")), webpChunk("C2PA", []byte("jumb"+vendorCanary)), webpChunk("VP8L", onePixelVP8L)), vendorCanary...),
			chunks: webpChunks,
			want:   []string{"VP8X", "ICCP", "VP8L"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if !bytes.Contains(tc.in, []byte(vendorCanary)) {
				t.Fatal("the fixture carries no metadata")
			}
			out := stripped(t, tc.in)
			if bytes.Contains(out, []byte(vendorCanary)) {
				t.Errorf("the canary survived: %q", out)
			}
			if got := tc.chunks(t, out); !slices.Equal(got, tc.want) {
				t.Errorf("chunks %q, want %q", got, tc.want)
			}
			if name != "webp" {
				samePixels(t, tc.in, out)
			}
		})
	}
}

func TestAStrippedWebPKeepsItsBitstreamAndClearsTheMetadataFlags(t *testing.T) {
	in := webp(vp8x(0x20|0x10|0x08|0x04), webpChunk("ICCP", []byte("profile")), webpChunk("EXIF", []byte(vendorCanary)),
		webpChunk("ALPH", []byte{0}), webpChunk("VP8L", onePixelVP8L), webpChunk("XMP ", []byte(vendorCanary)))
	want := webp(vp8x(0x20|0x10), webpChunk("ICCP", []byte("profile")), webpChunk("ALPH", []byte{0}), webpChunk("VP8L", onePixelVP8L))
	if out := stripped(t, in); !bytes.Equal(out, want) {
		t.Errorf("got  % x\nwant % x", out, want)
	}
	simple := webp(webpChunk("VP8L", onePixelVP8L))
	if out := stripped(t, simple); !bytes.Equal(out, simple) {
		t.Errorf("a simple-format WebP changed: % x", out)
	}
}

func TestAnImageWhoseContainerCannotBeWalkedIsRefused(t *testing.T) {
	pngData, jpegData := taggedPNG(t), taggedJPEG(t)
	cases := map[string][]byte{
		"png without IEND":          pngData[:len(pngData)-len(vendorCanary)-12],
		"png chunk past the end":    append(pngData[:8], pngChunk("tEXt", bytes.Repeat([]byte{0}, 64))[:20]...),
		"jpeg without EOI":          jpegData[:len(jpegData)-len(vendorCanary)-2],
		"jpeg segment past the end": append([]byte{0xff, 0xd8}, jpegSegment(0xe1, bytes.Repeat([]byte{0}, 64))[:20]...),
		"webp chunk past the end":   webp(webpChunk("VP8L", onePixelVP8L)[:10]),
	}
	for name, data := range cases {
		if _, err := media.NewImage(base64.StdEncoding.EncodeToString(data)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, upstream.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
