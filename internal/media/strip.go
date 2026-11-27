package media

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"morse/backend/internal/upstream"
)

var errUnwalkable = fmt.Errorf("%w: an image whose container could not be walked", upstream.ErrMalformed)

// why: signed says the image carries a C2PA manifest, whose hash covers every byte outside it, so ImageOf keeps such an
// image whole: dropping any other chunk would void the record that an AI model made it (EU AI Act Article 50(2)).
var strippers = map[string]func(data []byte) (stripped []byte, signed, ok bool){
	"image/png":  stripPNG,
	"image/jpeg": stripJPEG,
	"image/webp": stripWebP,
}

const (
	vp8xFlags = 20
	vp8xEXIF  = 0x08
	vp8xXMP   = 0x04
)

var pngRenderChunks = map[string]bool{
	"IHDR": true, "PLTE": true, "tRNS": true, "IDAT": true, "IEND": true,
	"gAMA": true, "cHRM": true, "sRGB": true, "iCCP": true, "sBIT": true, "pHYs": true,
}

var webpRenderChunks = map[string]bool{
	"VP8X": true, "VP8 ": true, "VP8L": true, "ALPH": true, "ICCP": true, "ANIM": true, "ANMF": true,
}

// why: C2PA 2.2 section A.3.4 (PNG) embeds the manifest store in a caBX chunk, A.3.3 (JPEG) in APP11 segments that open
// with JUMBF's common identifier "JP" and two counters, and A.3.6 (RIFF) in a WebP chunk named C2PA. The store is a jumb
// box whose description box (jumd) carries the C2PA UUID, which starts with "c2pa", so a box merely named so is stripped.
const (
	pngC2PA    = "caBX"
	webpC2PA   = "C2PA"
	jpegJUMBF  = "JP"
	jpegHeader = 8
)

func manifestStore(box []byte) bool {
	return len(box) >= 20 && string(box[4:8]) == "jumb" && string(box[12:20]) == "jumdc2pa"
}

func stripPNG(data []byte) (out []byte, signed, ok bool) {
	out = append([]byte(nil), data[:8]...)
	for pos := 8; ; {
		if len(data)-pos < 12 {
			return nil, false, false
		}
		n := int(binary.BigEndian.Uint32(data[pos:]))
		if n > len(data)-pos-12 {
			return nil, false, false
		}
		end := pos + 12 + n
		typ := string(data[pos+4 : pos+8])
		signed = signed || typ == pngC2PA && manifestStore(data[pos+8:end-4])
		if pngRenderChunks[typ] {
			out = append(out, data[pos:end]...)
		}
		if typ == "IEND" {
			return out, signed, true
		}
		pos = end
	}
}

const (
	markerTEM   byte = 0x01
	markerRST0  byte = 0xd0
	markerRST7  byte = 0xd7
	markerSOI   byte = 0xd8
	markerEOI   byte = 0xd9
	markerSOS   byte = 0xda
	markerAPP0  byte = 0xe0
	markerAPP2  byte = 0xe2
	markerAPP11 byte = 0xeb
	markerAPP14 byte = 0xee
	markerAPP15 byte = 0xef
	markerCOM   byte = 0xfe
)

func jpegRenderSegment(marker byte, payload []byte) bool {
	switch marker {
	case markerCOM:
		return false
	case markerAPP0:
		return true
	case markerAPP2:
		return bytes.HasPrefix(payload, []byte("ICC_PROFILE\x00"))
	case markerAPP14:
		return bytes.HasPrefix(payload, []byte("Adobe"))
	}
	return marker < markerAPP0 || marker > markerAPP15
}

func stripJPEG(data []byte) (out []byte, signed, ok bool) {
	out = []byte{0xff, markerSOI}
	for pos := 2; ; {
		if len(data)-pos < 2 || data[pos] != 0xff {
			return nil, false, false
		}
		marker := data[pos+1]
		switch {
		case marker == 0xff:
			pos++
			continue
		case marker == markerEOI:
			return append(out, 0xff, markerEOI), signed, true
		case marker == markerSOI || marker == markerTEM || isRestart(marker):
			out = append(out, 0xff, marker)
			pos += 2
			continue
		}
		if len(data)-pos < 4 {
			return nil, false, false
		}
		n := int(binary.BigEndian.Uint16(data[pos+2:]))
		if n < 2 || n > len(data)-pos-2 {
			return nil, false, false
		}
		end := pos + 2 + n
		signed = signed || marker == markerAPP11 && bytes.HasPrefix(data[pos+4:end], []byte(jpegJUMBF)) && manifestStore(data[min(pos+4+jpegHeader, end):end])
		if jpegRenderSegment(marker, data[pos+4:end]) {
			out = append(out, data[pos:end]...)
		}
		pos = end
		if marker == markerSOS {
			start := pos
			for pos < len(data) && !startsMarker(data[pos:]) {
				pos++
			}
			out = append(out, data[start:pos]...)
		}
	}
}

func isRestart(marker byte) bool { return marker >= markerRST0 && marker <= markerRST7 }

func startsMarker(b []byte) bool {
	const stuffed = 0x00
	return len(b) >= 2 && b[0] == 0xff && b[1] != stuffed && !isRestart(b[1])
}

func stripWebP(data []byte) (out []byte, signed, ok bool) {
	if len(data) < 12 {
		return nil, false, false
	}
	size := int(binary.LittleEndian.Uint32(data[4:]))
	if size < 4 || size > len(data)-8 {
		return nil, false, false
	}
	data = data[:8+size]
	out = append([]byte(nil), data[:12]...)
	for pos := 12; pos < len(data); {
		if len(data)-pos < 8 {
			return nil, false, false
		}
		n := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if n > len(data)-pos-8 {
			return nil, false, false
		}
		end := min(pos+8+n+n%2, len(data))
		signed = signed || string(data[pos:pos+4]) == webpC2PA && manifestStore(data[pos+8:pos+8+n])
		if webpRenderChunks[string(data[pos:pos+4])] {
			out = append(out, data[pos:end]...)
			if n%2 == 1 && end-pos == 8+n {
				out = append(out, 0)
			}
		}
		pos = end
	}
	if len(out) > vp8xFlags && string(out[12:16]) == "VP8X" {
		out[vp8xFlags] &^= vp8xEXIF | vp8xXMP
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)-8))
	return out, signed, true
}
