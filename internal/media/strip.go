package media

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"morse/backend/internal/upstream"
)

var errUnwalkable = fmt.Errorf("%w: an image whose container could not be walked", upstream.ErrMalformed)

var strippers = map[string]func([]byte) ([]byte, bool){
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

func stripPNG(data []byte) ([]byte, bool) {
	out := append([]byte(nil), data[:8]...)
	for pos := 8; ; {
		if len(data)-pos < 12 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint32(data[pos:]))
		if n > len(data)-pos-12 {
			return nil, false
		}
		end := pos + 12 + n
		typ := string(data[pos+4 : pos+8])
		if pngRenderChunks[typ] {
			out = append(out, data[pos:end]...)
		}
		if typ == "IEND" {
			return out, true
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

func stripJPEG(data []byte) ([]byte, bool) {
	out := []byte{0xff, markerSOI}
	for pos := 2; ; {
		if len(data)-pos < 2 || data[pos] != 0xff {
			return nil, false
		}
		marker := data[pos+1]
		switch {
		case marker == 0xff:
			pos++
			continue
		case marker == markerEOI:
			return append(out, 0xff, markerEOI), true
		case marker == markerSOI || marker == markerTEM || isRestart(marker):
			out = append(out, 0xff, marker)
			pos += 2
			continue
		}
		if len(data)-pos < 4 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(data[pos+2:]))
		if n < 2 || n > len(data)-pos-2 {
			return nil, false
		}
		end := pos + 2 + n
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

func stripWebP(data []byte) ([]byte, bool) {
	if len(data) < 12 {
		return nil, false
	}
	size := int(binary.LittleEndian.Uint32(data[4:]))
	if size < 4 || size > len(data)-8 {
		return nil, false
	}
	data = data[:8+size]
	out := append([]byte(nil), data[:12]...)
	for pos := 12; pos < len(data); {
		if len(data)-pos < 8 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if n > len(data)-pos-8 {
			return nil, false
		}
		end := min(pos+8+n+n%2, len(data))
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
	return out, true
}
