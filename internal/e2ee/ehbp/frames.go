package ehbp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"morse/backend/internal/chat"
)

const (
	frameHeaderLen = 4
	gcmTagLen      = 16
	// MaxFrame bounds one reply frame. EHBP allows 64 MiB; a router seals each event it writes as a
	// frame, so a larger one is no reply the proxy should hold.
	MaxFrame = 1 << 20
)

var ErrTruncated = errors.New("ehbp: the reply ended inside a frame")

// A Tinfoil router seals each write as a frame: an SSE event of about 370 to 420 bytes of ciphertext, which
// carries the running usage beside up to six tokens (its models draft five tokens ahead), or a bare line
// break, which carries none. A longer frame holds a longer delta, such as a tool call's arguments in one
// piece: the 731-byte frame among GLM 5.3's and DeepSeek V4.1 Flash's replies carried 93 tokens
// (2026-11-03).
const (
	tokenlessFrame   = frameHeaderLen + gcmTagLen + 16
	eventFrame       = frameHeaderLen + 400
	eventFrameTokens = 6
	bytesPerToken    = 2
)

// FrameTokens is the most completion tokens a reply frame of size bytes, its length header included, may
// carry: what a reply cut before the router's usage is billed. It errs high, as a prompt's byte estimate
// does: the replies measured carried 1.6 to 3.2 tokens a frame, and none more than this allows.
func FrameTokens(size int) int {
	if size <= tokenlessFrame {
		return 0
	}
	return max(eventFrameTokens, (size-eventFrame+bytesPerToken-1)/bytesPerToken)
}

// Frames reads a sealed reply as EHBP frames, a 4-byte big-endian length and that many bytes of ciphertext,
// and hands each one whole to each, its length included, so it can be relayed verbatim. It answers how
// many non-empty frames it read. A frame shorter than an AES-GCM tag or longer than max is no sealed reply:
// plaintext SSE or JSON reads as a length far beyond max. A reply that ends mid-frame is truncated.
func Frames(r io.Reader, max int, each func(frame []byte) error) (int, error) {
	n := 0
	header := make([]byte, frameHeaderLen)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			switch {
			case err == io.EOF:
				return n, nil
			case errors.Is(err, io.ErrUnexpectedEOF):
				return n, ErrTruncated
			}
			return n, err
		}
		size := int(binary.BigEndian.Uint32(header))
		if size == 0 {
			if err := each(header); err != nil {
				return n, err
			}
			continue
		}
		if size < gcmTagLen || size > max {
			return n, fmt.Errorf("%w: a frame of %d bytes", chat.ErrUnsealedReply, size)
		}
		frame := make([]byte, frameHeaderLen+size)
		copy(frame, header)
		if _, err := io.ReadFull(r, frame[frameHeaderLen:]); err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				return n, ErrTruncated
			}
			return n, err
		}
		n++
		if err := each(frame); err != nil {
			return n, err
		}
	}
}
