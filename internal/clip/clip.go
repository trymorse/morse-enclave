package clip

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	KeySize     = 32
	SaltSize    = 32
	SegmentSize = 64 << 10
	TagSize     = 16

	nonceSize      = 12
	segmentOnWire  = SegmentSize + TagSize
	infoSegmentKey = "morse-clip-v1 segment key"
	infoNonceBase  = "morse-clip-v1 nonce base"
	aadPrefix      = "morse-clip-v1\x00"

	KeyHeader = "Morse-Clip-Key"
)

type Key [KeySize]byte

func NewKey() Key {
	var k Key
	rand.Read(k[:])
	return k
}

func (k Key) Encode() string { return base64.RawURLEncoding.EncodeToString(k[:]) }

func ParseKey(s string) (Key, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != KeySize {
		return Key{}, ErrKey
	}
	return Key(b), nil
}

var (
	ErrKey       = errors.New("clip: not a clip key")
	ErrInvalid   = errors.New("clip: the sealed clip does not open")
	ErrTruncated = errors.New("clip: the sealed clip ends before its final segment")
	ErrLength    = errors.New("clip: the clip is not the length it declared")
)

func segments(plain int64) int64 {
	if plain <= 0 {
		return 1
	}
	return (plain + SegmentSize - 1) / SegmentSize
}

// why: a presigned S3 or R2 PUT takes a Content-Length and no chunked body, so the door must know a clip's
// sealed size before the vendor's first byte arrives.
func SealedSize(plain int64) int64 { return SaltSize + plain + segments(plain)*TagSize }

func PlainSize(sealed int64) (int64, error) {
	body := sealed - SaltSize
	if body < TagSize {
		return 0, ErrInvalid
	}
	plain := body - (body+segmentOnWire-1)/segmentOnWire*TagSize
	if plain < 0 || SealedSize(plain) != sealed {
		return 0, ErrInvalid
	}
	return plain, nil
}

type segmentCipher struct {
	aead  cipher.AEAD
	base  [nonceSize]byte
	clip  string
	index uint64
}

func newSegmentCipher(key Key, salt []byte, clip string) (*segmentCipher, error) {
	sub, err := hkdf.Key(sha256.New, key[:], salt, infoSegmentKey, KeySize)
	if err != nil {
		return nil, err
	}
	base, err := hkdf.Key(sha256.New, key[:], salt, infoNonceBase, nonceSize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &segmentCipher{aead: aead, base: [nonceSize]byte(base), clip: clip}, nil
}

func (c *segmentCipher) next(final bool) (nonce, aad []byte) {
	n := c.base
	binary.BigEndian.PutUint64(n[nonceSize-8:], binary.BigEndian.Uint64(n[nonceSize-8:])^c.index)
	c.index++
	aad = append([]byte(aadPrefix+c.clip+"\x00"), 0)
	if final {
		aad[len(aad)-1] = 1
	}
	return n[:], aad
}

type sealer struct {
	c      *segmentCipher
	plain  io.Reader
	left   int64
	in     []byte
	out    []byte
	buf    []byte
	sealed bool
	err    error
}

func Seal(key Key, clip string, plain io.Reader, size int64) (io.Reader, error) {
	if size < 0 {
		return nil, ErrLength
	}
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	c, err := newSegmentCipher(key, salt, clip)
	if err != nil {
		return nil, err
	}
	return &sealer{c: c, plain: plain, left: size, in: make([]byte, SegmentSize), buf: make([]byte, 0, segmentOnWire), out: salt}, nil
}

func (s *sealer) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		switch {
		case s.err != nil:
			return 0, s.err
		case s.sealed:
			return 0, io.EOF
		}
		s.err = s.segment()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

func (s *sealer) segment() error {
	size := min(s.left, SegmentSize)
	if _, err := io.ReadFull(s.plain, s.in[:size]); err != nil {
		return fmt.Errorf("%w: %d bytes short", ErrLength, s.left)
	}
	s.left -= size
	final := s.left == 0
	if final {
		var probe [1]byte
		if n, _ := io.ReadFull(s.plain, probe[:]); n > 0 {
			return fmt.Errorf("%w: it runs on past its end", ErrLength)
		}
		s.sealed = true
	}
	nonce, aad := s.c.next(final)
	s.out = s.c.aead.Seal(s.buf[:0], nonce, s.in[:size], aad)
	return nil
}

type opener struct {
	c     *segmentCipher
	r     *bufio.Reader
	seg   []byte
	out   []byte
	final bool
	err   error
}

func Open(key Key, clip string, sealed io.Reader) (io.Reader, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(sealed, salt); err != nil {
		return nil, ErrTruncated
	}
	c, err := newSegmentCipher(key, salt, clip)
	if err != nil {
		return nil, err
	}
	o := &opener{c: c, r: bufio.NewReaderSize(sealed, segmentOnWire+1), seg: make([]byte, segmentOnWire)}
	if o.err = o.segment(); o.err != nil {
		return nil, o.err
	}
	return o, nil
}

func (o *opener) Read(p []byte) (int, error) {
	for len(o.out) == 0 {
		switch {
		case o.err != nil:
			return 0, o.err
		case o.final:
			return 0, io.EOF
		}
		o.err = o.segment()
	}
	n := copy(p, o.out)
	o.out = o.out[n:]
	return n, nil
}

func (o *opener) segment() error {
	n, err := io.ReadFull(o.r, o.seg)
	switch {
	case errors.Is(err, io.EOF), n < TagSize:
		return ErrTruncated
	case errors.Is(err, io.ErrUnexpectedEOF):
		o.final = true
	case err != nil:
		return err
	default:
		_, err := o.r.Peek(1)
		o.final = errors.Is(err, io.EOF)
		if err != nil && !o.final {
			return err
		}
	}
	nonce, aad := o.c.next(o.final)
	out, err := o.c.aead.Open(o.seg[:0], nonce, o.seg[:n], aad)
	if err != nil {
		return ErrInvalid
	}
	o.out = out
	return nil
}
