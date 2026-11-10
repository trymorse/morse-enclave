package seal

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	Batch        = 50 * time.Millisecond
	MaxFrameData = 64 << 10

	saltSize       = 32
	nonceSize      = 12
	frameHeadSize  = 1 + 4
	maxFrameSize   = frameHeadSize + MaxFrameData + (Pad-(frameHeadSize+MaxFrameData)%Pad)%Pad + tagSize
	infoReplyKey   = "morse-seal-v1 reply key"
	infoReplyNonce = "morse-seal-v1 reply nonce"
)

var ErrTruncated = errors.New("seal: the reply ended before its final frame")

type ReplyHead struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
}

type Frames struct {
	aead cipher.AEAD
	base [nonceSize]byte
	n    uint32
}

func NewFrames(cek [cekSize]byte, salt [saltSize]byte) (*Frames, error) {
	key, err := hkdf.Key(sha256.New, cek[:], salt[:], infoReplyKey, cekSize)
	if err != nil {
		return nil, err
	}
	base, err := hkdf.Key(sha256.New, cek[:], salt[:], infoReplyNonce, nonceSize)
	if err != nil {
		return nil, err
	}
	aead, err := contentCipher(key)
	if err != nil {
		return nil, err
	}
	return &Frames{aead: aead, base: [nonceSize]byte(base)}, nil
}

func (f *Frames) nonce() []byte {
	nonce := f.base
	binary.BigEndian.PutUint32(nonce[nonceSize-4:], binary.BigEndian.Uint32(nonce[nonceSize-4:])^f.n)
	f.n++
	return nonce[:]
}

func (f *Frames) Seal(data []byte, final bool) []byte {
	pt := make([]byte, frameHeadSize, frameHeadSize+len(data))
	if final {
		pt[0] = 1
	}
	binary.BigEndian.PutUint32(pt[1:], uint32(len(data)))
	pt = append(pt, data...)
	pt = append(pt, make([]byte, padding(len(pt)))...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(pt)+tagSize))
	return f.aead.Seal(out, f.nonce(), pt, nil)
}

func (f *Frames) Open(frame []byte) (data []byte, final bool, err error) {
	if len(frame) < 4 || int(binary.BigEndian.Uint32(frame)) != len(frame)-4 {
		return nil, false, fmt.Errorf("%w: frame %d prefix", ErrInvalid, f.n)
	}
	pt, err := f.aead.Open(nil, f.nonce(), frame[4:], nil)
	if err != nil {
		return nil, false, fmt.Errorf("%w: frame %d", ErrInvalid, f.n-1)
	}
	if len(pt) < frameHeadSize || len(pt)%Pad != 0 || pt[0] > 1 {
		return nil, false, fmt.Errorf("%w: frame %d shape", ErrInvalid, f.n-1)
	}
	n := int(binary.BigEndian.Uint32(pt[1:]))
	if n > len(pt)-frameHeadSize {
		return nil, false, fmt.Errorf("%w: frame %d length", ErrInvalid, f.n-1)
	}
	return pt[frameHeadSize : frameHeadSize+n], pt[0] == 1, nil
}

type Stream struct {
	mu         sync.Mutex
	frames     *Frames
	w          io.Writer
	flush      func()
	unsentSalt []byte
	head       []byte
	pending    []byte
	last       time.Time
	timer      *time.Timer
	closed     bool
	err        error
}

func NewStream(w io.Writer, flush func(), cek [cekSize]byte) (*Stream, error) {
	var salt [saltSize]byte
	rand.Read(salt[:])
	frames, err := NewFrames(cek, salt)
	if err != nil {
		return nil, err
	}
	return &Stream{frames: frames, w: w, flush: flush, unsentSalt: salt[:]}, nil
}

func (s *Stream) Begin(head ReplyHead) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.head, _ = json.Marshal(head)
	s.schedule()
}

func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, http.ErrBodyNotAllowed
	}
	s.pending = append(s.pending, p...)
	for len(s.pending) >= MaxFrameData && s.err == nil {
		s.emitHead()
		s.emit(s.pending[:MaxFrameData], false)
		s.pending = s.pending[MaxFrameData:]
	}
	if len(s.pending) > 0 {
		s.schedule()
	}
	return len(p), s.err
}

func (s *Stream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.emitHead()
	s.emit(s.pending, true)
	s.pending = nil
	return s.err
}

func (s *Stream) schedule() {
	if s.timer != nil || s.err != nil {
		return
	}
	if wait := Batch - time.Since(s.last); wait > 0 {
		s.timer = time.AfterFunc(wait, s.tick)
		return
	}
	s.emitWaiting()
}

func (s *Stream) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timer = nil
	if !s.closed {
		s.emitWaiting()
	}
}

func (s *Stream) emitWaiting() {
	s.emitHead()
	if len(s.pending) > 0 {
		s.emit(s.pending, false)
		s.pending = nil
	}
}

func (s *Stream) emitHead() {
	if s.head != nil {
		s.emit(s.head, false)
		s.head = nil
	}
}

func (s *Stream) emit(data []byte, final bool) {
	if s.err != nil {
		return
	}
	frame := s.frames.Seal(data, final)
	if s.unsentSalt != nil {
		frame, s.unsentSalt = append(s.unsentSalt, frame...), nil
	}
	if _, err := s.w.Write(frame); err != nil {
		s.err = err
		return
	}
	s.flush()
	s.last = time.Now()
}

type Reply struct {
	Head   ReplyHead
	r      io.Reader
	frames *Frames
	buf    []byte
	done   bool
}

func OpenReply(r io.Reader, cek [cekSize]byte) (*Reply, error) {
	var salt [saltSize]byte
	if _, err := io.ReadFull(r, salt[:]); err != nil {
		return nil, fmt.Errorf("%w: salt", ErrTruncated)
	}
	frames, err := NewFrames(cek, salt)
	if err != nil {
		return nil, err
	}
	reply := &Reply{r: r, frames: frames}
	data, final, err := reply.next()
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &reply.Head); err != nil {
		return nil, fmt.Errorf("%w: head", ErrInvalid)
	}
	reply.done = final
	return reply, nil
}

func (r *Reply) next() ([]byte, bool, error) {
	var size [4]byte
	if _, err := io.ReadFull(r.r, size[:]); err != nil {
		return nil, false, ErrTruncated
	}
	if binary.BigEndian.Uint32(size[:]) > maxFrameSize {
		return nil, false, fmt.Errorf("%w: frame %d size", ErrInvalid, r.frames.n)
	}
	frame := make([]byte, 4+binary.BigEndian.Uint32(size[:]))
	copy(frame, size[:])
	if _, err := io.ReadFull(r.r, frame[4:]); err != nil {
		return nil, false, ErrTruncated
	}
	return r.frames.Open(frame)
}

func (r *Reply) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		data, final, err := r.next()
		if err != nil {
			return 0, err
		}
		r.buf, r.done = data, final
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
