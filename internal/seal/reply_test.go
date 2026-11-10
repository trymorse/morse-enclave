package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func testKeys(t *testing.T) (cek [cekSize]byte, salt [saltSize]byte) {
	t.Helper()
	rand.Read(cek[:])
	rand.Read(salt[:])
	return cek, salt
}

func TestFramesOpenInOrderOnlyAndEachIsPaddedToAWholeKiB(t *testing.T) {
	cek, salt := testKeys(t)
	sealer, _ := NewFrames(cek, salt)
	opener, _ := NewFrames(cek, salt)
	first := sealer.Seal([]byte("one"), false)
	second := sealer.Seal(bytes.Repeat([]byte("x"), Pad), true)
	if len(first) != 4+Pad+tagSize || len(second) != 4+2*Pad+tagSize {
		t.Errorf("frames of %d and %d bytes, want 1 KiB and 2 KiB plus tag and length", len(first), len(second))
	}
	if _, _, err := opener.Open(second); !errors.Is(err, ErrInvalid) {
		t.Errorf("the second frame opened first: %v", err)
	}
	opener, _ = NewFrames(cek, salt)
	if _, _, err := opener.Open(first[:len(first)-1]); !errors.Is(err, ErrInvalid) {
		t.Errorf("a frame shorter than its prefix says opened: %v", err)
	}
	data, final, err := opener.Open(first)
	if err != nil || string(data) != "one" || final {
		t.Errorf("first: %q %t %v", data, final, err)
	}
	data, final, err = opener.Open(second)
	if err != nil || len(data) != Pad || !final {
		t.Errorf("second: %d bytes %t %v", len(data), final, err)
	}
	if _, _, err := opener.Open(first); !errors.Is(err, ErrInvalid) {
		t.Errorf("a replayed frame opened: %v", err)
	}
	otherSalt := salt
	otherSalt[0] ^= 1
	opener, _ = NewFrames(cek, otherSalt)
	if _, _, err := opener.Open(first); !errors.Is(err, ErrInvalid) {
		t.Errorf("another salt opened the frame: %v", err)
	}
}

type timedWriter struct {
	mu      sync.Mutex
	chunks  [][]byte
	at      []time.Time
	flushes int
}

func (w *timedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.chunks = append(w.chunks, bytes.Clone(p))
	w.at = append(w.at, time.Now())
	return len(p), nil
}

func (w *timedWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushes++
}

func (w *timedWriter) writes() ([][]byte, []time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.chunks, w.at
}

func (w *timedWriter) waitForEmit(t *testing.T, s *Stream, n int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if chunks, _ := w.writes(); len(chunks) >= n {
			s.mu.Lock()
			s.mu.Unlock()
			return
		}
	}
	t.Fatalf("no write %d within 10s", n)
}

func openAll(t *testing.T, cek [cekSize]byte, chunks [][]byte) (ReplyHead, [][]byte, []bool) {
	t.Helper()
	reply, err := OpenReply(bytes.NewReader(bytes.Join(chunks, nil)), cek)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	var finals []bool
	frames = append(frames, nil)
	finals = append(finals, reply.done)
	for !reply.done {
		data, final, err := reply.next()
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, data)
		finals = append(finals, final)
		reply.done = final
	}
	return reply.Head, frames, finals
}

func TestTheHeadGoesOutAtOnceAndBodyBytesBatchForFiftyMilliseconds(t *testing.T) {
	cek, _ := testKeys(t)
	w := &timedWriter{}
	s, err := NewStream(w, w.flush, cek)
	if err != nil {
		t.Fatal(err)
	}
	if chunks, _ := w.writes(); len(chunks) != 0 {
		t.Fatalf("%d writes before Begin, want none, so an interim 103 can still go first", len(chunks))
	}
	s.Begin(ReplyHead{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}})
	if chunks, _ := w.writes(); len(chunks) != 1 {
		t.Fatalf("%d writes once Begin returned, want the salt with the head", len(chunks))
	}
	s.Write([]byte("data: a\n\n"))
	s.Write([]byte("data: b\n\n"))
	w.waitForEmit(t, s, 2)
	time.Sleep(Batch)
	s.Write([]byte("data: c\n\n"))
	if chunks, _ := w.writes(); len(chunks) != 3 {
		t.Fatalf("%d writes once a write a batch after the last frame returned, want it sent at once", len(chunks))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	chunks, at := w.writes()
	if len(chunks) != 4 {
		t.Fatalf("%d writes, want the salt with the head, one batched frame, one frame sent at once, and the final frame", len(chunks))
	}
	if len(chunks[0]) != saltSize+4+Pad+tagSize {
		t.Errorf("the first write is %d bytes, want the salt and the head's frame", len(chunks[0]))
	}
	if gap := at[1].Sub(at[0]); gap < Batch {
		t.Errorf("the first body frame went out %v after the head, before the batch had passed", gap)
	}
	head, frames, finals := openAll(t, cek, chunks)
	if head.Status != 200 || head.Headers.Get("Content-Type") != "text/event-stream" {
		t.Errorf("head %+v", head)
	}
	if string(frames[1]) != "data: a\n\ndata: b\n\n" || string(frames[2]) != "data: c\n\n" || len(frames[3]) != 0 {
		t.Errorf("frames %q", frames)
	}
	if finals[1] || finals[2] || !finals[3] {
		t.Errorf("finals %v, want only the last", finals)
	}
	if at[2].Sub(at[1]) < Batch {
		t.Errorf("the third frame went out %v after the second, which was before the batch had passed", at[2].Sub(at[1]))
	}
	if w.flushes != 4 {
		t.Errorf("%d flushes, want one per write", w.flushes)
	}
}

func TestAFrameCarriesAtMostSixtyFourKiBAndAFullOneWaitsForNothing(t *testing.T) {
	cek, _ := testKeys(t)
	w := &timedWriter{}
	s, _ := NewStream(w, w.flush, cek)
	s.Begin(ReplyHead{Status: 200})
	big := make([]byte, 2*MaxFrameData)
	rand.Read(big)
	s.Write(big)
	if chunks, _ := w.writes(); len(chunks) != 3 {
		t.Fatalf("%d writes once a 128 KiB write returned, want the salt with the head, and two full frames at once", len(chunks))
	}
	s.Close()
	chunks, _ := w.writes()
	_, frames, finals := openAll(t, cek, chunks)
	if len(frames) != 4 || !bytes.Equal(frames[1], big[:MaxFrameData]) || !bytes.Equal(frames[2], big[MaxFrameData:]) || len(frames[3]) != 0 || !finals[3] {
		t.Errorf("frames of %d, want two 64 KiB frames and an empty final one", len(frames))
	}
}

func TestAReplyWithNoBodyIsTheHeadAndAnEmptyFinalFrame(t *testing.T) {
	cek, _ := testKeys(t)
	w := &timedWriter{}
	s, _ := NewStream(w, w.flush, cek)
	s.Begin(ReplyHead{Status: 204, Headers: http.Header{}})
	s.Close()
	chunks, _ := w.writes()
	if len(chunks) != 2 {
		t.Fatalf("%d writes, want the salt with the head and the final frame", len(chunks))
	}
	head, frames, finals := openAll(t, cek, chunks)
	if head.Status != 204 || len(frames) != 2 || finals[0] || len(frames[1]) != 0 || !finals[1] {
		t.Errorf("head %+v, %d frames, finals %v", head, len(frames), finals)
	}
	reply, _ := OpenReply(bytes.NewReader(bytes.Join(chunks, nil)), cek)
	if body, err := io.ReadAll(reply); err != nil || len(body) != 0 {
		t.Errorf("body %q %v", body, err)
	}
}

func TestOpenReplyStreamsTheBodyAcrossFramesAndNamesATruncatedOne(t *testing.T) {
	cek, _ := testKeys(t)
	var out bytes.Buffer
	s, _ := NewStream(&out, func() {}, cek)
	s.Begin(ReplyHead{Status: 200})
	s.Write([]byte("hello "))
	time.Sleep(2 * Batch)
	s.Write([]byte("world"))
	s.Close()
	reply, err := OpenReply(bytes.NewReader(out.Bytes()), cek)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(reply); err != nil || string(body) != "hello world" {
		t.Errorf("body %q %v", body, err)
	}
	cut, _ := OpenReply(bytes.NewReader(out.Bytes()[:out.Len()-1]), cek)
	if _, err := io.ReadAll(cut); !errors.Is(err, ErrTruncated) {
		t.Errorf("a reply short by a byte read as %v", err)
	}
	if _, err := OpenReply(bytes.NewReader(out.Bytes()[:saltSize+3]), cek); !errors.Is(err, ErrTruncated) {
		t.Errorf("a reply cut inside the head's length read as %v", err)
	}
	if _, err := OpenReply(bytes.NewReader(nil), cek); !errors.Is(err, ErrTruncated) {
		t.Errorf("an empty reply read as %v", err)
	}
}

type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func TestAFrameSizePastTheFormatIsRefusedBeforeItIsRead(t *testing.T) {
	cek, _ := testKeys(t)
	var out bytes.Buffer
	s, _ := NewStream(&out, func() {}, cek)
	s.Begin(ReplyHead{Status: 200})
	s.Close()
	salt := out.Bytes()[:saltSize]
	for name, size := range map[string]uint32{"a gibibyte": 1 << 30, "one over the largest frame": maxFrameSize + 1} {
		wire := binary.BigEndian.AppendUint32(bytes.Clone(salt), size)
		r := &countingReader{r: bytes.NewReader(append(wire, make([]byte, 2*maxFrameSize)...))}
		var err error
		allocated := allocatedBy(func() { _, err = OpenReply(r, cek) })
		if !errors.Is(err, ErrInvalid) || r.read > saltSize+4 || allocated > 64<<10 {
			t.Errorf("%s: %v after reading %d bytes and allocating %d KiB; want ErrInvalid on the size alone, since a relay could otherwise make the door allocate 4 GiB before authenticating a byte", name, err, r.read, allocated>>10)
		}
	}
	wire := binary.BigEndian.AppendUint32(bytes.Clone(salt), maxFrameSize)
	if _, err := OpenReply(bytes.NewReader(wire), cek); !errors.Is(err, ErrTruncated) {
		t.Errorf("the largest frame the format allows read as %v, want its bytes read and ErrTruncated", err)
	}
}
