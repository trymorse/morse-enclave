package seal

import (
	"bytes"
	"crypto/rand"
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
	begun := time.Now()
	s.Begin(ReplyHead{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}})
	s.Write([]byte("data: a\n\n"))
	time.Sleep(10 * time.Millisecond)
	s.Write([]byte("data: b\n\n"))
	time.Sleep(2 * Batch)
	s.Write([]byte("data: c\n\n"))
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
	if at[0].Sub(begun) > Batch/2 {
		t.Errorf("the head went out %v after Begin", at[0].Sub(begun))
	}
	if gap := at[1].Sub(at[0]); gap < Batch || gap > 3*Batch {
		t.Errorf("the first body frame went out %v after the head, want about %v", gap, Batch)
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
	big := make([]byte, MaxFrameData+5)
	rand.Read(big)
	before := time.Now()
	s.Write(big)
	chunks, at := w.writes()
	if len(chunks) != 2 || at[1].Sub(before) > Batch/2 {
		t.Fatalf("%d writes after a large write, the last %v after it; want the salt with the head, and one full frame at once", len(chunks), at[len(at)-1].Sub(before))
	}
	s.Close()
	chunks, _ = w.writes()
	_, frames, finals := openAll(t, cek, chunks)
	if len(frames) != 3 || len(frames[1]) != MaxFrameData || !bytes.Equal(frames[2], big[MaxFrameData:]) || !finals[2] {
		t.Errorf("frames of %d, want a 64 KiB frame and a final 5-byte one", len(frames))
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
