package clip

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func sealAll(t *testing.T, key Key, clip string, plain []byte) []byte {
	t.Helper()
	r, err := Seal(key, clip, bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := io.ReadAll(iotest.OneByteReader(r))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func openAll(key Key, clip string, sealed []byte) ([]byte, error) {
	r, err := Open(key, clip, iotest.HalfReader(bytes.NewReader(sealed)))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestEveryLengthSealsToItsDeclaredSizeAndOpensToItself(t *testing.T) {
	key := NewKey()
	for _, n := range []int{0, 1, TagSize, SegmentSize - 1, SegmentSize, SegmentSize + 1, 2 * SegmentSize, 3*SegmentSize + 7} {
		plain := make([]byte, n)
		rand.Read(plain)
		sealed := sealAll(t, key, "video_1", plain)
		if int64(len(sealed)) != SealedSize(int64(n)) {
			t.Errorf("%d bytes sealed to %d, SealedSize says %d", n, len(sealed), SealedSize(int64(n)))
		}
		if back, err := PlainSize(int64(len(sealed))); err != nil || back != int64(n) {
			t.Errorf("PlainSize(%d) = %d, %v; want %d", len(sealed), back, err, n)
		}
		if n >= 16 && bytes.Contains(sealed, plain[:16]) {
			t.Errorf("%d bytes: the sealed clip carries the plaintext", n)
		}
		got, err := openAll(key, "video_1", sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%d bytes opened to %d bytes, %v", n, len(got), err)
		}
	}
}

func TestASizeNoClipSealsToHasNoPlainSize(t *testing.T) {
	for _, sealed := range []int64{0, SaltSize, SaltSize + TagSize - 1, SaltSize + SegmentSize + 2*TagSize, SaltSize + SegmentSize + TagSize + TagSize - 1} {
		if n, err := PlainSize(sealed); !errors.Is(err, ErrInvalid) {
			t.Errorf("PlainSize(%d) = %d, %v; want ErrInvalid", sealed, n, err)
		}
	}
}

func TestTwoSealsOfOneClipDiffer(t *testing.T) {
	key, plain := NewKey(), []byte("the same frames")
	if bytes.Equal(sealAll(t, key, "video_1", plain), sealAll(t, key, "video_1", plain)) {
		t.Error("two seals of one clip under one key are equal; each needs a fresh salt")
	}
}

func TestASealedClipOpensOnlyUnderItsKeyAndForItsClip(t *testing.T) {
	key, plain := NewKey(), bytes.Repeat([]byte("frame"), SegmentSize/2)
	sealed := sealAll(t, key, "video_1", plain)
	if _, err := openAll(NewKey(), "video_1", sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("another key opened it with %v, want ErrInvalid", err)
	}
	if _, err := openAll(key, "video_2", sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("another clip's download opened it with %v, want ErrInvalid", err)
	}
}

func TestAnAlteredSealedClipNeverOpens(t *testing.T) {
	key := NewKey()
	plain := make([]byte, 2*SegmentSize+100)
	rand.Read(plain)
	sealed := sealAll(t, key, "video_1", plain)
	seg := SegmentSize + TagSize
	first, second, last := sealed[SaltSize:SaltSize+seg], sealed[SaltSize+seg:SaltSize+2*seg], sealed[SaltSize+2*seg:]
	cases := map[string][]byte{
		"a flipped salt bit":         flip(sealed, 0),
		"a flipped bit in segment 0": flip(sealed, SaltSize+10),
		"a flipped bit in segment 1": flip(sealed, SaltSize+seg+10),
		"a flipped tag bit":          flip(sealed, len(sealed)-1),
		"the last segment dropped":   sealed[:SaltSize+2*seg],
		"the last segment cut short": sealed[:len(sealed)-1],
		"a byte appended":            append(append([]byte{}, sealed...), 0),
		"a segment appended":         concat(sealed, last),
		"segments 0 and 1 swapped":   concat(sealed[:SaltSize], second, first, last),
		"segment 0 repeated":         concat(sealed[:SaltSize], first, first, last),
	}
	for name, altered := range cases {
		got, err := openAll(key, "video_1", altered)
		if err == nil {
			t.Errorf("%s: opened to %d bytes with no error", name, len(got))
		}
		if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: %v, want ErrInvalid or ErrTruncated", name, err)
		}
	}
	if _, err := Open(key, "video_1", bytes.NewReader(sealed[:SaltSize-1])); !errors.Is(err, ErrTruncated) {
		t.Errorf("a short salt opened with %v, want ErrTruncated", err)
	}
	if _, err := Open(key, "video_1", bytes.NewReader(sealed[:SaltSize])); !errors.Is(err, ErrTruncated) {
		t.Errorf("a salt with no segment opened with %v, want ErrTruncated", err)
	}
}

func TestOpenRefusesAWrongKeyBeforeItReturnsAReader(t *testing.T) {
	sealed := sealAll(t, NewKey(), "video_1", []byte("frames"))
	if r, err := Open(NewKey(), "video_1", bytes.NewReader(sealed)); r != nil || !errors.Is(err, ErrInvalid) {
		t.Errorf("Open = %v, %v; want no reader and ErrInvalid, so no reply begins before the key is known to be right", r, err)
	}
}

func TestSealRefusesAClipOfAnotherLengthThanDeclared(t *testing.T) {
	for name, c := range map[string]struct {
		body     string
		declared int64
	}{
		"short":       {"frames", 7},
		"long":        {"frames!", 6},
		"long by one": {strings.Repeat("f", SegmentSize+1), SegmentSize},
	} {
		r, err := Seal(NewKey(), "video_1", strings.NewReader(c.body), c.declared)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, ErrLength) {
			t.Errorf("%s: %v, want ErrLength", name, err)
		}
	}
	if _, err := Seal(NewKey(), "video_1", strings.NewReader(""), -1); !errors.Is(err, ErrLength) {
		t.Errorf("a negative length sealed with %v", err)
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 1
	return out
}

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
