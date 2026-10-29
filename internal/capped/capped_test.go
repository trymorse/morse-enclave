package capped_test

import (
	"errors"
	"strings"
	"testing"

	"morse/backend/internal/capped"
)

func TestReadAllReturnsABodyOfExactlyTheLimitAndRefusesOneByteMore(t *testing.T) {
	body, err := capped.ReadAll(strings.NewReader("12345"), 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("body at the limit: %q, %v", body, err)
	}
	if body, err := capped.ReadAll(strings.NewReader("123456"), 5); !errors.Is(err, capped.ErrTooLarge) || body != nil {
		t.Fatalf("body over the limit: %q, %v", body, err)
	}
}

type failingReader struct{}

var errRead = errors.New("read failed")

func (failingReader) Read([]byte) (int, error) { return 0, errRead }

func TestReadAllPassesThroughAReadError(t *testing.T) {
	if _, err := capped.ReadAll(failingReader{}, 5); !errors.Is(err, errRead) {
		t.Fatalf("read error became %v", err)
	}
}

func TestAppendKeepsOneByteOverTheLimitSoTheCallerCanTellItWasExceeded(t *testing.T) {
	var buf []byte
	for _, piece := range []string{"123", "456", "789"} {
		buf = capped.Append(buf, []byte(piece), 5)
	}
	if string(buf) != "123456" {
		t.Fatalf("appended %q, want the limit plus one byte", buf)
	}
	if got := capped.Append([]byte("12"), []byte("34"), 5); string(got) != "1234" {
		t.Fatalf("under the limit: %q", got)
	}
}
