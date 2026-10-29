package audio_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"morse/backend/internal/audio"
)

func fiveMinutes() []byte { return wav(make([]byte, audio.MaxSeconds*16000*2)) }

func liveHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func BenchmarkTranscribeFiveMinutes(b *testing.B) {
	contentType, body := form(b, text("model", "whisper-large-v3-tee"), file(fiveMinutes()))
	req, err := audio.ParseRequest(contentType, bytes.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	body = nil
	var before uint64
	var held int64
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		held = int64(liveHeap()) - int64(before)
		if n, err := io.Copy(io.Discard, r.Body); err != nil || n != r.ContentLength || n < int64(len(req.Audio())) {
			b.Fatalf("the vendor read %d bytes (%v) of a %d-byte body", n, err, r.ContentLength)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"text":"hi","duration":300}`))}, nil
	})}
	transcriber := audio.NewOpenAI("http://vendor.test", "k", "m", client)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		before = liveHeap()
		b.StartTimer()
		if _, err := transcriber.Transcribe(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(held), "held-during-send-B")
}

func BenchmarkParseFiveMinutes(b *testing.B) {
	contentType, body := form(b, text("model", "whisper-large-v3-tee"), file(fiveMinutes()))
	var held int64
	b.ReportAllocs()
	for b.Loop() {
		before := liveHeap()
		req, err := audio.ParseRequest(contentType, bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		held = int64(liveHeap()) - int64(before)
		runtime.KeepAlive(req)
	}
	b.ReportMetric(float64(held), "parsed-B")
}
