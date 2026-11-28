package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/upstream"
)

const headerOpenTook = "Worker-Open-Took"

type OpenTook struct {
	Read  time.Duration `json:"read"`
	Work  time.Duration `json:"work"`
	Bytes int64         `json:"bytes"`
}

type OpenTrace struct {
	Ended time.Time
	Bytes int64
	Call  upstream.CallTimes
	Took  OpenTook
}

type openTraceKey struct{}

func WithOpenTrace(ctx context.Context, t *OpenTrace) context.Context {
	return context.WithValue(ctx, openTraceKey{}, t)
}

func openTraceOf(ctx context.Context) *OpenTrace {
	t, _ := ctx.Value(openTraceKey{}).(*OpenTrace)
	return t
}

// why: net/http sends a body of unknown length chunked, headers first and a chunk per write, and a byte slice with its
// length in one write. A *bytes.Reader already has its length, which net/http reads, so it is sent as it is, uncopied.
func wholeBody(ctx context.Context, body io.Reader) (io.Reader, error) {
	if body == nil {
		return http.NoBody, nil
	}
	if _, sized := body.(*bytes.Reader); !sized {
		read, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(read)
	}
	if t := openTraceOf(ctx); t != nil {
		t.Ended = time.Now()
	}
	return body, nil
}

func (t *OpenTrace) took(h http.Header) {
	if t == nil {
		return
	}
	json.Unmarshal([]byte(h.Get(headerOpenTook)), &t.Took)
}

type timedBody struct {
	io.Reader
	bytes int64
	last  time.Time
}

func (b *timedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if n > 0 {
		b.bytes += int64(n)
		b.last = time.Now()
	}
	return n, err
}

func (b *timedBody) took(began time.Time) OpenTook {
	read := began
	if !b.last.IsZero() {
		read = b.last
	}
	return OpenTook{Read: read.Sub(began), Work: time.Since(read), Bytes: b.bytes}
}

func setOpenTook(h http.Header, took OpenTook) {
	data, _ := json.Marshal(took)
	h.Set(headerOpenTook, string(data))
}
