package worker

import (
	"io"
	"net/http"
	"strings"

	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
)

type relayWriter struct {
	w           http.ResponseWriter
	rc          *http.ResponseController
	pad         bool
	lead        []byte
	eventStream bool
	atLineStart bool
	written     int
	err         error
}

func (rw *relayWriter) begin(head chat.Relayed) io.Writer {
	h := rw.w.Header()
	rw.eventStream = strings.HasPrefix(strings.ToLower(head.ContentType), eventStreamType)
	if head.ContentType != "" {
		h.Set("Content-Type", head.ContentType)
	}
	if rw.eventStream {
		setEventStreamHeaders(h)
	}
	for _, header := range head.Headers {
		h.Set(header.Name, header.Value)
	}
	rw.w.WriteHeader(http.StatusOK)
	rw.atLineStart = true
	if rw.eventStream && len(rw.lead) > 0 {
		_, rw.err = rw.w.Write(rw.lead)
	}
	return rw
}

func (rw *relayWriter) Write(p []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if rw.pad && rw.eventStream && rw.atLineStart {
		if _, rw.err = rw.w.Write(e2ee.PadComment(filler())); rw.err != nil {
			return 0, rw.err
		}
	}
	n, err := rw.w.Write(p)
	rw.err = err
	if err == nil {
		rw.atLineStart = p[len(p)-1] == '\n'
		rw.err = rw.rc.Flush()
	}
	if rw.err == nil {
		rw.written += n
	}
	return n, rw.err
}
