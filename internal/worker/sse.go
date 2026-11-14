package worker

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect"
)

type eventStream struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	mu      sync.Mutex
	started bool
	err     error
}

func (s *eventStream) start() {
	if s.started {
		return
	}
	s.started = true
	s.w.Header().Set("Content-Type", eventStreamType)
	setEventStreamHeaders(s.w.Header())
	s.w.WriteHeader(http.StatusOK)
}

func setEventStreamHeaders(h http.Header) {
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
}

func (s *eventStream) events(events []dialect.Event) error {
	if len(events) == 0 {
		return nil
	}
	return s.write(func(w io.Writer) error {
		for _, e := range events {
			data := e.Data
			if !e.Unpadded {
				data = padObject(data, filler())
			}
			if err := writeEvent(w, e.Name, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func commentOf(text string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, ": "+text+"\n\n")
		return err
	}
}

func (s *eventStream) write(to func(io.Writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(to)
}

func (s *eventStream) writeLocked(to func(io.Writer) error) error {
	if s.err != nil {
		return s.err
	}
	s.start()
	s.err = to(s.w)
	return s.flush()
}

// Cloudflare cuts a response that sends nothing for 100 seconds.
const keepalive = 25 * time.Second

const eventStreamType = "text/event-stream"

func (s *eventStream) keepAlive(ctx context.Context, every time.Duration) (stop func()) {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				s.mu.Lock()
				if s.started {
					s.writeLocked(commentOf("keepalive"))
				}
				s.mu.Unlock()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func (s *eventStream) flush() error {
	if s.err == nil {
		s.err = s.rc.Flush()
	}
	return s.err
}

func writeEvent(w io.Writer, name string, data []byte) error {
	if name != "" {
		if _, err := io.WriteString(w, "event: "+name+"\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "data: "); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n\n")
	return err
}

type sseWriter struct {
	eventStream
	encoder    dialect.Encoder
	delivered  int
	visible    int
	shown      bool
	sent       bool
	finish     chat.Finish
	calls      chat.ToolCalls
	transcript *chat.Transcript
	clock      *thinkingClock
	veil       *replyVeil
}

func (s *sseWriter) emit(c chat.Chunk) error {
	d := c.Delta()
	s.clock.observe(d)
	finish, shown, sent := cmp.Or(d.Finish, s.finish), s.shown || d.Shown(), s.sent || d.Delivered()
	if unanswered(finish, sent) {
		c = c.MarkUnanswered()
	}
	c = s.veil.chunk(c)
	err := s.events(s.encoder.Chunk(c))
	if err == nil {
		s.delivered++
		s.visible += d.VisibleBytes()
		s.finish, s.shown, s.sent = finish, shown, sent
		s.transcript.Add(d)
		if d.ToolCalled {
			s.calls.Add(c)
		}
	}
	return err
}

func unanswered(finish chat.Finish, delivered bool) bool {
	return finish == chat.FinishLength && !delivered
}

var errEmptyReply = errors.New("worker: the stream ended having shown nothing")

func (s *sseWriter) empty() bool {
	return !s.shown && s.finish != chat.FinishLength && s.finish != chat.FinishContentFilter
}

const (
	MinFiller      = 16
	MaxFiller      = 64
	fillerAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func filler() string {
	b := make([]byte, MinFiller+rand.IntN(MaxFiller-MinFiller+1))
	for i := range b {
		b[i] = fillerAlphabet[rand.IntN(len(fillerAlphabet))]
	}
	return string(b)
}

func padObject(object []byte, filler string) []byte {
	body := bytes.TrimRight(object, " \t\r\n")
	if !bytes.HasSuffix(body, []byte("}")) {
		return object
	}
	if !json.Valid(object) || hasPadding(object) {
		return object
	}
	value, _ := json.Marshal(filler)
	open := body[:len(body)-1]
	padded := make([]byte, 0, len(object)+len(value)+len(`,"obfuscation":`))
	padded = append(padded, open...)
	if !bytes.HasSuffix(bytes.TrimRight(open, " \t\r\n"), []byte("{")) {
		padded = append(padded, ',')
	}
	padded = append(padded, `"obfuscation":`...)
	padded = append(padded, value...)
	padded = append(padded, '}')
	padded = append(padded, object[len(body):]...)
	return padded
}

var paddingKeys = []string{`"obfuscation"`, `"p"`}

// Only a chunk relayed in its upstream envelope can already carry padding, so a byte scan for the
// quoted keys spares the proxy's own chunks the parse into a map.
func hasPadding(object []byte) bool {
	if !slices.ContainsFunc(paddingKeys, func(key string) bool { return bytes.Contains(object, []byte(key)) }) {
		return false
	}
	var topLevel map[string]json.RawMessage
	if json.Unmarshal(object, &topLevel) != nil {
		return true
	}
	return slices.ContainsFunc(paddingKeys, func(key string) bool {
		_, ok := topLevel[key[1:len(key)-1]]
		return ok
	})
}

// closeVeil writes, before the stream ends, any text the Veil still holds back and the report.
func (s *sseWriter) closeVeil() {
	for _, c := range s.veil.closing() {
		s.events(s.encoder.Chunk(c))
	}
}

func (s *sseWriter) done(usage chat.Usage) {
	s.events(s.encoder.End(usage))
}

func (s *sseWriter) errorEvent() {
	s.events(s.encoder.Failed(apierr.ErrUpstream))
}
