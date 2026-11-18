package upstream

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

type CallClock struct {
	mu      sync.Mutex
	began   time.Time
	claimed bool
	dns     [2]time.Time
	dial    [2]time.Time
	tls     [2]time.Time
	got     time.Time
	reused  bool
	wrote   time.Time
	head    time.Time
}

type CallTimes struct {
	Reused  bool          `json:",omitempty"`
	DNS     time.Duration `json:",omitempty"`
	Dial    time.Duration `json:",omitempty"`
	TLS     time.Duration `json:",omitempty"`
	Connect time.Duration `json:",omitempty"`
	Sent    time.Duration `json:",omitempty"`
	Head    time.Duration `json:",omitempty"`
}

type callClockKey struct{}

func WithCallClock(ctx context.Context, c *CallClock) context.Context {
	return context.WithValue(ctx, callClockKey{}, c)
}

func (c *CallClock) trace(ctx context.Context) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claimed {
		return ctx
	}
	c.claimed, c.began = true, time.Now()
	at := func(t *time.Time) func() {
		return func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if t.IsZero() {
				*t = time.Now()
			}
		}
	}
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { at(&c.dns[0])() },
		DNSDone:           func(httptrace.DNSDoneInfo) { at(&c.dns[1])() },
		ConnectStart:      func(string, string) { at(&c.dial[0])() },
		ConnectDone:       func(string, string, error) { at(&c.dial[1])() },
		TLSHandshakeStart: at(&c.tls[0]),
		TLSHandshakeDone:  func(tls.ConnectionState, error) { at(&c.tls[1])() },
		GotConn: func(info httptrace.GotConnInfo) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.got.IsZero() {
				c.got, c.reused = time.Now(), info.Reused
			}
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { at(&c.wrote)() },
		GotFirstResponseByte: at(&c.head),
	})
}

func (c *CallClock) Times() CallTimes {
	c.mu.Lock()
	defer c.mu.Unlock()
	span := func(from, to time.Time) time.Duration {
		if from.IsZero() || to.Before(from) {
			return 0
		}
		return to.Sub(from)
	}
	wrote, head := c.wrote, time.Duration(0)
	if !c.head.IsZero() {
		if wrote.IsZero() || c.head.Before(wrote) {
			wrote = c.head
		}
		head = max(span(wrote, c.head), 1)
	}
	return CallTimes{
		Reused:  c.reused,
		DNS:     span(c.dns[0], c.dns[1]),
		Dial:    span(c.dial[0], c.dial[1]),
		TLS:     span(c.tls[0], c.tls[1]),
		Connect: span(c.began, c.got),
		Sent:    span(c.began, wrote),
		Head:    head,
	}
}

func callClockOf(ctx context.Context) *CallClock {
	c, _ := ctx.Value(callClockKey{}).(*CallClock)
	return c
}
