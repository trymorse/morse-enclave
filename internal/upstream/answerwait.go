package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const HeaderWait = 2 * time.Minute

var errNoAnswer = errors.New("upstream: no reply headers within the endpoint's answer wait")

// why: ResponseHeaderTimeout is a transport's, not a request's, so a longer wait needs a transport without one. One
// such clone per base transport keeps those calls on one pool of connections.
var patientTransports sync.Map

func awaiting(client *http.Client, wait time.Duration) *http.Client {
	if client == nil {
		return nil
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok || base.ResponseHeaderTimeout <= 0 || wait <= base.ResponseHeaderTimeout {
		return client
	}
	patient, ok := patientTransports.Load(base)
	if !ok {
		clone := base.Clone()
		clone.ResponseHeaderTimeout = 0
		patient, _ = patientTransports.LoadOrStore(base, clone)
	}
	c := *client
	c.Transport = answerDeadline{next: patient.(*http.Transport), wait: wait}
	return &c
}

type answerDeadline struct {
	next http.RoundTripper
	wait time.Duration
}

func (d answerDeadline) RoundTrip(req *http.Request) (*http.Response, error) {
	// why: only this copy's context is cancelled, so the caller reads a missed deadline as the vendor unreachable and
	// not as its own request cancelled.
	ctx, cancel := context.WithCancelCause(req.Context())
	timer := time.AfterFunc(d.wait, func() { cancel(errNoAnswer) })
	resp, err := d.next.RoundTrip(req.WithContext(ctx))
	if !timer.Stop() && err == nil {
		resp.Body.Close()
		err = errNoAnswer
	}
	if err != nil {
		cancel(nil)
		return nil, err
	}
	resp.Body = canceledOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type canceledOnClose struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b canceledOnClose) Close() error {
	defer b.cancel(nil)
	return b.ReadCloser.Close()
}
