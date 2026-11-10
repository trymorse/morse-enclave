package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"

	"morse/backend/internal/apierr"
)

var ErrUnreachable = errors.New("upstream: the vendor could not be reached")

// ErrNotSent marks a failure before the request's headers were written: the name did not resolve, the connection was
// refused, the TLS handshake failed, or the caller left while any of these hung. The vendor never received the request,
// so it bills nothing. It joins the failure's own cause, ErrUnreachable or the context's error, so health still reads
// that cause.
var ErrNotSent = errors.New("upstream: the request was never sent")

func notSent(cause error) error { return fmt.Errorf("%w: %w", ErrNotSent, cause) }

// ErrStalled is a stream the proxy gave up before its first chunk: the vendor sent no headers, or headers and then
// nothing, for longer than a healthy host takes. It joins ErrNotSent when the request's headers were never written.
var ErrStalled = errors.New("upstream: the vendor sent no first chunk in time")

// Stalled is ErrStalled for a call that ended with err once the proxy gave it up, keeping whether it was sent.
func Stalled(err error) error {
	if errors.Is(err, ErrNotSent) {
		return notSent(ErrStalled)
	}
	return ErrStalled
}

func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	if _, set := req.Header["User-Agent"]; !set {
		req.Header["User-Agent"] = []string{""}
	}
	if err := egress(req); err != nil {
		return nil, err
	}
	var wrote atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteHeaders: func() { wrote.Store(true) }}))
	resp, err := noRedirects(client).Do(req)
	if err != nil {
		return nil, transportFailure(req.Context(), err, wrote.Load())
	}
	return resp, nil
}

func ErrorBody(resp *http.Response) []byte {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, apierr.MaxErrorBody))
	return body
}

func transportFailure(ctx context.Context, err error, sent bool) error {
	var wrapped *url.Error
	if errors.As(err, new(apierr.Error)) && errors.As(err, &wrapped) {
		return wrapped.Err
	}
	failure := ErrUnreachable
	if ctx.Err() != nil {
		failure = ctx.Err()
	}
	if sent {
		return failure
	}
	return notSent(failure)
}

func noRedirects(client *http.Client) *http.Client {
	var c http.Client
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.Jar = nil
	return &c
}
