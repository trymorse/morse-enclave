package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"morse/backend/internal/apierr"
)

var ErrUnreachable = errors.New("upstream: the vendor could not be reached")

func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	if _, set := req.Header["User-Agent"]; !set {
		req.Header["User-Agent"] = []string{""}
	}
	resp, err := noRedirects(client).Do(req)
	if err != nil {
		return nil, transportFailure(req.Context(), err)
	}
	return resp, nil
}

func ErrorBody(resp *http.Response) []byte {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, apierr.MaxErrorBody))
	return body
}

func transportFailure(ctx context.Context, err error) error {
	var wrapped *url.Error
	switch {
	case errors.As(err, new(apierr.Error)) && errors.As(err, &wrapped):
		return wrapped.Err
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return ErrUnreachable
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
