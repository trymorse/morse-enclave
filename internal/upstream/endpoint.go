package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/capped"
)

var (
	ErrMalformed     = errors.New("upstream: vendor reply is not usable")
	ErrNotFound      = errors.New("upstream: the vendor returned 404")
	ErrNotObject     = errors.New("upstream: the vendor's reply is not a JSON object")
	errReplyTooLarge = fmt.Errorf("upstream: vendor reply exceeds size limit: %w", capped.ErrTooLarge)
)

// Objects is an endpoint whose GETs each answer one JSON object, such as a vendor's attestation reports and
// receipts. A 404 is ErrNotFound.
func Objects(baseURL, apiKey string, client *http.Client) Endpoint {
	return Endpoint{BaseURL: baseURL, Auth: Bearer(apiKey), HTTP: client, Refuse: refuseObject}
}

func (e Endpoint) Object(ctx context.Context, path string, limit int64) ([]byte, error) {
	reply, err := e.JSON(ctx, Request{Method: http.MethodGet, Path: path}, nil, limit)
	if err != nil {
		return nil, err
	}
	if !json.Valid(reply.Body) || !bytes.HasPrefix(bytes.TrimSpace(reply.Body), []byte("{")) {
		return nil, ErrNotObject
	}
	return reply.Body, nil
}

func refuseObject(r Reply) error {
	if r.Status == http.StatusNotFound {
		return ErrNotFound
	}
	return fmt.Errorf("upstream: the vendor returned %d", r.Status)
}

type Endpoint struct {
	BaseURL string
	Auth    http.Header
	HTTP    *http.Client
	Refuse  func(Reply) error // nil: apierr.SanitizedUpstreamError
	Failed  error             // wraps a transport failure and an unusable reply; nil: they pass through bare
	Confirm func(get func(name string) string) error
}

type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
	Parts  [][]byte
}

func (r Request) body() (int64, func() (io.ReadCloser, error)) {
	chunks := append([][]byte{r.Body}, r.Parts...)
	var length int64
	for _, chunk := range chunks {
		length += int64(len(chunk))
	}
	if length == 0 {
		return 0, func() (io.ReadCloser, error) { return http.NoBody, nil }
	}
	return length, func() (io.ReadCloser, error) {
		unread := net.Buffers(slices.Clone(chunks))
		return io.NopCloser(&unread), nil
	}
}

type Reply struct {
	Status int
	Header http.Header
	Body   []byte
}

type Refused struct {
	Status int
	Err    error
}

func (r Refused) Error() string   { return r.Err.Error() }
func (r Refused) Unwrap() error   { return r.Err }
func (r Refused) Transient() bool { return transient(r.Status) }

func transient(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }

type Unusable bool

const (
	UnusableRetries Unusable = false
	UnusableEnds    Unusable = true
)

// Final reports whether a failed poll ends the job. A refusal ends it unless its status is one a
// later poll can change. A 2xx reply that cannot be read ends it only for a caller that says so.
// Anything else, a transport failure included, is retried.
func Final(err error, unusable Unusable) bool {
	var r Refused
	if errors.As(err, &r) {
		return !r.Transient()
	}
	return bool(unusable) && (errors.Is(err, ErrMalformed) || errors.Is(err, capped.ErrTooLarge))
}

func Bearer(key string) http.Header {
	if key == "" {
		return nil
	}
	return http.Header{"Authorization": {"Bearer " + key}}
}

func (e Endpoint) Open(ctx context.Context, r Request) (*http.Response, error) {
	resp, err := e.send(ctx, r)
	if err != nil {
		return nil, e.fail(err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, e.refuse(Reply{Status: resp.StatusCode, Header: resp.Header, Body: ErrorBody(resp)})
	}
	if err := e.confirm(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

func (e Endpoint) Call(ctx context.Context, r Request, limit int64) (Reply, error) {
	reply, err := e.call(ctx, r, limit)
	return reply, e.fail(err)
}

func (e Endpoint) call(ctx context.Context, r Request, limit int64) (Reply, error) {
	r.Header = r.Header.Clone()
	if r.Header == nil {
		r.Header = http.Header{}
	}
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", "application/json")
	}
	resp, err := e.send(ctx, r)
	if err != nil {
		return Reply{}, err
	}
	defer resp.Body.Close()
	reply := Reply{Status: resp.StatusCode, Header: resp.Header}
	if resp.StatusCode/100 != 2 {
		reply.Body = ErrorBody(resp)
		return reply, nil
	}
	if err := e.confirm(resp); err != nil {
		return Reply{}, err
	}
	data, err := capped.ReadAll(resp.Body, limit)
	switch {
	case errors.Is(err, capped.ErrTooLarge):
		return reply, errReplyTooLarge
	case err != nil && ctx.Err() != nil:
		return Reply{}, ctx.Err()
	case err != nil:
		return Reply{}, ErrUnreachable
	}
	reply.Body = data
	return reply, nil
}

func (e Endpoint) JSON(ctx context.Context, r Request, into any, limit int64) (Reply, error) {
	reply, err := e.call(ctx, r, limit)
	switch {
	case err != nil:
		return reply, e.fail(err)
	case reply.Status/100 != 2:
		return reply, e.refuse(reply)
	case into != nil && json.Unmarshal(reply.Body, into) != nil:
		return reply, e.fail(ErrMalformed)
	}
	return reply, nil
}

func (e Endpoint) send(ctx context.Context, r Request) (*http.Response, error) {
	h := r.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	for name := range e.Auth {
		for have := range h {
			if strings.EqualFold(have, name) {
				delete(h, have)
			}
		}
	}
	maps.Copy(h, e.Auth)
	req, err := http.NewRequestWithContext(ctx, r.Method, e.BaseURL+r.Path, nil)
	if err != nil {
		return nil, notSent(ErrUnreachable)
	}
	if r.Body != nil || r.Parts != nil {
		if h.Get("Content-Type") == "" {
			h.Set("Content-Type", "application/json")
		}
		req.ContentLength, req.GetBody = r.body()
		req.Body, _ = req.GetBody()
	}
	req.Header = h
	return Do(e.HTTP, req)
}

func (e Endpoint) confirm(resp *http.Response) error {
	if e.Confirm == nil {
		return nil
	}
	if err := e.Confirm(resp.Header.Get); err != nil {
		return Refused{Status: resp.StatusCode, Err: err}
	}
	return nil
}

func (e Endpoint) refuse(r Reply) error {
	if e.Refuse != nil {
		return Refused{Status: r.Status, Err: e.Refuse(r)}
	}
	return Refused{Status: r.Status, Err: apierr.SanitizedUpstreamError(r.Status, r.Body)}
}

func (e Endpoint) fail(err error) error {
	if err == nil || e.Failed == nil || errors.As(err, new(Refused)) {
		return err
	}
	return fmt.Errorf("%w: %w", e.Failed, err)
}
