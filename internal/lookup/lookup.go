// Package lookup relays the app's agent tools' reads of public JSON APIs, so the third party sees
// the proxy's address instead of the user's.
package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/flight"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/upstream"
)

// UserAgent identifies the relay to every service. Wikipedia and MET Norway refuse anonymous clients
// and ask for a way to reach the operator.
const UserAgent = "Morse/1.0 (https://trymorse.ai; hello@trymorse.ai)"

const (
	MaxReplyBytes  = 2 << 20
	maxQueryBytes  = 4 << 10
	callTimeout    = 15 * time.Second
	cacheEntries   = 4096
	cacheBytes     = 64 << 20
	busyRetryAfter = 30 * time.Second
)

var (
	ErrNotFound    = apierr.Invalid(http.StatusNotFound, "lookup_not_found", "No such lookup.")
	ErrBadQuery    = apierr.Invalid(http.StatusBadRequest, "invalid_lookup_query", "The lookup's query string is malformed.")
	ErrUnavailable = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "lookup_unavailable", Message: "The lookup service is unavailable."}
	ErrBusy        = apierr.Error{Status: http.StatusServiceUnavailable, Type: "upstream_error", Code: "lookup_busy", Message: "The lookup service is busy. Retry after the time in the Retry-After header."}
)

type Busy struct{ RetryAfter time.Duration }

func (b Busy) Error() string { return "lookup: busy, retry after " + b.RetryAfter.String() }

type service struct {
	Service
	endpoint upstream.Endpoint
}

type Relay struct {
	services map[string]service
	cache    *cache
	flight   flight.Group[[]byte]
	now      func() time.Time
}

func New(services map[string]Service, client *http.Client, now func() time.Time) *Relay {
	built := make(map[string]service, len(services))
	for name, s := range services {
		built[name] = service{s, endpointFor(s, client)}
	}
	return &Relay{services: built, cache: newCache(cacheEntries, cacheBytes), now: now}
}

func endpointFor(s Service, client *http.Client) upstream.Endpoint {
	return upstream.Endpoint{BaseURL: s.Base, Auth: s.AuthHeader, HTTP: client, Failed: ErrUnavailable,
		Refuse: func(r upstream.Reply) error {
			switch r.Status {
			case http.StatusTooManyRequests:
				return Busy{RetryAfter: retryAfter(r.Header)}
			case http.StatusNotFound:
				return ErrNotFound
			}
			return fmt.Errorf("%w: status %d", ErrUnavailable, r.Status)
		},
		Confirm: func(get func(string) string) error {
			if contentType := get("Content-Type"); !isJSON(contentType) {
				return fmt.Errorf("%w: Content-Type %q", ErrUnavailable, contentType)
			}
			return nil
		},
	}
}

type Lookup struct {
	Limit  limits.SharedLimit
	Cached bool
}

type target struct {
	service service
	key     string
	query   url.Values
	path    string
}

func (r *Relay) resolve(name, path, rawQuery string) (target, error) {
	s, ok := r.services[name]
	if !ok || !slices.Contains(s.Paths, "/"+path) {
		return target{}, ErrNotFound
	}
	if len(rawQuery) > maxQueryBytes {
		return target{}, ErrBadQuery
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return target{}, ErrBadQuery
	}
	for k := range s.AuthQuery {
		query.Del(k)
	}
	return target{service: s, key: name + "/" + path + "?" + query.Encode(), query: query, path: path}, nil
}

func (r *Relay) Look(service, path, rawQuery string) (Lookup, error) {
	t, err := r.resolve(service, path, rawQuery)
	if err != nil {
		return Lookup{}, err
	}
	_, hit := r.cache.get(t.key, r.now())
	return Lookup{Limit: t.service.Limit, Cached: hit}, nil
}

func (r *Relay) Get(ctx context.Context, service, path, rawQuery string) ([]byte, error) {
	t, err := r.resolve(service, path, rawQuery)
	if err != nil {
		return nil, err
	}
	if body, hit := r.cache.get(t.key, r.now()); hit {
		return body, nil
	}
	return r.flight.Do(ctx, t.key, callTimeout, func(ctx context.Context) ([]byte, error) {
		body, ttl, err := r.call(ctx, t.service, "/"+t.path+"?"+withAuth(t.query, t.service.AuthQuery))
		if err == nil && ttl > 0 {
			r.cache.put(t.key, body, r.now().Add(ttl))
		}
		return body, err
	})
}

func withAuth(query, auth url.Values) string {
	all := url.Values{}
	for _, v := range []url.Values{query, auth} {
		for k, vs := range v {
			all[k] = append(all[k], vs...)
		}
	}
	return all.Encode()
}

func (r *Relay) call(ctx context.Context, s service, target string) ([]byte, time.Duration, error) {
	reply, err := s.endpoint.JSON(ctx, upstream.Request{Method: http.MethodGet, Path: target, Header: http.Header{"User-Agent": {UserAgent}}}, new(json.RawMessage), MaxReplyBytes)
	if err != nil {
		return nil, 0, err
	}
	return reply.Body, s.TTL(reply.Header, r.now()), nil
}

func isJSON(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	return err == nil && (media == "application/json" || strings.HasSuffix(media, "+json"))
}

func retryAfter(h http.Header) time.Duration {
	if seconds, err := strconv.Atoi(h.Get("Retry-After")); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return busyRetryAfter
}
