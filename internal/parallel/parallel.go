package parallel

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/research"
	"morse/backend/internal/upstream"
	"morse/backend/internal/web"
)

const (
	ExtractModel     = "extract"
	searchPath       = "/v1/search"
	extractPath      = "/v1/extract"
	maxReplyBytes    = 8 << 20
	searchTimeout    = 20 * time.Second
	extractTimeout   = 40 * time.Second
	liveFetchSeconds = 30
	sharedRPM        = 500
)

var (
	SearchLimit  = limits.SharedLimit{Subject: "parallel/search", RPM: sharedRPM}
	ExtractLimit = limits.SharedLimit{Subject: "parallel/fetch", RPM: sharedRPM}
)

var modes = []string{"turbo", "fast", "basic", "advanced"}

var (
	webErrors      = apierr.Family{Busy: web.ErrUpstreamBusy, Unavailable: web.ErrUpstreamUnavailable, Failed: web.ErrUpstream}
	researchErrors = apierr.Family{Busy: research.ErrUpstreamBusy, Unavailable: research.ErrUpstreamUnavailable, Failed: research.ErrUpstream}
)

type client struct{ vendor upstream.Endpoint }

func newClient(baseURL, apiKey string, httpClient *http.Client, errors apierr.Family) client {
	return client{upstream.Endpoint{BaseURL: baseURL, Auth: http.Header{"X-Api-Key": {apiKey}}, HTTP: httpClient,
		Refuse: func(r upstream.Reply) error { return errors.Of(r.Status) }, Failed: errors.Failed}}
}

func (c client) call(ctx context.Context, r upstream.Request, reply any) error {
	_, err := c.vendor.JSON(ctx, r, reply, maxReplyBytes)
	return err
}

type result struct {
	URL         string   `json:"url"`
	Title       *string  `json:"title"`
	PublishDate *string  `json:"publish_date"`
	Excerpts    []string `json:"excerpts"`
	FullContent *string  `json:"full_content"`
}

type reply struct {
	Results []result `json:"results"`
}

type Search struct {
	client
	mode    string
	Timeout time.Duration
}

func NewSearch(baseURL, apiKey, mode string, httpClient *http.Client) (*Search, error) {
	if !slices.Contains(modes, mode) {
		return nil, fmt.Errorf("%q is not a search mode parallel serves, one of %s", mode, strings.Join(modes, ", "))
	}
	return &Search{client: newClient(baseURL, apiKey, httpClient, webErrors), mode: mode, Timeout: searchTimeout}, nil
}

type searchSettings struct {
	MaxResults int `json:"max_results"`
}

// Parallel bills an omitted mode as advanced, five times the price of fast.
type searchRequest struct {
	Mode             string         `json:"mode"`
	SearchQueries    []string       `json:"search_queries"`
	Objective        string         `json:"objective,omitempty"`
	MaxCharsTotal    int            `json:"max_chars_total"`
	AdvancedSettings searchSettings `json:"advanced_settings"`
}

func (s *Search) Search(ctx context.Context, req *web.SearchRequest) (web.Results, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	body := searchRequest{
		Mode: s.mode, SearchQueries: req.Queries(), Objective: req.Objective(),
		MaxCharsTotal: web.MaxExcerptChars, AdvancedSettings: searchSettings{MaxResults: web.MaxResults},
	}
	var got reply
	if err := s.call(ctx, upstream.Request{Method: http.MethodPost, Path: searchPath, Body: jsonx.Encode(body)}, &got); err != nil {
		return web.Results{}, err
	}
	if got.Results == nil {
		return web.Results{}, web.ErrUpstream
	}
	var out web.Results
	for _, r := range got.Results {
		out.Add(r.URL, r.Title, r.PublishDate, r.Excerpts)
	}
	return out, nil
}

type Extract struct {
	client
	Timeout time.Duration
}

func NewExtract(baseURL, apiKey, model string, httpClient *http.Client) (*Extract, error) {
	if model != ExtractModel {
		return nil, fmt.Errorf("%q is not a fetch model parallel serves, only %s", model, ExtractModel)
	}
	return &Extract{client: newClient(baseURL, apiKey, httpClient, webErrors), Timeout: extractTimeout}, nil
}

type fullContent struct {
	MaxCharsPerResult int `json:"max_chars_per_result"`
}

type fetchPolicy struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

type extractSettings struct {
	FullContent fullContent `json:"full_content"`
	FetchPolicy fetchPolicy `json:"fetch_policy"`
}

type extractRequest struct {
	URLs             []string        `json:"urls"`
	AdvancedSettings extractSettings `json:"advanced_settings"`
}

func (e *Extract) Fetch(ctx context.Context, req *web.FetchRequest) (web.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	body := extractRequest{
		URLs: []string{req.UpstreamURL()},
		AdvancedSettings: extractSettings{
			FullContent: fullContent{MaxCharsPerResult: web.MaxContentChars + 1},
			FetchPolicy: fetchPolicy{TimeoutSeconds: liveFetchSeconds},
		},
	}
	var got reply
	if err := e.call(ctx, upstream.Request{Method: http.MethodPost, Path: extractPath, Body: jsonx.Encode(body)}, &got); err != nil {
		return web.Page{}, err
	}
	switch {
	case got.Results == nil:
		return web.Page{}, web.ErrUpstream
	case len(got.Results) == 0, got.Results[0].FullContent == nil, strings.TrimSpace(*got.Results[0].FullContent) == "":
		return web.Page{}, web.ErrFetchFailed
	}
	r := got.Results[0]
	return web.NewPage(req, r.URL, r.Title, r.PublishDate, *r.FullContent), nil
}
