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
	ExtractModel      = "extract"
	searchPath        = "/v1/search"
	extractPath       = "/v1/extract"
	maxReplyBytes     = 8 << 20
	searchTimeout     = 20 * time.Second
	extractTimeout    = 40 * time.Second
	liveFetchSeconds  = 10
	retryFetchSeconds = 20
	fetchTimedOut     = "timeout"
	sharedRPM         = 500
)

// why: Parallel answers a read from its cache however old the copy unless the request sets max_age_seconds, and gave
// a read with an objective a copy nine months old (https://docs.parallel.ai/extract/advanced-extract-settings).
const maxPageAgeSeconds = 24 * 60 * 60

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
	AcquiredAt  *string  `json:"acquired_at"`
}

type failure struct {
	Type string `json:"error_type"`
}

type reply struct {
	Results []result  `json:"results"`
	Errors  []failure `json:"errors"`
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

type sourcePolicy struct {
	IncludeDomains []string `json:"include_domains"`
}

type searchSettings struct {
	MaxResults   int           `json:"max_results"`
	SourcePolicy *sourcePolicy `json:"source_policy,omitempty"`
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
	if domains := req.Domains(); len(domains) > 0 {
		body.AdvancedSettings.SourcePolicy = &sourcePolicy{IncludeDomains: domains}
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
	MaxAgeSeconds  int `json:"max_age_seconds"`
}

type excerptSettings struct {
	MaxCharsPerResult int `json:"max_chars_per_result"`
}

// why: Parallel returns excerpts by default and full content only when it is asked for.
type extractSettings struct {
	FullContent     *fullContent     `json:"full_content,omitempty"`
	ExcerptSettings *excerptSettings `json:"excerpt_settings,omitempty"`
	FetchPolicy     fetchPolicy      `json:"fetch_policy"`
}

type extractRequest struct {
	URLs             []string        `json:"urls"`
	Objective        string          `json:"objective,omitempty"`
	AdvancedSettings extractSettings `json:"advanced_settings"`
}

func (e *Extract) Fetch(ctx context.Context, req *web.FetchRequest) (web.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	body := extractRequest{
		URLs:             []string{req.UpstreamURL()},
		AdvancedSettings: extractSettings{FetchPolicy: fetchPolicy{TimeoutSeconds: liveFetchSeconds, MaxAgeSeconds: maxPageAgeSeconds}},
	}
	if req.Objective() != "" {
		body.Objective = req.Objective()
		body.AdvancedSettings.ExcerptSettings = &excerptSettings{MaxCharsPerResult: web.MaxPurposeChars}
		return e.fetchExcerpts(ctx, req, body)
	}
	body.AdvancedSettings.FullContent = &fullContent{MaxCharsPerResult: web.MaxContentChars + 1}
	got, err := e.extract(ctx, body)
	if err != nil {
		return web.Page{}, err
	}
	switch {
	case got.Results == nil:
		return web.Page{}, web.ErrUpstream
	case len(got.Results) == 0, got.Results[0].FullContent == nil, strings.TrimSpace(*got.Results[0].FullContent) == "":
		return web.Page{}, web.ErrFetchFailed
	}
	r := got.Results[0]
	return web.NewPage(req, r.URL, r.Title, r.PublishDate, *r.FullContent).FetchedAt(r.AcquiredAt), nil
}

// why: Parallel answers a live fetch that outruns timeout_seconds with its older copy, and with a timeout error
// when it has none (https://docs.parallel.ai/extract/advanced-extract-settings), so only that error waits longer.
func (e *Extract) extract(ctx context.Context, body extractRequest) (reply, error) {
	got, err := e.post(ctx, body)
	if err != nil || got.Results == nil || len(got.Results) > 0 || !slices.ContainsFunc(got.Errors, func(f failure) bool { return f.Type == fetchTimedOut }) {
		return got, err
	}
	body.AdvancedSettings.FetchPolicy.TimeoutSeconds = retryFetchSeconds
	return e.post(ctx, body)
}

func (e *Extract) post(ctx context.Context, body extractRequest) (reply, error) {
	var got reply
	err := e.call(ctx, upstream.Request{Method: http.MethodPost, Path: extractPath, Body: jsonx.Encode(body)}, &got)
	return got, err
}

func (e *Extract) fetchExcerpts(ctx context.Context, req *web.FetchRequest, body extractRequest) (web.Page, error) {
	got, err := e.extract(ctx, body)
	if err != nil {
		return web.Page{}, err
	}
	if got.Results == nil {
		return web.Page{}, web.ErrUpstream
	}
	if len(got.Results) == 0 {
		return web.Page{}, web.ErrFetchFailed
	}
	r := got.Results[0]
	text := strings.TrimSpace(strings.Join(r.Excerpts, "\n\n"))
	if text == "" {
		return web.Page{}, web.ErrFetchFailed
	}
	text, _ = web.Clip(text, web.MaxPurposeChars)
	return web.NewPage(req, r.URL, r.Title, r.PublishDate, text).FetchedAt(r.AcquiredAt), nil
}
