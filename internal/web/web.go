package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/strictjson"
)

const (
	MaxRequestBody    = 64 << 10
	MaxQueries        = 3
	MaxQueryChars     = 200
	MaxObjectiveChars = 500
	MaxURLLength      = 2048
	MaxResults        = 10
	MaxExcerptChars   = 8000
	MaxTitleChars     = 300
	MaxContentChars   = 12_000
	dateLayout        = "2006-01-02"
)

var (
	ErrInvalidURL = errors.New("web: url must be http or https on a public host and the default port, 80, or 443, at most 2048 characters, without credentials")

	ErrUpstreamBusy        = apierr.Error{Status: 503, Type: "upstream_error", Code: "upstream_busy", Message: "The web provider is busy. Try again shortly."}
	ErrUpstreamUnavailable = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_unavailable", Message: "The web provider is unavailable."}
	ErrUpstream            = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_error", Message: "The web provider failed."}
	ErrFetchFailed         = apierr.Error{Status: 422, Type: "upstream_error", Code: "fetch_failed", Message: "The page could not be read."}

	nonPublicPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("fec0::/10"),
	}
	nonPublicSuffixes = []string{".localhost", ".local", ".internal", ".home.arpa", ".lan", ".home", ".corp"}
)

type SearchRequest struct {
	Model     string
	queries   []string
	objective string
}

func (r SearchRequest) ModelName() string { return r.Model }
func (r SearchRequest) Queries() []string { return slices.Clone(r.queries) }
func (r SearchRequest) Objective() string { return r.objective }
func (r SearchRequest) String() string {
	return fmt.Sprintf("web.SearchRequest(%s, %d queries, objective %t)", r.Model, len(r.queries), r.objective != "")
}
func (r SearchRequest) GoString() string { return r.String() }

type FetchRequest struct {
	Model string
	url   string
}

func (r FetchRequest) ModelName() string { return r.Model }

func (r FetchRequest) UpstreamURL() string {
	page, _, _ := strings.Cut(r.url, "#")
	return page
}

func (r FetchRequest) String() string   { return fmt.Sprintf("web.FetchRequest(%s)", r.Model) }
func (r FetchRequest) GoString() string { return r.String() }

func ParseSearchRequest(body io.Reader) (*SearchRequest, error) {
	fields, err := strictjson.Object(body, "model", "queries", "objective")
	if err != nil {
		return nil, err
	}
	model, err := modelOf(fields)
	if err != nil {
		return nil, err
	}
	var queries []string
	if json.Unmarshal(fields["queries"], &queries) != nil || len(queries) == 0 || len(queries) > MaxQueries {
		return nil, strictjson.Invalid(fmt.Sprintf("queries must be a list of 1 to %d strings.", MaxQueries))
	}
	for i, q := range queries {
		queries[i] = strings.TrimSpace(q)
		if n := utf8.RuneCountInString(queries[i]); n == 0 || n > MaxQueryChars {
			return nil, strictjson.Invalid(fmt.Sprintf("Each query must be 1 to %d characters.", MaxQueryChars))
		}
	}
	var objective string
	if raw, ok := fields["objective"]; ok && json.Unmarshal(raw, &objective) != nil {
		return nil, strictjson.Invalid("objective must be a string.")
	}
	if objective = strings.TrimSpace(objective); utf8.RuneCountInString(objective) > MaxObjectiveChars {
		return nil, strictjson.Invalid(fmt.Sprintf("objective must be at most %d characters.", MaxObjectiveChars))
	}
	return &SearchRequest{Model: model, queries: queries, objective: objective}, nil
}

func ParseFetchRequest(body io.Reader) (*FetchRequest, error) {
	fields, err := strictjson.Object(body, "model", "url")
	if err != nil {
		return nil, err
	}
	model, err := modelOf(fields)
	if err != nil {
		return nil, err
	}
	var raw string
	if json.Unmarshal(fields["url"], &raw) != nil {
		return nil, ErrInvalidURL
	}
	page, ok := PageURL(raw)
	if !ok || !fetchable(page) {
		return nil, ErrInvalidURL
	}
	return &FetchRequest{Model: model, url: page}, nil
}

func fetchable(page string) bool {
	u, err := url.Parse(page)
	if err != nil {
		return false
	}
	switch u.Port() {
	case "", "80", "443":
	default:
		return false
	}
	host := strings.ToLower(u.Hostname())
	mapped := strings.ToLower(strings.ReplaceAll(norm.NFKC.String(host), "\u3002", "."))
	return publicHost(host) && publicHost(mapped)
}

func publicHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return PublicAddr(addr.WithZone("").Unmap())
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 || slices.Contains(labels, "") || numericLabel(labels[len(labels)-1]) {
		return false
	}
	return !slices.ContainsFunc(nonPublicSuffixes, func(suffix string) bool { return strings.HasSuffix(host, suffix) })
}

// PublicAddr reports whether addr is a public unicast address: no private, loopback, link-local, CGNAT,
// reserved, or translated range.
func PublicAddr(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	return !slices.ContainsFunc(nonPublicPrefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

func numericLabel(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(label, "0123456789") == ""
}

func modelOf(fields map[string]json.RawMessage) (string, error) {
	var model string
	if json.Unmarshal(fields["model"], &model) != nil || model == "" {
		return "", strictjson.Invalid("model is required.")
	}
	return model, nil
}

func PageURL(raw string) (string, bool) {
	if raw == "" || utf8.RuneCountInString(raw) > MaxURLLength || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return "", false
	}
	return raw, true
}

type Result struct {
	url       string
	title     string
	published string
	excerpts  []string
}

type Results struct {
	list  []Result
	chars int
}

func (rs *Results) Add(link string, title, published *string, excerpts []string) {
	if len(rs.list) == MaxResults {
		return
	}
	link, ok := PageURL(link)
	if !ok {
		return
	}
	r := Result{url: link, title: TitleOf(title), published: dateOf(published), excerpts: []string{}}
	for _, e := range excerpts {
		left := MaxExcerptChars - rs.chars
		if left <= 0 {
			break
		}
		if strings.TrimSpace(e) == "" {
			continue
		}
		e, _ = Clip(e, left)
		rs.chars += utf8.RuneCountInString(e)
		r.excerpts = append(r.excerpts, e)
	}
	rs.list = append(rs.list, r)
}

func (rs Results) Len() int         { return len(rs.list) }
func (rs Results) String() string   { return fmt.Sprintf("web.Results(%d results)", len(rs.list)) }
func (rs Results) GoString() string { return rs.String() }
func (r Result) String() string     { return fmt.Sprintf("web.Result(%d excerpts)", len(r.excerpts)) }
func (r Result) GoString() string   { return r.String() }

type Page struct {
	url       string
	title     string
	published string
	content   string
	truncated bool
}

func NewPage(req *FetchRequest, reported string, title, published *string, content string) Page {
	link, ok := PageURL(reported)
	if !ok {
		link = req.UpstreamURL()
	}
	body, truncated := Clip(content, MaxContentChars)
	return Page{url: link, title: TitleOf(title), published: dateOf(published), content: body, truncated: truncated}
}

func (p Page) Truncated() bool { return p.truncated }
func (p Page) String() string {
	return fmt.Sprintf("web.Page(%d bytes, truncated %t)", len(p.content), p.truncated)
}
func (p Page) GoString() string { return p.String() }

func TitleOf(title *string) string {
	if title == nil {
		return ""
	}
	t, _ := Clip(strings.TrimSpace(*title), MaxTitleChars)
	return t
}

func dateOf(published *string) string {
	if published == nil || len(*published) != len(dateLayout) {
		return ""
	}
	if _, err := time.Parse(dateLayout, *published); err != nil {
		return ""
	}
	return *published
}

func Clip(s string, max int) (string, bool) {
	if utf8.RuneCountInString(s) <= max {
		return s, false
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i], true
		}
		n++
	}
	return s, false
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type wireResult struct {
	URL       string   `json:"url"`
	Title     string   `json:"title"`
	Published *string  `json:"published"`
	Excerpts  []string `json:"excerpts"`
}

type wireResults struct {
	Object  string       `json:"object"`
	Results []wireResult `json:"results"`
}

type wirePage struct {
	Object    string  `json:"object"`
	URL       string  `json:"url"`
	Title     *string `json:"title"`
	Published *string `json:"published"`
	Content   string  `json:"content"`
	Truncated bool    `json:"truncated"`
}

func WriteResults(w io.Writer, rs Results) error {
	out := wireResults{Object: "search.results", Results: make([]wireResult, 0, len(rs.list))}
	for _, r := range rs.list {
		out.Results = append(out.Results, wireResult{URL: r.url, Title: r.title, Published: nullable(r.published), Excerpts: r.excerpts})
	}
	return encode(w, out)
}

func WritePage(w io.Writer, p Page) error {
	return encode(w, wirePage{
		Object: "fetch.result", URL: p.url, Title: nullable(p.title), Published: nullable(p.published),
		Content: p.content, Truncated: p.truncated,
	})
}

func encode(w io.Writer, v any) error {
	_, err := w.Write(append(jsonx.Encode(v), '\n'))
	return err
}

type Searcher interface {
	Search(ctx context.Context, req *SearchRequest) (Results, error)
}

type Fetcher interface {
	Fetch(ctx context.Context, req *FetchRequest) (Page, error)
}
