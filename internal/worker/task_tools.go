package worker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"morse/backend/internal/jsonx"
	"morse/backend/internal/web"
)

// A run's web tools, as the app's own agent has them (src/lib/tools/web.ts): web_search through the mode's search
// route and read_page through its extract route, the same output caps, and read_page opening only pages the task's
// prompt or an earlier result showed, so text injected into a page can't send the run to a URL of its making.

const (
	webSearchName = "web_search"
	readPageName  = "read_page"

	maxSearchQuery = 200
	maxObjective   = 500
	maxHits        = 10
	maxHitTitle    = 200
	maxHitExcerpt  = 1_500
	maxListing     = 6_000
	maxPageURL     = 2_048
	maxPageText    = 12_000
	maxSourceTitle = 200
	// maxCallsPerPass bounds the calls one pass replays; the run's tool limits stop them running long before.
	maxCallsPerPass = MaxTaskSearches + MaxTaskReads
)

// taskToolRoutes are the routes a mode's web tools go through, chosen by the worker, never by the relay: Anonymous
// tasks use Parallel's own routes, Private ones the routes Morse's zero data retention agreement covers.
var taskToolRoutes = map[TaskMode]struct{ search, fetch string }{
	TaskAnon:    {"parallel-search", "parallel-extract"},
	TaskPrivate: {"parallel-search-zdr", "parallel-extract-zdr"},
}

type toolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type toolSpec struct {
	Type     string       `json:"type"`
	Function toolFunction `json:"function"`
}

const (
	webSearchParameters = `{"type":"object","properties":{"queries":{"minItems":1,"maxItems":3,"type":"array","items":{"type":"string","minLength":1,"maxLength":200},"description":"1 to 3 keyword search queries, each 3 to 6 words"},"objective":{"description":"Optional: what you are trying to find out, in one plain sentence","type":"string","maxLength":500}},"required":["queries"],"additionalProperties":false}`
	readPageParameters  = `{"type":"object","properties":{"url":{"type":"string","minLength":1,"description":"The page's full http(s) URL, exactly as the user or a tool result gave it"}},"required":["url"],"additionalProperties":false}`
)

func webSearchSpec(reads bool) json.RawMessage {
	description := "Search the web. Write 1 to 3 short keyword queries (3 to 6 words each, like a person would type) that approach the question from different angles, and optionally an objective: one sentence saying what you need to find out. Returns up to 10 results with titles, URLs, publication dates when known, and excerpts."
	if reads {
		description += " To read a result in full, pass its URL to " + readPageName + "."
	}
	return jsonx.Encode(toolSpec{Type: "function", Function: toolFunction{Name: webSearchName, Description: description, Parameters: json.RawMessage(webSearchParameters)}})
}

func readPageSpec() json.RawMessage {
	description := "Read a web page as text, given its URL. Only opens URLs that appear in the task's prompt or in search results, such as " + webSearchName + "'s; it refuses any other URL, a link found on a page included, so search first. Use it after " + webSearchName + " when an excerpt isn't enough. Long pages are cut to about 12,000 characters. Some pages can't be read; then try another result."
	return jsonx.Encode(toolSpec{Type: "function", Function: toolFunction{Name: readPageName, Description: description, Parameters: json.RawMessage(readPageParameters)}})
}

// toolError is a call's result when it failed, as the app words one, so the model reads what went wrong and can
// correct it.
func toolError(message string) string { return "Error: " + message }

type searchArgs struct {
	Queries   []string `json:"queries"`
	Objective *string  `json:"objective,omitempty"`
}

// readSearchArgs reads web_search's arguments as the app's tool takes them, or says what is wrong with them.
func readSearchArgs(args string) (searchArgs, string) {
	fields, problem := argsObject(args)
	if problem != "" {
		return searchArgs{}, problem
	}
	var a searchArgs
	queries, ok := fields["queries"]
	if !ok || json.Unmarshal(queries, &a.Queries) != nil || len(a.Queries) < 1 || len(a.Queries) > web.MaxQueries {
		return searchArgs{}, toolError(fmt.Sprintf("invalid arguments: queries must be a list of 1 to %d keyword search queries", web.MaxQueries))
	}
	for i, q := range a.Queries {
		a.Queries[i] = strings.TrimSpace(q)
		if n := runes(a.Queries[i]); n < 1 || n > maxSearchQuery {
			return searchArgs{}, toolError(fmt.Sprintf("invalid arguments: each query must be 1 to %d characters", maxSearchQuery))
		}
	}
	if raw, ok := fields["objective"]; ok {
		var objective string
		if json.Unmarshal(raw, &objective) != nil || runes(strings.TrimSpace(objective)) > maxObjective {
			return searchArgs{}, toolError(fmt.Sprintf("invalid arguments: objective must be a string of at most %d characters", maxObjective))
		}
		if objective = strings.TrimSpace(objective); objective != "" {
			a.Objective = &objective
		}
	}
	return a, ""
}

// readPageArgs reads read_page's URL argument, or says what is wrong with it.
func readPageArgs(args string) (string, string) {
	fields, problem := argsObject(args)
	if problem != "" {
		return "", problem
	}
	var raw string
	if value, ok := fields["url"]; !ok || json.Unmarshal(value, &raw) != nil || raw == "" {
		return "", toolError("invalid arguments: url must be the page's full http(s) URL")
	}
	return raw, ""
}

func argsObject(args string) (map[string]json.RawMessage, string) {
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(args), &fields) != nil || fields == nil {
		return nil, toolError("the arguments aren't valid JSON; send one JSON object")
	}
	return fields, ""
}

// openable is raw as a page a tool may open, http(s) with no username or password in it, or why it isn't one.
func openable(raw string) (*url.URL, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil || u.Scheme == "":
		return nil, toolError("That isn't a full URL. Pass the page's whole http(s) URL, exactly as the prompt or a tool result gave it.")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, toolError(readPageName + " opens only http and https pages")
	case u.Host == "":
		return nil, toolError("That isn't a full URL. Pass the page's whole http(s) URL, exactly as the prompt or a tool result gave it.")
	case u.User != nil:
		return nil, toolError(readPageName + " won't open a URL that carries a username or password")
	}
	return u, ""
}

// pageKey is one page's spelling for comparison: the fragment never reaches the server, scheme and host compare in
// lower case without their default port, and a path is the same page with or without its trailing slash.
func pageKey(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		return "", false
	}
	if port := u.Port(); port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":"+port)
	}
	u.Fragment, u.RawFragment = "", ""
	if len(u.Path) > 1 {
		u.Path = strings.TrimSuffix(u.Path, "/")
		u.RawPath = strings.TrimSuffix(u.RawPath, "/")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

var (
	urlInText     = regexp.MustCompile("https?://[^\\s\\p{Z}\\p{Cc}<>\"'`]+")
	proseTrailing = regexp.MustCompile(`[.,;:!?\]}*_]+$`)
)

// urlsIn are the pages absolute URLs in text name, by key, without the punctuation of the prose around them. A closing
// parenthesis stays when it closes one in the URL, as in GFM autolinks.
func urlsIn(text string) []string {
	var keys []string
	for _, raw := range urlInText.FindAllString(text, -1) {
		u := proseTrailing.ReplaceAllString(raw, "")
		for strings.HasSuffix(u, ")") && strings.Count(u, ")") > strings.Count(u, "(") {
			u = proseTrailing.ReplaceAllString(strings.TrimSuffix(u, ")"), "")
		}
		if key, ok := pageKey(u); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// wasShown reports whether the prompt or a result showed the page u names. Only these exact pages pass: a variant
// that differs in its query or path could carry the run to whoever runs the server. URLs are read out of prose, where
// a closing parenthesis usually ends a sentence, so a key may lack parentheses the shown URL left open.
func wasShown(u *url.URL, seen map[string]bool) bool {
	key, ok := pageKey(u.String())
	if !ok {
		return false
	}
	if seen[key] {
		return true
	}
	closers := len(key) - len(strings.TrimRight(key, ")"))
	open := key[:len(key)-closers]
	return closers > 0 && strings.Count(open, "(")-strings.Count(open, ")") >= closers && seen[open]
}

var (
	lineBreaks = regexp.MustCompile(`[\p{Cc}\p{Z}\s\x{FEFF}]+`)
	isDay      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// oneLine is text on one line, without control characters.
func oneLine(text string) string { return strings.TrimSpace(lineBreaks.ReplaceAllString(text, " ")) }

// cutText is text cut to max runes, saying so with an ellipsis, as the app's cut does.
func cutText(text string, max int) string {
	if runes(text) <= max {
		return text
	}
	if max < 2 {
		return ""
	}
	return strings.TrimRightFunc(cutRunes(text, max-1), func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' }) + "…"
}

// clip cuts text to max runes, saying so, so the model knows there was more.
func clip(text string, max int) string {
	n := runes(text)
	if n <= max {
		return text
	}
	return cutRunes(text, max) + "\n[Cut at " + thousands(max) + " of " + thousands(n) + " characters.]"
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// hitKey is how one search result compares with another: a page can be listed under http and https, with or
// without www. and a trailing slash.
func hitKey(u *url.URL) string {
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.") + strings.TrimSuffix(u.EscapedPath(), "/") + queryOf(u)
}

func queryOf(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

type searchHit struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Published string `json:"published,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

type searchReply struct {
	Results []struct {
		URL       string   `json:"url"`
		Title     *string  `json:"title"`
		Published *string  `json:"published"`
		Excerpts  []string `json:"excerpts"`
	} `json:"results"`
}

type pageReply struct {
	URL       string  `json:"url"`
	Title     *string `json:"title"`
	Published *string `json:"published"`
	Content   string  `json:"content"`
	Truncated bool    `json:"truncated"`
}

// searchOutput is what the model reads of a search's reply, and the results it lists, which become the run's
// sources and pages read_page may open.
func searchOutput(body []byte) (string, []TaskSource) {
	var reply searchReply
	if json.Unmarshal(body, &reply) != nil {
		return toolError("the search provider sent a reply Morse couldn't read. Try again, or rephrase the queries."), nil
	}
	var hits []searchHit
	keys := map[string]bool{}
	for _, r := range reply.Results {
		u, problem := openable(r.URL)
		if problem != "" || len(u.String()) > maxPageURL || keys[hitKey(u)] {
			continue
		}
		keys[hitKey(u)] = true
		hit := searchHit{Title: cutText(oneLine(deref(r.Title)), maxHitTitle), URL: u.String(), Excerpt: oneLine(strings.Join(r.Excerpts, " … "))}
		if hit.Title == "" {
			hit.Title = u.Hostname()
		}
		if p := deref(r.Published); isDay.MatchString(p) {
			hit.Published = p
		}
		if hits = append(hits, hit); len(hits) == maxHits {
			break
		}
	}
	if len(hits) == 0 {
		return "No results for those queries. Try other or fewer keywords.", nil
	}
	listed := listing(hits)
	sources := make([]TaskSource, len(listed))
	for i, hit := range listed {
		sources[i] = TaskSource{URL: hit.URL, Title: hit.Title}
	}
	return string(jsonx.Encode(listed)), sources
}

// listing is hits as the model reads them, within maxListing: the excerpts share the room the titles and URLs
// leave, and the last results go if escaping still overflows it.
func listing(hits []searchHit) []searchHit {
	bare := make([]searchHit, len(hits))
	for i, hit := range hits {
		bare[i] = hit
		bare[i].Excerpt = ""
	}
	room := maxListing - len(jsonx.Encode(bare)) - len(hits)*len(`,"excerpt":""`)
	each := min(maxHitExcerpt, room/len(hits))
	listed := make([]searchHit, len(hits))
	for i, hit := range hits {
		listed[i] = hit
		listed[i].Excerpt = cutText(hit.Excerpt, each)
	}
	for len(listed) > 1 && len(jsonx.Encode(listed)) > maxListing {
		listed = listed[:len(listed)-1]
	}
	return listed
}

// pageOutput is what the model reads of a page read_page opened at u, and the page as a source, or why it has
// nothing to read.
func pageOutput(u *url.URL, body []byte) (string, *TaskSource) {
	var page pageReply
	host := u.Hostname()
	if json.Unmarshal(body, &page) != nil {
		return toolError("Couldn't read " + host + ": the reader sent a reply Morse couldn't read. Try another result."), nil
	}
	text := strings.TrimSpace(page.Content)
	if text == "" {
		return toolError("Couldn't read " + host + ": the reader found no text on it"), nil
	}
	title := cutText(oneLine(deref(page.Title)), maxHitTitle)
	if title == "" {
		title = host
	}
	lines := []string{"Title: " + title, "URL: " + u.String()}
	if p := deref(page.Published); isDay.MatchString(p) {
		lines = append(lines, "Published: "+p)
	}
	lines = append(lines, "", clip(text, maxPageText))
	if page.Truncated {
		lines = append(lines, "[The reader cut the page short.]")
	}
	return strings.Join(lines, "\n"), &TaskSource{URL: u.String(), Title: title}
}

// callFailed is a tool step's result when its call failed, worded by the refusal a client would have seen.
func callFailed(name string, u *url.URL, code string) string {
	if name == webSearchName {
		switch code {
		case "upstream_busy":
			return toolError("The search provider is busy right now. Try the search again in a moment.")
		case "upstream_unavailable":
			return toolError("Web search is unavailable right now. Don't call " + webSearchName + " again in this run; answer without it.")
		}
		return toolError("The search failed. Try again, or rephrase the queries.")
	}
	host := u.Hostname()
	switch code {
	case "fetch_failed":
		return toolError("Couldn't read " + host + ": the reader couldn't fetch the page. Try another result.")
	case "invalid_url", "invalid_parameter":
		return toolError("Couldn't read " + host + ": Morse won't send that URL to the reader")
	case "upstream_busy":
		return toolError("The reader is busy right now. Try reading the page again in a moment.")
	case "upstream_unavailable":
		return toolError("Couldn't read " + host + ": the reader is unavailable right now.")
	}
	return toolError("Couldn't read " + host + ". Try again, or try another result.")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// zwsp breaks a mark, written after a tag's "<" or "</", or after a heading's first word.
const zwsp = "\u200b"

var (
	// Every tool-call dialect's tags, as the app's src/lib/tool-protocol/dialects.ts lists them, and the run's own
	// last_result block.
	dialectTags  = regexp.MustCompile(`(?i)<(/?)(tool_call\||tool_response\||tool_call|tool_response|tool_result|arg_key|arg_value|function|parameter|unbound_|last_result|\|tool|tool\||\|"\||\|turn|turn\||\|channel|channel\|)`)
	dialectToken = regexp.MustCompile(`<(/?)([|｜])([\w▁]+[|｜])`)
	dialectHeads = regexp.MustCompile(`(?m)^(##|Result)( Return of| of call)`)
)

// defang breaks the marks of every tool-call dialect in text a model reads as data: a page can't close the result it
// is in, pose as the model, or open a call in a template that writes results as text.
func defang(text string) string {
	text = dialectTags.ReplaceAllString(text, "<${1}"+zwsp+"${2}")
	text = dialectToken.ReplaceAllString(text, "<${1}"+zwsp+"${2}${3}")
	return dialectHeads.ReplaceAllStringFunc(text, func(head string) string {
		word, rest, _ := strings.Cut(head, " ")
		if word == "##" && rest != "Return of" || word == "Result" && rest != "of call" {
			return head
		}
		return word + zwsp + " " + rest
	})
}

// taskSources are the pages a run used: those its read_page calls opened, then its search results, each page once.
type taskSources struct{ read, found []TaskSource }

func (s taskSources) list() []TaskSource {
	var out []TaskSource
	seen := map[string]bool{}
	for _, source := range append(append([]TaskSource{}, s.read...), s.found...) {
		key, ok := pageKey(source.URL)
		if !ok || seen[key] || len(source.URL) > maxPageURL || !utf8.ValidString(source.Title) {
			continue
		}
		seen[key] = true
		out = append(out, TaskSource{URL: source.URL, Title: cutRunes(source.Title, maxSourceTitle)})
		if len(out) == MaxTaskSources {
			break
		}
	}
	return out
}
