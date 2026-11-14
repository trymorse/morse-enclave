package worker

import (
	"context"
	"net/http"
	"net/url"

	"morse/backend/internal/dialect"
	"morse/backend/internal/dialect/messages"
	"morse/backend/internal/dialect/responses"
	"morse/backend/internal/plugins"
	"morse/backend/internal/worker/taskrun"
)

const (
	ChatPattern           = "POST /v1/chat/completions"
	CompactPattern        = "POST /v1/chat/compact"
	MessagesPattern       = "POST /v1/messages"
	ResponsesPattern      = "POST /v1/responses"
	ImagesPattern         = "POST /v1/images/generations"
	VideosPattern         = "POST /v1/videos"
	VideoContentPattern   = "GET /v1/videos/{id}/content"
	SearchPattern         = "POST /v1/search"
	FetchPattern          = "POST /v1/fetch"
	ResearchPattern       = "POST /v1/research"
	ResearchReadPattern   = "GET /v1/research/{id}"
	ResearchEventsPattern = "GET /v1/research/{id}/events"
	LookupPattern         = "GET /v1/lookup/{service}/{path...}"
	TranscriptionPattern  = "POST /v1/audio/transcriptions"
)

// Dialects are the chat routes whose clients speak a wire format other than Chat Completions, by route pattern. The
// relay and the door write their refusals on such a route in its dialect's envelope.
var Dialects = map[string]dialect.Dialect{MessagesPattern: messages.Dialect, ResponsesPattern: responses.Dialect}

func pluginOpener(kind plugins.Kind) opener {
	return func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openPlugin(o, kind) }
}

func chatOpener(d dialect.Dialect, compaction bool) opener {
	return func(w *InProcess, o Opening, _ func(string) string) (Admission, error) {
		return w.openChat(o, d, compaction)
	}
}

type opener func(w *InProcess, o Opening, pathValue func(string) string) (Admission, error)

var sealableRoutes = []struct {
	pattern string
	open    opener
}{
	{ChatPattern, chatOpener(dialect.Dialect{}, false)},
	{CompactPattern, chatOpener(dialect.Dialect{}, true)},
	{MessagesPattern, chatOpener(messages.Dialect, false)},
	{ResponsesPattern, chatOpener(responses.Dialect, false)},
	{ImagesPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openImages(o) }},
	{VideosPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openVideo(o) }},
	{VideoContentPattern, (*InProcess).openRead},
	{SearchPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openSearch(o) }},
	{FetchPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openFetch(o) }},
	{ResearchPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openResearch(o) }},
	{ResearchReadPattern, (*InProcess).openRead},
	{ResearchEventsPattern, (*InProcess).openRead},
	{LookupPattern, (*InProcess).openLookup},
	{TranscriptionPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) { return w.openTranscription(o) }},
	{PluginCallPattern, pluginOpener(plugins.KindCall)},
	{PluginTokenPattern, pluginOpener(plugins.KindToken)},
	{PluginRevokePattern, pluginOpener(plugins.KindRevoke)},
	{TasksPattern, func(w *InProcess, o Opening, _ func(string) string) (Admission, error) {
		return w.openTask(o, taskrun.BundleRoute{})
	}},
	{TaskBundlePattern, func(w *InProcess, o Opening, pathValue func(string) string) (Admission, error) {
		return w.openTask(o, taskrun.BundleRoute{Replaces: true, PathID: pathValue("id")})
	}},
}

var SealablePatterns = func() []string {
	patterns := make([]string, 0, len(sealableRoutes))
	for _, rt := range sealableRoutes {
		patterns = append(patterns, rt.pattern)
	}
	return patterns
}()

var mux = func() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range sealableRoutes {
		mux.HandleFunc(rt.pattern, func(rw http.ResponseWriter, r *http.Request) {
			call := rw.(*openCall)
			call.admitted, call.err = rt.open(call.worker, call.opening, r.PathValue)
		})
	}
	return mux
}()

type openCall struct {
	worker   *InProcess
	opening  Opening
	admitted Admission
	err      error
}

func (c *openCall) Header() http.Header { return http.Header{} }

func (c *openCall) Write([]byte) (int, error) { return 0, nil }

func (c *openCall) WriteHeader(int) { c.err = errNoSuchRoute }

func (w *InProcess) Open(ctx context.Context, o Opening) (Admission, error) {
	route := o.Method + " " + o.Path
	if o.Writing != nil && route != ChatPattern {
		return nil, errExamplesNotChat
	}
	if route != ChatPattern && route != CompactPattern && route != MessagesPattern && route != ResponsesPattern {
		if err := veilNotHere(o); err != nil {
			return nil, err
		}
	}
	call := &openCall{worker: w, opening: o}
	r := &http.Request{Method: o.Method, URL: &url.URL{Path: o.Path, RawQuery: o.Query}}
	mux.ServeHTTP(call, r.WithContext(ctx))
	return call.admitted, call.err
}
