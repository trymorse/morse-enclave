package worker

import (
	"cmp"
	"context"
	"fmt"
	"sync"
	"time"

	"morse/backend/internal/chat"
	"morse/backend/internal/jobs"
	"morse/backend/internal/lookup"
	"morse/backend/internal/media"
	"morse/backend/internal/research"
	"morse/backend/internal/web"
)

type InProcess struct {
	chats          map[string][]chatRoute
	images         map[string]media.ImageGenerator
	videos         map[string]media.VideoGenerator
	searches       map[string]web.Searcher
	fetches        map[string]web.Fetcher
	researchers    map[string]research.Researcher
	transcribers   map[string]transcriber
	lookup         *lookup.Relay
	reports        Reporter
	now            func() time.Time
	keepaliveEvery time.Duration
	videoSubmit    time.Duration
	counters       counters
	sealing        sealedState
	mu             sync.Mutex
	last           uint64
	opened         map[Handle]*entry
}

// Reporter hears what the worker notices but does not answer. Nil is NopReporter, which a reporter that hears only
// some of it embeds.
type Reporter interface {
	UnknownReplyField(model, field string)
	Failed(route string, err error)
	LookupBusy(service string)
	VendorRefused(model string, status int)
	UpstreamErrorChunk(model string, code chat.ErrorCode)
}

type NopReporter struct{}

func (NopReporter) UnknownReplyField(string, string)          {}
func (NopReporter) Failed(string, error)                      {}
func (NopReporter) LookupBusy(string)                         {}
func (NopReporter) VendorRefused(string, int)                 {}
func (NopReporter) UpstreamErrorChunk(string, chat.ErrorCode) {}

type Config struct {
	Models        map[string]Model
	Lookup        *lookup.Relay
	Reports       Reporter
	Now           func() time.Time
	CountingSlots int
	Sealing       Sealing
	Keepalive     time.Duration
	VideoSubmit   time.Duration
}

func NewInProcess(cfg Config) (*InProcess, error) {
	for name, m := range cfg.Models {
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("worker: model %s %w", name, err)
		}
	}
	w := &InProcess{
		chats: map[string][]chatRoute{}, images: map[string]media.ImageGenerator{}, videos: map[string]media.VideoGenerator{},
		searches: map[string]web.Searcher{}, fetches: map[string]web.Fetcher{}, researchers: map[string]research.Researcher{}, transcribers: map[string]transcriber{},
		lookup: cfg.Lookup, reports: cfg.Reports,
		now: cfg.Now, keepaliveEvery: cmp.Or(cfg.Keepalive, keepalive), videoSubmit: cmp.Or(cfg.VideoSubmit, videoSubmitTimeout), opened: map[Handle]*entry{},
	}
	if w.now == nil {
		w.now = time.Now
	}
	w.sealing.Sealing, w.sealing.started = cfg.Sealing, w.now()
	if w.reports == nil {
		w.reports = NopReporter{}
	}
	for name, m := range cfg.Models {
		for _, vendor := range append([]Model{m}, m.Fallbacks...) {
			switch s := vendor.Serves.(type) {
			case Chat:
				w.chats[name] = append(w.chats[name], s.route(vendor.Attester, vendor.Tier))
			case Images:
				w.images[name] = s.ImageGenerator
			case Videos:
				w.videos[name] = s.VideoGenerator
			case Search:
				w.searches[name] = s.Searcher
			case Fetch:
				w.fetches[name] = s.Fetcher
			case Research:
				w.researchers[name] = s.Researcher
			case Transcription:
				w.transcribers[name] = transcriber{Transcription: s, attester: vendor.Attester}
			}
		}
	}
	w.counters.init(cfg.CountingSlots)
	return w, nil
}

const videoSubmitTimeout = 2 * time.Minute

func (w *InProcess) Poll(ctx context.Context, route, vendorID string) (jobs.Poll, error) {
	if videos, known := w.videos[route]; known {
		return videos.PollVideo(ctx, vendorID)
	}
	if vendor, known := w.researchers[route]; known {
		return vendor.Check(ctx, vendorID)
	}
	return jobs.Poll{}, errNoSuchRoute
}
