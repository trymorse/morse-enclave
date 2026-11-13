package worker

import (
	"cmp"
	"context"
	"fmt"
	"sync"
	"time"

	"morse/backend/internal/attested"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/jobs"
	"morse/backend/internal/lookup"
	"morse/backend/internal/media"
	"morse/backend/internal/plugins"
	"morse/backend/internal/research"
	"morse/backend/internal/web"
	"morse/backend/internal/worker/taskrun"
)

type InProcess struct {
	chats          map[string]chatName
	images         map[string]media.ImageGenerator
	videos         map[string]media.VideoGenerator
	searches       map[string]web.Searcher
	fetches        map[string]web.Fetcher
	researchers    map[string]research.Researcher
	transcribers   map[string]transcriber
	endpoints      map[string]catalog.EndpointID
	lookup         *lookup.Relay
	plugins        *plugins.Relay
	reports        Reporter
	unpinned       func() []attested.UnpinnedRelease
	now            func() time.Time
	keepaliveEvery time.Duration
	videoSubmit    time.Duration
	proofBudget    time.Duration
	counters       counters
	sealing        sealedState
	privacyVeil    *PrivacyVeil
	mu             sync.Mutex
	last           uint64
	opened         map[Handle]*entry
	tiers          map[string]catalog.Tier
	runs           map[Handle]*taskRun
	taskLife       time.Duration
}

type Reporter interface {
	UnknownReplyField(model, field string)
	Failed(route string, err error)
	LookupBusy(service string)
	VendorRefused(model string, status int)
	UpstreamErrorChunk(model string, code chat.ErrorCode)
	VendorUsageMissing(model string)
}

type NopReporter struct{}

func (NopReporter) UnknownReplyField(string, string)          {}
func (NopReporter) Failed(string, error)                      {}
func (NopReporter) LookupBusy(string)                         {}
func (NopReporter) VendorRefused(string, int)                 {}
func (NopReporter) UpstreamErrorChunk(string, chat.ErrorCode) {}
func (NopReporter) VendorUsageMissing(string)                 {}

type Config struct {
	Models        map[string]Model
	Lookup        *lookup.Relay
	Plugins       *plugins.Relay
	Reports       Reporter
	Now           func() time.Time
	CountingSlots int
	Sealing       Sealing
	Keepalive     time.Duration
	VideoSubmit   time.Duration
	ProofBudget   time.Duration
	Unpinned      func() []attested.UnpinnedRelease
	PrivacyVeil   *PrivacyVeil
}

func NewInProcess(cfg Config) (*InProcess, error) {
	for name, m := range cfg.Models {
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("worker: model %s %w", name, err)
		}
	}
	w := &InProcess{
		chats: indexChats(cfg.Models), images: map[string]media.ImageGenerator{}, videos: map[string]media.VideoGenerator{},
		searches: map[string]web.Searcher{}, fetches: map[string]web.Fetcher{}, researchers: map[string]research.Researcher{}, transcribers: map[string]transcriber{},
		endpoints: map[string]catalog.EndpointID{},
		lookup:    cfg.Lookup, plugins: cfg.Plugins, reports: cfg.Reports, unpinned: cfg.Unpinned, privacyVeil: cfg.PrivacyVeil,
		now: cfg.Now, keepaliveEvery: cmp.Or(cfg.Keepalive, keepalive), videoSubmit: cmp.Or(cfg.VideoSubmit, videoSubmitTimeout), proofBudget: cmp.Or(cfg.ProofBudget, proofBudget), opened: map[Handle]*entry{},
		tiers: map[string]catalog.Tier{}, runs: map[Handle]*taskRun{}, taskLife: taskrun.RunLife,
	}
	if w.now == nil {
		w.now = time.Now
	}
	w.sealing.Sealing, w.sealing.started = cfg.Sealing, w.now()
	if w.reports == nil {
		w.reports = NopReporter{}
	}
	named := make([]catalog.Named, 0, len(cfg.Models))
	for name, m := range cfg.Models {
		w.tiers[name] = m.Tier
		w.indexNonChat(name, m)
		named = append(named, catalog.Named{Name: name, Model: m.ID, Tier: m.Tier, Order: m.Order})
	}
	for id, name := range catalog.IDNames(named) {
		w.indexNonChat(id, cfg.Models[name])
	}
	w.counters.init(cfg.CountingSlots)
	return w, nil
}

func (w *InProcess) indexNonChat(name string, m Model) {
	for _, vendor := range append([]Model{m}, m.at(catalog.PlaceFallback)...) {
		if _, chats := vendor.Serves.(Chat); chats {
			continue
		}
		w.endpoints[name] = vendor.Endpoint
		switch s := vendor.Serves.(type) {
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

const videoSubmitTimeout = 2 * time.Minute

const proofBudget = 6 * time.Second

func (w *InProcess) Unpinned(context.Context) ([]attested.UnpinnedRelease, error) {
	if w.unpinned == nil {
		return nil, nil
	}
	return w.unpinned(), nil
}

func (w *InProcess) Poll(ctx context.Context, route, vendorID string) (jobs.Poll, error) {
	if videos, known := w.videos[route]; known {
		return videos.PollVideo(ctx, vendorID)
	}
	if vendor, known := w.researchers[route]; known {
		return vendor.Check(ctx, vendorID)
	}
	return jobs.Poll{}, errNoSuchRoute
}
