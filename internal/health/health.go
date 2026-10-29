package health

import (
	"sync"
	"sync/atomic"
	"time"

	"morse/backend/internal/catalog"
	"morse/backend/internal/enum"
)

type Key struct {
	Host          string
	UpstreamModel string
	Model         string
	Kind          catalog.Kind
}

type Path uint8

const (
	PathStream Path = iota
	PathBuffered
	PathVerbatimStream
	PathVerbatimBuffered
	PathCall
	PathSubmit
	PathJob
	PathCompact
	pathCount
)

var pathNames = enum.Names[Path]{
	PathStream: "stream", PathBuffered: "buffered", PathVerbatimStream: "verbatim_stream", PathVerbatimBuffered: "verbatim_buffered",
	PathCall: "call", PathSubmit: "submit", PathJob: "job", PathCompact: "compact",
}

func (p Path) String() string { return pathNames.String(p) }

func (p Path) MarshalText() ([]byte, error) { return pathNames.MarshalText(p) }

func (p *Path) UnmarshalText(text []byte) error { return pathNames.UnmarshalText(p, text) }

func Paths() []Path { return pathNames.Values() }

type Outcome uint8

const (
	OK Outcome = iota
	ClientError
	UpstreamBusy
	UpstreamError
	UpstreamUnavailable
	Unreachable
	MidstreamBreak
	Unattested
	Retention
	Deadline
	ClientCancel
	Throttled
	Shutdown
	ContentFilter
	outcomeCount
)

var outcomeNames = enum.Names[Outcome]{
	OK: "ok", ClientError: "client_error", UpstreamBusy: "upstream_busy", UpstreamError: "upstream_error",
	UpstreamUnavailable: "upstream_unavailable", Unreachable: "unreachable", MidstreamBreak: "midstream_break",
	Unattested: "unattested", Retention: "retention", Deadline: "deadline", ClientCancel: "client_cancel",
	Throttled: "throttled", Shutdown: "shutdown", ContentFilter: "content_filter",
}

func (o Outcome) String() string { return outcomeNames.String(o) }

func (o Outcome) MarshalText() ([]byte, error) { return outcomeNames.MarshalText(o) }

func (o *Outcome) UnmarshalText(text []byte) error { return outcomeNames.UnmarshalText(o, text) }

func Outcomes() []Outcome { return outcomeNames.Values() }

type Observation struct {
	Path         Path
	Outcome      Outcome
	Duration     time.Duration
	TTFT         time.Duration
	Overhead     time.Duration
	OutputTokens int
	Retries      int
}

type Recorder struct {
	mu     sync.Mutex
	meters map[Key]*Meter
}

func NewRecorder() *Recorder { return &Recorder{meters: map[Key]*Meter{}} }

func (r *Recorder) Meter(k Key) *Meter {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.meters[k]
	if !ok {
		m = &Meter{key: k}
		r.meters[k] = m
	}
	return m
}

type Meter struct {
	key    Key
	series [pathCount][outcomeCount]atomic.Pointer[series]
}

type series struct {
	requests                 atomic.Uint64
	duration, ttft, overhead Histogram
	outputTokens             atomic.Uint64
	generationMicros         atomic.Uint64
	retries                  atomic.Uint64
}

func (m *Meter) Observe(o Observation) {
	if m == nil {
		return
	}
	slot := &m.series[o.Path][o.Outcome]
	s := slot.Load()
	if s == nil {
		slot.CompareAndSwap(nil, new(series))
		s = slot.Load()
	}
	s.requests.Add(1)
	for _, measured := range []struct {
		hist *Histogram
		took time.Duration
	}{{&s.duration, o.Duration}, {&s.ttft, o.TTFT}, {&s.overhead, o.Overhead}} {
		if measured.took > 0 {
			measured.hist.Record(measured.took)
		}
	}
	if o.OutputTokens > 0 {
		s.outputTokens.Add(uint64(o.OutputTokens))
		s.generationMicros.Add(uint64(o.Duration.Microseconds()))
	}
	if o.Retries > 0 {
		s.retries.Add(uint64(o.Retries))
	}
}

type Row struct {
	Key
	Path                     Path
	Outcome                  Outcome
	Requests                 uint64
	Duration, TTFT, Overhead Counts
	OutputTokens             uint64
	GenerationMicros         uint64
	Retries                  uint64
}

func (r Row) empty() bool {
	return r.Requests == 0 && len(r.Duration) == 0 && len(r.TTFT) == 0 && len(r.Overhead) == 0 &&
		r.OutputTokens == 0 && r.GenerationMicros == 0 && r.Retries == 0
}

type Batch []Row

func (r *Recorder) Drain() Batch {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var batch Batch
	for _, m := range r.meters {
		for _, p := range Paths() {
			for _, o := range Outcomes() {
				s := m.series[p][o].Load()
				if s == nil {
					continue
				}
				row := Row{
					Key: m.key, Path: p, Outcome: o, Requests: s.requests.Swap(0),
					Duration: s.duration.Drain(), TTFT: s.ttft.Drain(), Overhead: s.overhead.Drain(),
					OutputTokens: s.outputTokens.Swap(0), GenerationMicros: s.generationMicros.Swap(0), Retries: s.retries.Swap(0),
				}
				if !row.empty() {
					batch = append(batch, row)
				}
			}
		}
	}
	return batch
}
