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
	Endpoint      catalog.EndpointID
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
	UpstreamRefused
	Stalled
	ContextOverflow
	// Malformed is an ok reply that gave its client a tool call it cannot use. No worker reports it: the relay
	// records an Observation that ended OK with Malformed set under it (Recorded), so provider_health counts the
	// malformed-reply rate that routing gate 3 demotes on.
	Malformed
	outcomeCount
)

var outcomeNames = enum.Names[Outcome]{
	OK: "ok", ClientError: "client_error", UpstreamBusy: "upstream_busy", UpstreamError: "upstream_error",
	UpstreamUnavailable: "upstream_unavailable", Unreachable: "unreachable", MidstreamBreak: "midstream_break",
	Unattested: "unattested", Retention: "retention", Deadline: "deadline", ClientCancel: "client_cancel",
	Throttled: "throttled", Shutdown: "shutdown", ContentFilter: "content_filter", UpstreamRefused: "upstream_refused",
	Stalled: "stalled", ContextOverflow: "context_overflow",
	Malformed: "malformed",
}

func (o Outcome) String() string { return outcomeNames.String(o) }

func (o Outcome) MarshalText() ([]byte, error) { return outcomeNames.MarshalText(o) }

func (o *Outcome) UnmarshalText(text []byte) error { return outcomeNames.UnmarshalText(o, text) }

func Outcomes() []Outcome { return outcomeNames.Values() }

func ParseOutcome(name string) (Outcome, bool) { return outcomeNames.Parse(name) }

const (
	MinDecodeTokens = 200
	MaxDecodeRate   = 2000
)

type Observation struct {
	Path         Path
	Outcome      Outcome
	Duration     time.Duration
	TTFT         time.Duration
	Overhead     time.Duration
	OutputTokens int
	Retries      int
	Hedges       int
	// Malformed marks a reply that ended ok but gave its client a tool call it cannot use: one with no function name,
	// or arguments that are not JSON in a reply that did not stop at its length limit or a content filter to a request
	// that set no stop string, since some hosts cut a call's arguments at the client's stop string.
	// It travels as this flag, not as an outcome, so a relay that names no Malformed outcome still reads the trailer.
	Malformed bool `json:",omitempty"`
	// Window is the context window the host stated when it refused the prompt as too long (ContextOverflow), or 0
	// when it stated none.
	Window int `json:",omitempty"`
}

// Recorded is the outcome the observation counts under: its own, or Malformed for an ok reply with an unusable call.
func (o Observation) Recorded() Outcome {
	if o.Outcome == OK && o.Malformed {
		return Malformed
	}
	return o.Outcome
}

// Healthy is whether the observation closes its endpoint's streak of failures.
func (o Observation) Healthy() bool { return o.Recorded() == OK }

// TripsBreaker is whether the observation counts as a failure of its endpoint.
func (o Observation) TripsBreaker() bool { return o.Recorded().TripsBreaker() }

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

// Key is the series key the meter flushes under. A nil meter, one no recorder made, has none.
func (m *Meter) Key() (Key, bool) {
	if m == nil {
		return Key{}, false
	}
	return m.key, true
}

type series struct {
	requests                 atomic.Uint64
	duration, ttft, overhead Histogram
	decodeRate               rateHistogram
	outputTokens             atomic.Uint64
	generationMicros         atomic.Uint64
	retries, hedges          atomic.Uint64
}

func (m *Meter) Observe(o Observation) {
	if m == nil {
		return
	}
	slot := &m.series[o.Path][o.Recorded()]
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
	if decode := o.Duration - o.TTFT; o.OutputTokens >= MinDecodeTokens && o.TTFT > 0 && !Burst(o.OutputTokens, decode) {
		s.outputTokens.Add(uint64(o.OutputTokens))
		s.generationMicros.Add(uint64(decode.Microseconds()))
		s.decodeRate.record(DecodeRate(o.OutputTokens, decode))
	}
	if o.Retries > 0 {
		s.retries.Add(uint64(o.Retries))
	}
	if o.Hedges > 0 {
		s.hedges.Add(uint64(o.Hedges))
	}
}

// DecodeRate is a reply's decode speed in whole tokens a second, rounded down, so a rate reaches a floor only when it
// truly does.
func DecodeRate(tokens int, decode time.Duration) int {
	return int(int64(tokens) * int64(time.Second) / int64(decode))
}

func Burst(tokens int, decode time.Duration) bool {
	return tokens > int(decode/(time.Second/MaxDecodeRate))
}

type Row struct {
	Key
	Path                     Path
	Outcome                  Outcome
	Requests                 uint64
	Duration, TTFT, Overhead Counts
	// DecodeRate counts the replies that decoded at each whole rate, so a median rate can be read back.
	DecodeRate       Rates
	OutputTokens     uint64
	GenerationMicros uint64
	Retries, Hedges  uint64
}

func (r Row) empty() bool {
	return r.Requests == 0 && len(r.Duration) == 0 && len(r.TTFT) == 0 && len(r.Overhead) == 0 && len(r.DecodeRate) == 0 &&
		r.OutputTokens == 0 && r.GenerationMicros == 0 && r.Retries == 0 && r.Hedges == 0
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
					Duration: s.duration.Drain(), TTFT: s.ttft.Drain(), Overhead: s.overhead.Drain(), DecodeRate: s.decodeRate.drain(),
					OutputTokens: s.outputTokens.Swap(0), GenerationMicros: s.generationMicros.Swap(0), Retries: s.retries.Swap(0), Hedges: s.hedges.Swap(0),
				}
				if !row.empty() {
					batch = append(batch, row)
				}
			}
		}
	}
	return batch
}
