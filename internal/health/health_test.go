package health

import (
	"slices"
	"sync"
	"testing"
	"time"

	"morse/backend/internal/catalog"
)

var route = Key{Host: "api.vendor.example", UpstreamModel: "vendor/model", Model: "m", Kind: catalog.KindChat}

func rowFor(t *testing.T, batch Batch, p Path, o Outcome) Row {
	t.Helper()
	i := slices.IndexFunc(batch, func(r Row) bool { return r.Path == p && r.Outcome == o })
	if i < 0 {
		t.Fatalf("no %s/%s row in %+v", p, o, batch)
	}
	return batch[i]
}

func TestEveryPathAndOutcomeHasAName(t *testing.T) {
	if len(Paths()) != int(pathCount) || len(Outcomes()) != int(outcomeCount) {
		t.Fatalf("%d paths and %d outcomes listed, want %d and %d", len(Paths()), len(Outcomes()), pathCount, outcomeCount)
	}
	seen := map[string]bool{}
	for _, p := range Paths() {
		if !pathNames.Valid(p) || seen[p.String()] {
			t.Errorf("path %d is named %q, which is missing or repeated", p, p)
		}
		seen[p.String()] = true
	}
	seen = map[string]bool{}
	for _, o := range Outcomes() {
		if !outcomeNames.Valid(o) || seen[o.String()] {
			t.Errorf("outcome %d is named %q, which is missing or repeated", o, o)
		}
		seen[o.String()] = true
	}
}

func TestADrainReturnsWhatWasObservedSinceTheLastOneUnderTheRoutesKey(t *testing.T) {
	r := NewRecorder()
	m := r.Meter(route)
	if again := r.Meter(route); again != m {
		t.Fatal("the same route got a second meter, so one batch would name its key twice")
	}
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 2 * time.Second, TTFT: 300 * time.Millisecond, Overhead: time.Millisecond, OutputTokens: 40, Retries: 2})
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: time.Second, TTFT: 200 * time.Millisecond, Overhead: time.Millisecond})
	m.Observe(Observation{Path: PathBuffered, Outcome: Throttled, Overhead: time.Millisecond})
	batch := r.Drain()
	if len(batch) != 2 {
		t.Fatalf("batch %+v, want a stream/ok row and a buffered/throttled row", batch)
	}
	ok := rowFor(t, batch, PathStream, OK)
	if ok.Key != route || ok.Requests != 2 || ok.Duration.Total() != 2 || ok.TTFT.Total() != 2 || ok.Overhead.Total() != 2 {
		t.Errorf("stream/ok row %+v, want two requests with every latency under the route's key", ok)
	}
	if ok.OutputTokens != 40 || ok.GenerationMicros != 2_000_000 || ok.Retries != 2 {
		t.Errorf("stream/ok sums %d tokens, %dµs, %d retries, want 40 over the 2s of the one call that reported them, and 2", ok.OutputTokens, ok.GenerationMicros, ok.Retries)
	}
	throttled := rowFor(t, batch, PathBuffered, Throttled)
	if throttled.Requests != 1 || len(throttled.Duration) != 0 || len(throttled.TTFT) != 0 || throttled.Overhead.Total() != 1 {
		t.Errorf("throttled row %+v, want one request with an overhead and no duration or ttft", throttled)
	}
	if again := r.Drain(); len(again) != 0 {
		t.Errorf("a second drain returned %+v, want nothing", again)
	}
}

func TestANilRecorderAndANilMeterRecordNothing(t *testing.T) {
	var r *Recorder
	m := r.Meter(route)
	if m != nil {
		t.Fatalf("a nil recorder handed out %v", m)
	}
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: time.Second})
	if batch := r.Drain(); batch != nil {
		t.Errorf("a nil recorder drained %+v", batch)
	}
}

func TestAnObservationRacingADrainIsNeitherLostNorDoubled(t *testing.T) {
	const writers, each = 8, 5000
	r := NewRecorder()
	meters := []*Meter{r.Meter(route), r.Meter(Key{Host: "other.example", UpstreamModel: "u", Model: "n", Kind: catalog.KindChat})}
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				meters[w%len(meters)].Observe(Observation{
					Path: PathStream, Outcome: Outcome(i % int(outcomeCount)),
					Duration: time.Duration(i+1) * time.Microsecond, TTFT: time.Millisecond, Overhead: time.Microsecond,
					OutputTokens: 3, Retries: 1,
				})
			}
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	var total Row
	total.Duration, total.TTFT, total.Overhead = Counts{}, Counts{}, Counts{}
	fold := func(batch Batch) {
		for _, row := range batch {
			total.Requests += row.Requests
			total.OutputTokens += row.OutputTokens
			total.GenerationMicros += row.GenerationMicros
			total.Retries += row.Retries
			for into, from := range map[*Counts]Counts{&total.Duration: row.Duration, &total.TTFT: row.TTFT, &total.Overhead: row.Overhead} {
				for bound, n := range from {
					(*into)[bound] += n
				}
			}
		}
	}
	for draining := true; draining; {
		select {
		case <-done:
			draining = false
		default:
		}
		fold(r.Drain())
	}
	const want = writers * each
	if total.Requests != want || total.Duration.Total() != want || total.TTFT.Total() != want || total.Overhead.Total() != want {
		t.Errorf("drains took %d requests, %d durations, %d ttfts, %d overheads, want %d each", total.Requests, total.Duration.Total(), total.TTFT.Total(), total.Overhead.Total(), want)
	}
	const micros = writers * each * (each + 1) / 2
	if total.OutputTokens != 3*want || total.GenerationMicros != micros || total.Retries != want {
		t.Errorf("drains took %d tokens, %dµs, %d retries, want %d, %d, %d", total.OutputTokens, total.GenerationMicros, total.Retries, 3*want, micros, want)
	}
}
