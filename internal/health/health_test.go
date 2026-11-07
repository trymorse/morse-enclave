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
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 2 * time.Second, TTFT: 300 * time.Millisecond, Overhead: time.Millisecond, OutputTokens: 400, Retries: 2, Hedges: 1})
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
	if ok.OutputTokens != 400 || ok.GenerationMicros != 1_700_000 || ok.Retries != 2 || ok.Hedges != 1 {
		t.Errorf("stream/ok sums %d tokens, %dµs, %d retries, %d hedges, want 400 over the 1.7s after the first token of the one call that reported them, 2, and 1", ok.OutputTokens, ok.GenerationMicros, ok.Retries, ok.Hedges)
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
					Duration: 101*time.Millisecond + time.Duration(i+1)*time.Microsecond, TTFT: time.Millisecond, Overhead: time.Microsecond,
					OutputTokens: MinDecodeTokens, Retries: 1, Hedges: 1,
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
			total.Hedges += row.Hedges
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
	micros := uint64(writers * (each*100_000 + each*(each+1)/2))
	if total.OutputTokens != MinDecodeTokens*want || total.GenerationMicros != micros || total.Retries != want || total.Hedges != want {
		t.Errorf("drains took %d tokens, %dµs, %d retries, %d hedges, want %d, %d, %d, %d", total.OutputTokens, total.GenerationMicros, total.Retries, total.Hedges, MinDecodeTokens*want, micros, want, want)
	}
}

func tokensPerSecond(row Row) float64 {
	return float64(row.OutputTokens) * 1e6 / float64(row.GenerationMicros)
}

func TestTokensPerSecondIsTheDecodeSpeedOfLongStreamedReplies(t *testing.T) {
	r := NewRecorder()
	m := r.Meter(route)
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 3 * time.Second, TTFT: time.Second, OutputTokens: 276})
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 1500 * time.Millisecond, TTFT: 1200 * time.Millisecond, OutputTokens: 11})
	m.Observe(Observation{Path: PathBuffered, Outcome: OK, Duration: 3 * time.Second, OutputTokens: 500})
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 2*time.Second - time.Microsecond, TTFT: time.Second, OutputTokens: 2000})
	batch := r.Drain()
	stream := rowFor(t, batch, PathStream, OK)
	if got := tokensPerSecond(stream); got != 138 {
		t.Errorf("stream/ok reads %d tokens over %dµs, %.1f a second, want 138: the 276 tokens over the 2s after the first token, the 11-token reply and the 2,000 that came in one burst left out", stream.OutputTokens, stream.GenerationMicros, got)
	}
	if stream.Requests != 3 || stream.Duration.Total() != 3 || stream.TTFT.Total() != 3 {
		t.Errorf("stream/ok row %+v, want all three replies counted with a duration and a ttft", stream)
	}
	buffered := rowFor(t, batch, PathBuffered, OK)
	if buffered.Requests != 1 || buffered.Duration.Total() != 1 || buffered.OutputTokens != 0 || buffered.GenerationMicros != 0 {
		t.Errorf("buffered/ok row %+v, want one request with a duration and no tokens, since a buffered reply has no first token to measure decode from", buffered)
	}
}

func TestALongReplyFasterThanMaxDecodeRateIsABurstAndLeftOut(t *testing.T) {
	r := NewRecorder()
	m := r.Meter(route)
	for range 10 {
		m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: 11 * time.Second, TTFT: time.Second, OutputTokens: 500})
	}
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: time.Second + 101*time.Millisecond, TTFT: time.Second, OutputTokens: 5000})
	if row := rowFor(t, r.Drain(), PathStream, OK); tokensPerSecond(row) != 50 {
		t.Errorf("%d tokens over %dµs, %.1f a second, want 50: ten 500-token replies over 10s each, and the 5,000 tokens in 101ms left out as a burst", row.OutputTokens, row.GenerationMicros, tokensPerSecond(row))
	}
}

func TestALongReplyJustUnderMaxDecodeRateCounts(t *testing.T) {
	r := NewRecorder()
	m := r.Meter(route)
	m.Observe(Observation{Path: PathStream, Outcome: OK, Duration: time.Second + 2600*time.Millisecond, TTFT: time.Second, OutputTokens: 5000})
	if row := rowFor(t, r.Drain(), PathStream, OK); row.OutputTokens != 5000 || row.GenerationMicros != 2_600_000 {
		t.Errorf("%d tokens over %dµs, want 5000 over 2600000: about 1,923 a second is under the cap", row.OutputTokens, row.GenerationMicros)
	}
}

func TestADecodeAtExactlyMaxDecodeRateCountsAndOneMicrosecondFasterDoesNot(t *testing.T) {
	for _, tc := range []struct {
		decode         time.Duration
		tokens, micros uint64
	}{{2500 * time.Millisecond, 5000, 2_500_000}, {2500*time.Millisecond - time.Microsecond, 0, 0}} {
		r := NewRecorder()
		r.Meter(route).Observe(Observation{Path: PathStream, Outcome: OK, Duration: time.Second + tc.decode, TTFT: time.Second, OutputTokens: 5000})
		if row := rowFor(t, r.Drain(), PathStream, OK); row.OutputTokens != tc.tokens || row.GenerationMicros != tc.micros {
			t.Errorf("5,000 tokens over %v recorded %d tokens over %dµs, want %d over %dµs: 5,000 at 2,000 a second take exactly 2.5s", tc.decode, row.OutputTokens, row.GenerationMicros, tc.tokens, tc.micros)
		}
	}
}

func TestAHostReportingMoreTokensThanADurationCanHoldIsABurstAndLeftOut(t *testing.T) {
	for _, tokens := range []int{9_223_372_037, 10_000_000_000} {
		r := NewRecorder()
		r.Meter(route).Observe(Observation{Path: PathStream, Outcome: OK, Duration: 2 * time.Second, TTFT: time.Second, OutputTokens: tokens})
		if row := rowFor(t, r.Drain(), PathStream, OK); row.OutputTokens != 0 || row.GenerationMicros != 0 {
			t.Errorf("%d tokens in one second recorded %d tokens over %dµs, want none: that is far above %d a second", tokens, row.OutputTokens, row.GenerationMicros, MaxDecodeRate)
		}
	}
}

func TestAReplyUnderMinDecodeTokensIsLeftOut(t *testing.T) {
	r := NewRecorder()
	r.Meter(route).Observe(Observation{Path: PathStream, Outcome: OK, Duration: 11 * time.Second, TTFT: time.Second, OutputTokens: 199})
	if row := rowFor(t, r.Drain(), PathStream, OK); row.OutputTokens != 0 || row.GenerationMicros != 0 {
		t.Errorf("a 199-token reply recorded %d tokens over %dµs, want none: under %d tokens a reply is mostly fixed latency", row.OutputTokens, row.GenerationMicros, MinDecodeTokens)
	}
}
