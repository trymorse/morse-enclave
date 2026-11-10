package health

import (
	"sync"
	"testing"
	"time"
)

func TestEveryDurationFallsInsideItsBucket(t *testing.T) {
	for micros := uint64(0); micros < 1<<trackedMicroBits; micros = micros*9/8 + 1 {
		i := bucketOf(micros)
		lower := time.Duration(0)
		if i > 0 {
			lower = bucketUpperBound(i - 1)
		}
		d := time.Duration(micros) * time.Microsecond
		if d < lower || d >= bucketUpperBound(i) {
			t.Fatalf("%v landed in bucket %d, which spans [%v, %v)", d, i, lower, bucketUpperBound(i))
		}
	}
}

func TestASnapshotChangesNothingAndADrainLeavesZero(t *testing.T) {
	var hist Histogram
	for i := 1; i <= 1000; i++ {
		hist.Record(time.Duration(i) * time.Millisecond)
	}
	first, second := hist.Snapshot(), hist.Snapshot()
	if first.Total() != 1000 || second.Total() != 1000 {
		t.Fatalf("two snapshots hold %d and %d samples, want 1000 each", first.Total(), second.Total())
	}
	for _, c := range []struct {
		q    float64
		want time.Duration
	}{{0.5, 500 * time.Millisecond}, {0.9, 900 * time.Millisecond}, {0.99, 990 * time.Millisecond}} {
		if got := first.Quantile(c.q); got < c.want || got > c.want*9/8 {
			t.Errorf("quantile %v is %v, want within 12.5%% above %v", c.q, got, c.want)
		}
	}
	if drained := hist.Drain(); drained.Total() != 1000 {
		t.Errorf("the drain took %d samples, want 1000", drained.Total())
	}
	if left := hist.Drain(); len(left) != 0 {
		t.Errorf("a second drain took %v, want nothing", left)
	}
	if hist.Max() != time.Second {
		t.Errorf("max %v after the drain, want the longest recorded second", hist.Max())
	}
}

func TestCountsAreKeyedByTheBucketsUpperBoundInMicroseconds(t *testing.T) {
	var hist Histogram
	hist.Record(3 * time.Microsecond)
	hist.Record(1500 * time.Microsecond)
	hist.Record(1500 * time.Microsecond)
	got := hist.Snapshot()
	if len(got) != 2 || got[4] != 1 || got[1536] != 2 {
		t.Errorf("counts %v, want one sample under 4µs and two under 1536µs", got)
	}
	if empty := (Counts{}).Quantile(0.5); empty != 0 {
		t.Errorf("an empty histogram's median is %v, want 0", empty)
	}
}

func TestARecordRacingADrainIsTakenExactlyOnce(t *testing.T) {
	const writers, each = 8, 20000
	var hist Histogram
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				hist.Record(time.Duration(w*each+i) * time.Microsecond)
			}
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	var taken uint64
	for draining := true; draining; {
		select {
		case <-done:
			draining = false
		default:
		}
		taken += hist.Drain().Total()
	}
	if taken != writers*each {
		t.Errorf("drains took %d samples of %d recorded", taken, writers*each)
	}
}

func TestTheLeastAQuantileCanBeIsTheLowerEdgeOfTheBucketItFallsIn(t *testing.T) {
	var h Histogram
	for range 9 {
		h.Record(time.Second)
	}
	h.Record(2 * time.Second)
	c := h.Snapshot()
	for _, q := range []float64{0.5, 0.9} {
		if lo, hi := c.QuantileAtLeast(q), c.Quantile(q); lo > time.Second || hi <= time.Second || lo >= hi {
			t.Errorf("q%.0f: at least %s, at most %s, want an edge at or below 1s below a bound above it", q*100, lo, hi)
		}
	}
	if lo := c.QuantileAtLeast(1); lo > 2*time.Second || lo <= time.Second {
		t.Errorf("q100 at least %s, want the edge of 2s's bucket", lo)
	}
	if lo := (Counts{}).QuantileAtLeast(0.9); lo != 0 {
		t.Errorf("an empty histogram's q90 is at least %s, want 0", lo)
	}
}
