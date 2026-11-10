package health

import (
	"maps"
	"math"
	"math/bits"
	"slices"
	"sync/atomic"
	"time"
)

const (
	subBucketBits    = 3
	subBuckets       = 1 << subBucketBits
	trackedMicroBits = 32
	bucketCount      = (trackedMicroBits - subBucketBits + 1) * subBuckets
)

var LongestTracked = bucketUpperBound(bucketCount - 1)

type Histogram struct {
	buckets [bucketCount]atomic.Uint64
	max     atomic.Int64
}

func (h *Histogram) Record(d time.Duration) {
	d = max(d, 0)
	h.buckets[bucketOf(uint64(d.Microseconds()))].Add(1)
	for {
		seen := h.max.Load()
		if int64(d) <= seen || h.max.CompareAndSwap(seen, int64(d)) {
			return
		}
	}
}

func (h *Histogram) Max() time.Duration { return time.Duration(h.max.Load()) }

func bucketOf(micros uint64) int {
	micros = min(micros, 1<<trackedMicroBits-1)
	if micros < subBuckets {
		return int(micros)
	}
	octave := bits.Len64(micros) - 1
	return (octave-subBucketBits+1)*subBuckets + int(micros>>(octave-subBucketBits)) - subBuckets
}

func bucketUpperBound(i int) time.Duration {
	if i < subBuckets {
		return time.Duration(i+1) * time.Microsecond
	}
	octave := i/subBuckets + subBucketBits - 1
	return time.Duration(subBuckets+i%subBuckets+1) << (octave - subBucketBits) * time.Microsecond
}

type BoundMicros int64

func (b BoundMicros) Duration() time.Duration { return time.Duration(b) * time.Microsecond }

type Counts map[BoundMicros]uint64

func (c Counts) Total() uint64 {
	var total uint64
	for _, n := range c {
		total += n
	}
	return total
}

func (c Counts) Bounds() []BoundMicros { return slices.Sorted(maps.Keys(c)) }

func (c Counts) Quantile(q float64) time.Duration {
	rank := max(uint64(math.Ceil(q*float64(c.Total()))), 1)
	var seen uint64
	for _, bound := range c.Bounds() {
		if seen += c[bound]; seen >= rank {
			return bound.Duration()
		}
	}
	return 0
}

// QuantileAtLeast is the least the q-quantile can be: the lower edge of the bucket Quantile names. A bucket is up to an
// eighth of its bound wide, so a ceiling it straddles is not known to be missed, and only this edge passing it is.
func (c Counts) QuantileAtLeast(q float64) time.Duration {
	bound := c.Quantile(q)
	if bound <= 0 {
		return 0
	}
	i := bucketOf(uint64(bound.Microseconds()) - 1)
	if i == 0 {
		return 0
	}
	return bucketUpperBound(i - 1)
}

func (h *Histogram) Snapshot() Counts {
	return h.read((*atomic.Uint64).Load)
}

func (h *Histogram) Drain() Counts {
	return h.read(func(bucket *atomic.Uint64) uint64 { return bucket.Swap(0) })
}

func (h *Histogram) read(take func(*atomic.Uint64) uint64) Counts {
	counts := Counts{}
	for i := range h.buckets {
		if n := take(&h.buckets[i]); n > 0 {
			counts[BoundMicros(bucketUpperBound(i).Microseconds())] = n
		}
	}
	return counts
}
