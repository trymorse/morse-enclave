package health

import (
	"maps"
	"math"
	"slices"
	"sync"
)

// Rates counts replies by whole decode rate in tokens a second. Unlike a Histogram's bounds, each key is exact, so a
// median read from it can be held to a floor such as 80 tok/s without a bucket's width deciding the verdict.
type Rates map[int]uint64

func (r Rates) Total() uint64 {
	var total uint64
	for _, n := range r {
		total += n
	}
	return total
}

// Quantile is the smallest rate at or below which a q share of the replies decoded, as Counts.Quantile ranks.
func (r Rates) Quantile(q float64) int {
	rank := max(uint64(math.Ceil(q*float64(r.Total()))), 1)
	var seen uint64
	for _, rate := range slices.Sorted(maps.Keys(r)) {
		if seen += r[rate]; seen >= rank {
			return rate
		}
	}
	return 0
}

func (r Rates) Add(o Rates) {
	for rate, n := range o {
		r[rate] += n
	}
}

type rateHistogram struct {
	mu    sync.Mutex
	rates Rates
}

func (h *rateHistogram) record(rate int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rates == nil {
		h.rates = Rates{}
	}
	h.rates[rate]++
}

func (h *rateHistogram) drain() Rates {
	h.mu.Lock()
	defer h.mu.Unlock()
	drained := h.rates
	h.rates = nil
	return drained
}
