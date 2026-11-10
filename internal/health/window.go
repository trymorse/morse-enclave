package health

// Tally is what one endpoint's chat replies showed over a window: how many ended ok or malformed, how many of those
// were malformed, their times to first token, and the decode rates of those long enough to time.
type Tally struct {
	Replies, Malformed uint64
	TTFT               Counts
	DecodeRate         Rates
}

// Window holds a Tally per series key, summed over the window's buckets.
type Window map[Key]*Tally

func (w Window) Add(k Key, o Outcome, requests uint64, ttft Counts, rates Rates) {
	t := w[k]
	if t == nil {
		t = &Tally{TTFT: Counts{}, DecodeRate: Rates{}}
		w[k] = t
	}
	t.Replies += requests
	if o == Malformed {
		t.Malformed += requests
	}
	for bound, n := range ttft {
		t.TTFT[bound] += n
	}
	t.DecodeRate.Add(rates)
}
