package health

// Tally is what one endpoint's chat replies showed over a window: how many ended ok or malformed, how many of those
// were malformed, their times to first token, and the decode rates of those long enough to time.
type Tally struct {
	Replies, Malformed, Failed uint64
	TTFT                       Counts
	DecodeRate                 Rates
}

// Window holds a Tally per series key, summed over the window's buckets.
type Window map[Key]*Tally

func (w Window) Add(k Key, o Outcome, requests uint64, ttft Counts, rates Rates) {
	t := w[k]
	if t == nil {
		t = &Tally{TTFT: Counts{}, DecodeRate: Rates{}}
		w[k] = t
	}
	if o != OK && o != Malformed {
		if o.TripsBreaker() {
			t.Failed += requests
		}
		return
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

func (t *Tally) Merge(o Tally) {
	t.Replies, t.Malformed, t.Failed = t.Replies+o.Replies, t.Malformed+o.Malformed, t.Failed+o.Failed
	if t.TTFT == nil {
		t.TTFT = Counts{}
	}
	if t.DecodeRate == nil {
		t.DecodeRate = Rates{}
	}
	for bound, n := range o.TTFT {
		t.TTFT[bound] += n
	}
	t.DecodeRate.Add(o.DecodeRate)
}
