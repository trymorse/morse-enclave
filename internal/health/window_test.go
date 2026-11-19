package health

import "testing"

func TestAWindowCountsAHostFaultAsAFailedCallAndLeavesEveryOtherFailureOut(t *testing.T) {
	k := Key{Host: "h", Endpoint: "e"}
	w := Window{}
	w.Add(k, OK, 4, Counts{1000: 4}, Rates{90: 4})
	w.Add(k, Malformed, 1, nil, nil)
	w.Add(k, UpstreamError, 2, Counts{1000: 2}, nil)
	w.Add(k, Stalled, 1, nil, nil)
	w.Add(k, ClientError, 7, nil, nil)
	w.Add(k, ContextOverflow, 3, nil, nil)
	got := w[k]
	if got.Replies != 5 || got.Malformed != 1 || got.Failed != 3 || got.TTFT.Total() != 4 || got.DecodeRate.Total() != 4 {
		t.Errorf("%+v, want 5 replies, 1 malformed, 3 failed, and only the replies' 4 first tokens and decode rates", *got)
	}
}
