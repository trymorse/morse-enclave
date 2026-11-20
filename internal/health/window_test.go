package health

import (
	"maps"
	"testing"
)

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

func TestMergingTalliesSumsThemAsOneWindowOfTheirBucketsWould(t *testing.T) {
	key := Key{Host: "h", Model: "m", Endpoint: "e"}
	one, two := Counts{1000: 2}, Counts{1000: 1, 2000: 3}
	whole := Window{}
	whole.Add(key, OK, 2, one, Rates{80: 2})
	whole.Add(key, Malformed, 1, two, Rates{90: 1})
	whole.Add(key, Stalled, 4, nil, nil)
	first, second := Window{}, Window{}
	first.Add(key, OK, 2, one, Rates{80: 2})
	second.Add(key, Malformed, 1, two, Rates{90: 1})
	second.Add(key, Stalled, 4, nil, nil)
	var merged Tally
	merged.Merge(*first[key])
	merged.Merge(*second[key])
	if merged.Replies != whole[key].Replies || merged.Malformed != whole[key].Malformed || merged.Failed != whole[key].Failed ||
		!maps.Equal(merged.TTFT, whole[key].TTFT) || !maps.Equal(merged.DecodeRate, whole[key].DecodeRate) {
		t.Errorf("merged %+v, want %+v", merged, *whole[key])
	}
}
