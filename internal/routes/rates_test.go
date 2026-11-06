package routes

import (
	"strings"
	"testing"
)

func TestParsePriceReadsARateObjectAsARoutesPriceAndNamesTheFieldItRefuses(t *testing.T) {
	rts, err := parse([]byte(`[` + chatJSON + `]`))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ChatOf(rts[0].Serves)
	got, err := ParsePrice([]byte(`{"prompt_micros_per_mtok":150000,"cached_prompt_micros_per_mtok":15000,"completion_micros_per_mtok":600000}`), "cost")
	if err != nil || got != want.Price {
		t.Errorf("ParsePrice gives %+v %v, want the route's price %+v", got, err, want.Price)
	}
	long, err := ParsePrice([]byte(`{"prompt_micros_per_mtok":1,"cached_prompt_micros_per_mtok":1,"completion_micros_per_mtok":1,"long_context":{"from_prompt_tokens":5,"prompt_micros_per_mtok":2,"cached_prompt_micros_per_mtok":2,"cache_write_prompt_micros_per_mtok":3,"completion_micros_per_mtok":2}}`), "cost")
	if err != nil || long.LongContext == nil || long.LongContext.FromPromptTokens != 5 || long.LongContext.CacheWritePromptPerMTok != 3 {
		t.Errorf("a long-context rate parses as %+v %v", long, err)
	}
	for name, c := range map[string]struct{ raw, want string }{
		"nothing":             {``, `needs cost.prompt_micros_per_mtok, cost.cached_prompt_micros_per_mtok, and cost.completion_micros_per_mtok`},
		"null":                {`null`, `needs cost.prompt_micros_per_mtok`},
		"an unknown field":    {`{"prompt_micros_per_mtok":1,"cached_prompt_micros_per_mtok":1,"completion_micros_per_mtok":1,"cached":1}`, `cost: json: unknown field "cached"`},
		"a stray threshold":   {`{"prompt_micros_per_mtok":1,"cached_prompt_micros_per_mtok":1,"completion_micros_per_mtok":1,"from_prompt_tokens":5}`, `sets from_prompt_tokens outside cost.long_context`},
		"a cached rate above": {`{"prompt_micros_per_mtok":1,"cached_prompt_micros_per_mtok":2,"completion_micros_per_mtok":1}`, `has an invalid cost: the cached prompt price must not exceed the prompt price`},
	} {
		if _, err := ParsePrice([]byte(c.raw), "cost"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestParseMicrosPerCallReadsAPerCallRateFromOneMicroToTheUnitCeiling(t *testing.T) {
	if got, err := ParseMicrosPerCall([]byte(`{"micros_per_call":1000}`), "cost"); err != nil || got != 1000 {
		t.Errorf("1000 micros parses as %d %v", got, err)
	}
	for name, c := range map[string]struct{ raw, want string }{
		"nothing":          {``, `needs cost.micros_per_call`},
		"an empty object":  {`{}`, `needs cost.micros_per_call`},
		"zero":             {`{"micros_per_call":0}`, `cost.micros_per_call must be between 1 and 10000000 micros`},
		"past the ceiling": {`{"micros_per_call":10000001}`, `cost.micros_per_call must be between 1 and 10000000 micros`},
		"an unknown field": {`{"micros_per_call":1,"micros_per_result":1}`, `cost: json: unknown field "micros_per_result"`},
	} {
		if _, err := ParseMicrosPerCall([]byte(c.raw), "cost"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}
