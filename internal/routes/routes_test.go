package routes

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/attester"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/compaction"
	"morse/backend/internal/plankind"
)

const testDefaultMarkup money.Markup = 5_000

func parse(data []byte) ([]Route, error) { return Parse(data, testDefaultMarkup) }

const (
	tokenPriced  = `"price":{"prompt_micros_per_mtok":150000,"cached_prompt_micros_per_mtok":15000,"completion_micros_per_mtok":600000},"max_output_tokens":16384,"default_max_tokens":16384,"context_tokens":131072,"reasoning_efforts":[]`
	chatJSON     = `{"model":"m","label":"M","tier":"private","base_url":"https://u","upstream_model":"up/m",` + tokenPriced + `}`
	imageJSON    = `{"model":"i","label":"I","tier":"anon","owned_by":"V","kind":"image","provider":"fal","base_url":"https://u","upstream_model":"fal-ai/flux-2-pro","api_key_env":"K","price":{"hold_micros_per_image":1}}`
	videoJSON    = `{"model":"v","label":"V","tier":"anon","owned_by":"V","kind":"video","provider":"fal","base_url":"https://u","upstream_model":"x","api_key_env":"K","price":{"hold_micros_per_second":1}}`
	searchJSON   = `{"model":"s","label":"S","tier":"anon","owned_by":"V","kind":"search","provider":"parallel","base_url":"https://u","upstream_model":"fast","api_key_env":"K","price":{"micros_per_call":1}}`
	fetchJSON    = `{"model":"f","label":"F","tier":"anon","owned_by":"V","kind":"fetch","provider":"parallel","base_url":"https://u","upstream_model":"extract","api_key_env":"K","price":{"micros_per_call":1}}`
	researchJSON = `{"model":"r","label":"R","tier":"anon","owned_by":"V","kind":"research","provider":"parallel","base_url":"https://u","upstream_model":"pro","api_key_env":"K","price":{"micros_per_call":100000}}`
	speechJSON   = `{"model":"w","label":"W","tier":"anon","owned_by":"V","kind":"transcription","base_url":"https://u","upstream_model":"whisper-1","api_key_env":"K","price":{"micros_per_call":1000}}`
	nearWhisper  = `{"model":"whisper-tee","label":"Whisper","tier":"tee","attester":"near","kind":"transcription","base_url":"https://cloud-api.near.ai","upstream_model":"openai/whisper-large-v3","api_key_env":"NEAR_API_KEY","price":{"micros_per_call":1000}}`
)

func TestChatImageAndVideoRoutesSellAtTheDefaultMarkupUnlessTheyNameTheirOwn(t *testing.T) {
	with := func(route, markup string) string {
		return strings.Replace(route, `"price"`, `"markup":`+markup+`,"price"`, 1)
	}
	rts, err := parse([]byte(`[` + strings.Join([]string{with(chatJSON, "1"), with(imageJSON, "1.25"), with(videoJSON, "2.5")}, ",") + `]`))
	if err != nil {
		t.Fatal(err)
	}
	listed := rts[0].Serves.(Chat)
	if listed.Markup != 0 || listed.Billed().PromptPerMTok != 150000 {
		t.Errorf("chat at markup 1: %+v billed %+v", listed, listed.Billed())
	}
	if got := rts[1].Serves.(Image).Price.Markup; got != 2_500 {
		t.Errorf("image markup %d, want 2500", got)
	}
	if got := rts[2].Serves.(Video).Price.Markup; got != 15_000 {
		t.Errorf("video markup %d, want 15000", got)
	}
	defaulted, err := parse([]byte(`[` + chatJSON + `]`))
	if err != nil {
		t.Fatal(err)
	}
	if billed := defaulted[0].Serves.(Chat).Billed(); billed != (money.Price{PromptPerMTok: 225000, CachedPromptPerMTok: 22500, CacheWritePromptPerMTok: 225000, CompletionPerMTok: 900000}) {
		t.Errorf("default markup bills %+v, want 1.5x the list", billed)
	}
	for _, markup := range []string{"0.9", "0", "10.5", "1.23456", `"1.3"`, "null", "1e0", "-1"} {
		for _, route := range []string{chatJSON, imageJSON, videoJSON} {
			if _, err := parse([]byte(`[` + with(route, markup) + `]`)); err == nil || !strings.Contains(err.Error(), "markup must be a number from 1 to 10 with at most four decimal places") {
				t.Errorf("markup %s: err %v", markup, err)
			}
		}
	}
	near := strings.Replace(chatJSON, `"completion_micros_per_mtok":600000`, `"completion_micros_per_mtok":900000000`, 1)
	if _, err := parse([]byte(`[` + near + `]`)); err == nil || !strings.Contains(err.Error(), "at its markup") {
		t.Errorf("a list rate the markup lifts past the ceiling: %v", err)
	}
	if _, err := parse([]byte(`[` + with(near, "1") + `]`)); err != nil {
		t.Errorf("the same rate at list: %v", err)
	}
}

func TestEachKindDecodesIntoItsOwnSchemaAndRefusesAnotherKindsFields(t *testing.T) {
	rts, err := parse([]byte(`[` + strings.Join([]string{chatJSON, imageJSON, videoJSON, searchJSON, fetchJSON, researchJSON, speechJSON, nearWhisper}, ",") + `]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Serves{
		Chat{Price: money.Price{PromptPerMTok: 150000, CachedPromptPerMTok: 15000, CacheWritePromptPerMTok: 150000, CompletionPerMTok: 600000}, Markup: testDefaultMarkup, OpenRouterID: "up/m", ChatTerms: catalog.ChatTerms{MaxOutputTokens: 16384, DefaultMaxTokens: 16384, ReasoningEfforts: []string{}, ContextTokens: 131072, CompactAtTokens: 131072 - 16384 - compaction.SummaryReserve}},
		Image{Price: money.MediaPrice{PerUnit: 1, Markup: testDefaultMarkup}},
		Video{Price: money.MediaPrice{PerUnit: 1, Markup: testDefaultMarkup}},
		PerCall{Call: catalog.KindSearch, Price: 1},
		PerCall{Call: catalog.KindFetch, Price: 1},
		PerCall{Call: catalog.KindResearch, Price: 100000},
		PerCall{Call: catalog.KindTranscription, Price: 1000},
		PerCall{Call: catalog.KindTranscription, Price: 1000},
	}
	for i, rt := range rts {
		if !reflect.DeepEqual(rt.Serves, want[i]) {
			t.Errorf("route %d serves %+v, want %+v", i, rt.Serves, want[i])
		}
	}
	if m := rts[0]; m.Upstream != (Vendor{Provider: ProviderOpenAI}) || m.Retention != catalog.RetentionVendor || m.OwnedBy != "morse" || m.Tier != catalog.Private || m.Host != "u" {
		t.Errorf("defaults: %+v", m)
	}
	if w := rts[7]; w.Upstream != (Attested{Attester: attester.Near}) || w.Tier != catalog.TEE || w.Host != "cloud-api.near.ai" || w.UpstreamModel != "openai/whisper-large-v3" {
		t.Errorf("the NEAR transcription route: %+v", w)
	}
	stray := map[string]string{
		"image with token limits":       strings.Replace(imageJSON, `"price"`, `"max_output_tokens":1,"price"`, 1),
		"video with a context":          strings.Replace(videoJSON, `"price"`, `"context_tokens":1,"price"`, 1),
		"search with a default":         strings.Replace(searchJSON, `"price"`, `"default_max_tokens":1,"price"`, 1),
		"fetch with a context":          strings.Replace(fetchJSON, `"price"`, `"context_tokens":1,"price"`, 1),
		"search with a context":         strings.Replace(searchJSON, `"price"`, `"context_tokens":5000,"price"`, 1),
		"chat with an image hold":       strings.Replace(chatJSON, `"completion_micros_per_mtok"`, `"hold_micros_per_image":1,"completion_micros_per_mtok"`, 1),
		"image with a call price":       strings.Replace(imageJSON, `"hold_micros_per_image"`, `"micros_per_call":1,"hold_micros_per_image"`, 1),
		"search with a token rate":      strings.Replace(searchJSON, `"micros_per_call"`, `"prompt_micros_per_mtok":1,"micros_per_call"`, 1),
		"a field no kind takes":         strings.Replace(chatJSON, `"label"`, `"api_key":"inline","label"`, 1),
		"image with a token rate":       strings.Replace(imageJSON, `"hold_micros_per_image"`, `"prompt_micros_per_mtok":1,"hold_micros_per_image"`, 1),
		"image with a seconds hold":     strings.Replace(imageJSON, `"hold_micros_per_image"`, `"hold_micros_per_second":1,"hold_micros_per_image"`, 1),
		"chat with a seconds hold":      strings.Replace(chatJSON, `"completion_micros_per_mtok"`, `"hold_micros_per_second":1,"completion_micros_per_mtok"`, 1),
		"video with a reference hold":   strings.Replace(videoJSON, `"hold_micros_per_second"`, `"hold_micros_per_reference":1,"hold_micros_per_second"`, 1),
		"video with an image hold":      strings.Replace(videoJSON, `"hold_micros_per_second"`, `"hold_micros_per_image":1,"hold_micros_per_second"`, 1),
		"chat with a call price":        strings.Replace(chatJSON, `"completion_micros_per_mtok"`, `"micros_per_call":5,"completion_micros_per_mtok"`, 1),
		"search with an image hold":     strings.Replace(searchJSON, `"micros_per_call"`, `"hold_micros_per_image":1,"micros_per_call"`, 1),
		"fetch with token limits":       strings.Replace(fetchJSON, `"price"`, `"max_output_tokens":1,"price"`, 1),
		"image with a default effort":   strings.Replace(imageJSON, `"price"`, `"default_reasoning_effort":"high","price"`, 1),
		"search with a default effort":  strings.Replace(searchJSON, `"price"`, `"default_reasoning_effort":"high","price"`, 1),
		"search with a markup":          strings.Replace(searchJSON, `"price"`, `"markup":1.2,"price"`, 1),
		"fetch with a markup":           strings.Replace(fetchJSON, `"price"`, `"markup":1,"price"`, 1),
		"research with a markup":        strings.Replace(researchJSON, `"price"`, `"markup":1,"price"`, 1),
		"research with a token rate":    strings.Replace(researchJSON, `"micros_per_call"`, `"completion_micros_per_mtok":1,"micros_per_call"`, 1),
		"transcription with a markup":   strings.Replace(speechJSON, `"price"`, `"markup":1,"price"`, 1),
		"transcription with a context":  strings.Replace(speechJSON, `"price"`, `"context_tokens":1,"price"`, 1),
		"transcription with modalities": strings.Replace(speechJSON, `"price"`, `"input_modalities":["text"],"price"`, 1),
		"transcription by the second":   strings.Replace(speechJSON, `"micros_per_call"`, `"hold_micros_per_second":1,"micros_per_call"`, 1),
		"a markup inside price":         strings.Replace(chatJSON, `"completion_micros_per_mtok"`, `"markup":1.2,"completion_micros_per_mtok"`, 1),
	}
	for name, route := range stray {
		_, err := parse([]byte(`[` + route + `]`))
		if err == nil || !strings.Contains(err.Error(), "json: unknown field") || !strings.Contains(err.Error(), "of kind") {
			t.Errorf("%s: err %v, want an unknown-field refusal naming the kind", name, err)
		}
	}
	if _, err := parse([]byte(`[` + strings.Replace(chatJSON, `"label"`, `"kind":"audio","label"`, 1) + `]`)); err == nil || !strings.Contains(err.Error(), `kind "audio"`) {
		t.Errorf("unknown kind: %v", err)
	}
}

func patched(t *testing.T, base string, patch map[string]any) []byte {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(base), &fields); err != nil {
		t.Fatal(err)
	}
	for name, value := range patch {
		if value == nil {
			delete(fields, name)
		} else {
			fields[name] = value
		}
	}
	file, err := json.Marshal([]any{fields})
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func rates(prompt, cached, completion float64) map[string]any {
	return map[string]any{"prompt_micros_per_mtok": prompt, "cached_prompt_micros_per_mtok": cached, "completion_micros_per_mtok": completion}
}

func withRates(rates map[string]any, more map[string]any) map[string]any {
	out := maps.Clone(rates)
	maps.Copy(out, more)
	return out
}

func TestARouteThatBreaksARuleIsRefusedNamingTheRule(t *testing.T) {
	long := func(from float64, prompt, cached, completion float64) map[string]any {
		return withRates(rates(prompt, cached, completion), map[string]any{"from_prompt_tokens": from})
	}
	included := func(fields map[string]any) map[string]any { return map[string]any{"included": fields} }
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  string
	}{
		"no model":                     {chatJSON, map[string]any{"model": nil}, `route 0: has no model`},
		"relative base_url":            {chatJSON, map[string]any{"base_url": "vllm:8000"}, `route "m" base_url must be an absolute URL`},
		"no tier":                      {chatJSON, map[string]any{"tier": nil}, `route "m" tier "" must be one of`},
		"unknown tier":                 {chatJSON, map[string]any{"tier": "zdr"}, `route "m" tier "zdr" must be one of`},
		"no upstream_model":            {chatJSON, map[string]any{"upstream_model": nil}, `route "m" has no upstream_model`},
		"anon without owner":           {chatJSON, map[string]any{"tier": "anon"}, `route "m" is tier anon and must name owned_by`},
		"anon image without owner":     {imageJSON, map[string]any{"owned_by": nil}, `route "i" is tier anon and must name owned_by`},
		"no price":                     {chatJSON, map[string]any{"price": nil}, `route "m" needs price.prompt_micros_per_mtok, price.cached_prompt_micros_per_mtok, and price.completion_micros_per_mtok`},
		"price missing completion":     {chatJSON, map[string]any{"price": map[string]any{"prompt_micros_per_mtok": 1, "cached_prompt_micros_per_mtok": 1}}, `route "m" needs price.prompt_micros_per_mtok`},
		"price missing cached":         {chatJSON, map[string]any{"price": map[string]any{"prompt_micros_per_mtok": 1, "completion_micros_per_mtok": 1}}, `route "m" needs price.prompt_micros_per_mtok`},
		"unknown price field":          {chatJSON, map[string]any{"price": withRates(rates(1, 1, 1), map[string]any{"cached": 1})}, `json: unknown field "cached"`},
		"negative price":               {chatJSON, map[string]any{"price": rates(-1, -1, 1)}, `route "m" has an invalid price: prices must be between 0 and 1000000000 micros per million tokens`},
		"price above the ceiling":      {chatJSON, map[string]any{"price": rates(1, 1, 1000000001)}, `route "m" has an invalid price: prices must be between 0 and 1000000000 micros per million tokens`},
		"cached price above prompt":    {chatJSON, map[string]any{"price": rates(1, 2, 1)}, `route "m" has an invalid price: the cached prompt price must not exceed the prompt price`},
		"cache write below prompt":     {chatJSON, map[string]any{"price": withRates(rates(2, 1, 1), map[string]any{"cache_write_prompt_micros_per_mtok": 1})}, `route "m" has an invalid price: the cache-write prompt price must not be below the prompt price`},
		"threshold outside long":       {chatJSON, map[string]any{"price": long(5, 1, 1, 1)}, `route "m" sets from_prompt_tokens outside price.long_context`},
		"long context missing cached":  {chatJSON, map[string]any{"price": withRates(rates(1, 1, 1), map[string]any{"long_context": map[string]any{"from_prompt_tokens": 5, "prompt_micros_per_mtok": 2, "completion_micros_per_mtok": 2}})}, `route "m" needs price.long_context.prompt_micros_per_mtok`},
		"long context no threshold":    {chatJSON, map[string]any{"price": withRates(rates(1, 1, 1), map[string]any{"long_context": rates(2, 2, 2)})}, `route "m" has an invalid price: a long-context price needs a positive from_prompt_tokens`},
		"long context below base":      {chatJSON, map[string]any{"price": withRates(rates(3, 1, 3), map[string]any{"long_context": long(5, 2, 1, 3)})}, `route "m" has an invalid price: long-context prices must not be below the base prices`},
		"long cache write below base":  {chatJSON, map[string]any{"price": withRates(rates(1, 1, 1), map[string]any{"cache_write_prompt_micros_per_mtok": 3, "long_context": long(5, 2, 1, 1)})}, `route "m" has an invalid price: long-context prices must not be below the base prices`},
		"no max_output_tokens":         {chatJSON, map[string]any{"max_output_tokens": nil}, `route "m" needs a positive max_output_tokens`},
		"zero max_output_tokens":       {chatJSON, map[string]any{"max_output_tokens": 0}, `route "m" needs a positive max_output_tokens`},
		"fractional max_output_token":  {chatJSON, map[string]any{"max_output_tokens": 1.5}, `cannot unmarshal number 1.5 into Go struct field chatRoute.max_output_tokens of type int`},
		"no default_max_tokens":        {chatJSON, map[string]any{"default_max_tokens": nil}, `route "m" needs a default_max_tokens between 1 and its max_output_tokens 16384`},
		"zero default_max_tokens":      {chatJSON, map[string]any{"default_max_tokens": 0}, `route "m" needs a default_max_tokens between 1 and its max_output_tokens 16384`},
		"default above the maximum":    {chatJSON, map[string]any{"default_max_tokens": 16385}, `route "m" needs a default_max_tokens between 1 and its max_output_tokens 16384`},
		"image without hold":           {imageJSON, map[string]any{"price": map[string]any{"hold_micros_per_reference": 1}}, `route "i" of kind image needs price.hold_micros_per_image`},
		"image with zero hold":         {imageJSON, map[string]any{"price": map[string]any{"hold_micros_per_image": 0}}, `route "i" has an invalid price: media routes need a positive hold price per unit`},
		"video without seconds hold":   {videoJSON, map[string]any{"price": map[string]any{}}, `route "v" of kind video needs price.hold_micros_per_second`},
		"research without price":       {researchJSON, map[string]any{"price": nil}, `route "r" of kind research needs price.micros_per_call`},
		"research without a processor": {researchJSON, map[string]any{"upstream_model": ""}, `route "r" has no upstream_model`},
		"an unknown included field":    {chatJSON, included(map[string]any{"from": "free", "quota": "messages", "limit": 10}), `json: unknown field "limit"`},
		"search without price":         {searchJSON, map[string]any{"price": nil}, `route "s" of kind search needs price.micros_per_call`},
		"search with an empty price":   {searchJSON, map[string]any{"price": map[string]any{}}, `route "s" of kind search needs price.micros_per_call`},
		"search with a zero price":     {searchJSON, map[string]any{"price": map[string]any{"micros_per_call": 0}}, `route "s" price.micros_per_call must be between 1 and 10000000 micros`},
		"fetch with a negative price":  {fetchJSON, map[string]any{"price": map[string]any{"micros_per_call": -5}}, `route "f" price.micros_per_call must be between 1 and 10000000 micros`},
		"call price above the ceiling": {searchJSON, map[string]any{"price": map[string]any{"micros_per_call": 10000001}}, `route "s" price.micros_per_call must be between 1 and 10000000 micros`},
		"fractional call price":        {searchJSON, map[string]any{"price": map[string]any{"micros_per_call": 1.5}}, `route "s" of kind search: json: cannot unmarshal number 1.5`},
		"unknown call price field":     {searchJSON, map[string]any{"price": map[string]any{"micros_per_call": 1000, "micros_per_result": 1}}, `json: unknown field "micros_per_result"`},
		"search without a mode":        {searchJSON, map[string]any{"upstream_model": ""}, `route "s" has no upstream_model`},
		"unknown default effort":       {chatJSON, map[string]any{"default_reasoning_effort": "turbo"}, `route "m" default_reasoning_effort must be one of its reasoning_efforts other than none`},
		"default effort none":          {chatJSON, map[string]any{"default_reasoning_effort": "none", "reasoning_efforts": []string{"none", "low"}}, `route "m" default_reasoning_effort must be one of its reasoning_efforts other than none`},
		"default effort unlisted":      {chatJSON, map[string]any{"default_reasoning_effort": "medium", "reasoning_efforts": []string{"low", "high"}}, `route "m" default_reasoning_effort must be one of its reasoning_efforts other than none`},
		"no reasoning_efforts":         {chatJSON, map[string]any{"reasoning_efforts": nil}, `route "m" must list the reasoning_efforts its upstream model accepts, [] for none`},
	} {
		if _, err := parse(patched(t, c.base, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestARouteRequiresAPaidPlanAtOrBelowTheOneThatIncludesIt(t *testing.T) {
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  plankind.Kind
		err   string
	}{
		"open to every plan":      {chatJSON, nil, plankind.Free, ""},
		"pro":                     {chatJSON, map[string]any{"requires_plan": "pro"}, plankind.Pro, ""},
		"included from pro":       {chatJSON, map[string]any{"requires_plan": "pro", "included": map[string]any{"from": "pro"}}, plankind.Pro, ""},
		"free":                    {chatJSON, map[string]any{"requires_plan": "free"}, 0, `route "m" requires_plan "free" must be a paid plan, pro, max; leave it out to let every plan use the route`},
		"unknown":                 {chatJSON, map[string]any{"requires_plan": "gold"}, 0, `requires_plan "gold" must be a paid plan`},
		"web tool on a paid plan": {searchJSON, map[string]any{"requires_plan": "max"}, plankind.Max, ""},
	} {
		rts, err := parse(patched(t, c.base, c.patch))
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: err %v, want %q", name, err, c.err)
		case c.err == "" && (err != nil || rts[0].RequiresPlan != c.want):
			t.Errorf("%s: %+v %v, want requires %s", name, rts, err, c.want)
		}
	}
}

func TestARouteIsAppOnlyOnlyWhenItSaysSo(t *testing.T) {
	for name, c := range map[string]struct {
		patch map[string]any
		want  bool
		err   string
	}{
		"open to keys": {nil, false, ""},
		"app only":     {map[string]any{"app_only": true}, true, ""},
		"said false":   {map[string]any{"app_only": false}, false, ""},
		"not a bool":   {map[string]any{"app_only": "yes"}, false, "json: cannot unmarshal string"},
	} {
		rts, err := parse(patched(t, chatJSON, c.patch))
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: err %v, want %q", name, err, c.err)
		case c.err == "" && (err != nil || rts[0].AppOnly != c.want):
			t.Errorf("%s: %+v %v, want app only %t", name, rts, err, c.want)
		}
	}
}

func TestTheFileIsANonEmptyArrayOfUniqueModelsAndOneAttesterPerHost(t *testing.T) {
	for name, c := range map[string]struct{ file, want string }{
		"not an array":  {`"m"`, "routes must be a JSON array of routes or an object of models and aliases"},
		"empty":         {`[]`, "routes file has no routes"},
		"not objects":   {`[1]`, "route 0: json: cannot unmarshal number"},
		"repeats model": {`[` + chatJSON + `,` + chatJSON + `]`, `route 1 repeats model "m"`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	attested := func(model, tier, attester string) string {
		return `{"model":"` + model + `","label":"M","tier":"` + tier + `","attester":"` + attester + `","base_url":"https://gw.example","upstream_model":"` + model + `",` + tokenPriced + `}`
	}
	rts, err := parse([]byte(`[` + attested("a", "tee", "phala") + `,` + attested("b", "e2ee", "phala") + `]`))
	if err != nil || rts[0].Upstream != (Attested{Attester: attester.Phala}) || rts[1].Upstream != (Attested{Attester: attester.Phala}) {
		t.Errorf("one attester on one host: %+v %v", rts, err)
	}
	rts, err = parse([]byte(`[` + attested("org/n", "e2ee", "near") + `]`))
	if err != nil || rts[0].Upstream != (Attested{Attester: attester.Near}) {
		t.Errorf("a near e2ee route: %+v %v", rts, err)
	}
	_, err = parse([]byte(`[` + attested("a", "tee", "phala") + `,` + attested("org/n", "e2ee", "near") + `]`))
	if err == nil || !strings.Contains(err.Error(), "share host gw.example") {
		t.Errorf("two attesters on one host: %v", err)
	}
}

func TestProviderAndRetentionParseFromTheirNamesAndRefuseOthersByListingThem(t *testing.T) {
	with := func(fields string) string {
		return `[` + strings.Replace(chatJSON, `"label"`, fields+`,"label"`, 1) + `]`
	}
	rts, err := parse(patched(t, chatJSON, map[string]any{"provider": "openai-responses", "retention": "zdr", "tier": "anon", "owned_by": "O", "api_key_env": "K", "reasoning_efforts": []string{}}))
	if err != nil || rts[0].Upstream != (Vendor{Provider: ProviderOpenAIResponses}) || rts[0].Retention != catalog.RetentionZDR {
		t.Errorf("named provider and retention: %+v %v", rts, err)
	}
	for fields, want := range map[string]string{
		`"provider":"mistral"`: `provider "mistral" must be one of openai, openai-responses, anthropic, xai, runware, fal, parallel, gemini`,
		`"provider":"OpenAI"`:  `provider "OpenAI" must be one of`,
		`"retention":"none"`:   `retention "none" must be vendor or zdr`,
		`"retention":"ZDR"`:    `retention "ZDR" must be vendor or zdr`,
	} {
		if _, err := parse([]byte(with(fields))); err == nil || !strings.Contains(err.Error(), `route "m" `+want) {
			t.Errorf("%s: err %v, want %q", fields, err, want)
		}
	}
}

func TestEveryChatRouteNamesAWindowThatHoldsItsOutputAndACompactionCall(t *testing.T) {
	refused := map[string]struct{ route, want string }{
		"no context_tokens":         {strings.Replace(chatJSON, `,"context_tokens":131072`, ``, 1), "needs a positive context_tokens"},
		"a zero context_tokens":     {strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":0`, 1), "needs a positive context_tokens"},
		"output above the window":   {strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":16383`, 1), "max_output_tokens 16384 above its context_tokens 16383"},
		"a window too small":        {strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":32768`, 1), "too small to hold a reply and a compaction call"},
		"a threshold past the room": {strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":131072,"compact_at_tokens":96257`, 1), "compact_at_tokens between 1 and 96256"},
		"a negative threshold":      {strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":131072,"compact_at_tokens":-1`, 1), "compact_at_tokens between 1 and 96256"},
	}
	for name, c := range refused {
		if _, err := parse([]byte(`[` + c.route + `]`)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	rts, err := parse([]byte(`[` + strings.Replace(chatJSON, `"context_tokens":131072`, `"context_tokens":131072,"compact_at_tokens":50000`, 1) + `]`))
	if err != nil {
		t.Fatal(err)
	}
	if c := rts[0].Serves.(Chat); c.ContextTokens != 131072 || c.CompactAtTokens != 50000 {
		t.Errorf("an override below the threshold: %+v", c)
	}
}

func TestAnAttestedRouteTakesNoProviderAndServesChatOrNEARsTranscriptionAtTEE(t *testing.T) {
	attested := func(base, tier, extra string) string {
		unprovided := strings.NewReplacer(`"provider":"fal",`, "", `"provider":"parallel",`, "").Replace(base)
		return strings.Replace(unprovided, `"tier":"anon"`, `"tier":"`+tier+`","attester":"phala"`+extra, 1)
	}
	for name, c := range map[string]struct{ file, want string }{
		"tee with the default provider": {`[` + attested(strings.Replace(chatJSON, `"tier":"private"`, `"tier":"anon"`, 1), "tee", `,"provider":"openai"`) + `]`, `route "m" is tier tee, so attester phala serves it and it takes no provider`},
		"e2ee with another provider":    {`[` + attested(strings.Replace(chatJSON, `"tier":"private"`, `"tier":"anon"`, 1), "e2ee", `,"provider":"anthropic"`) + `]`, `route "m" is tier e2ee, so attester phala serves it and it takes no provider`},
		"tee image":                     {`[` + attested(imageJSON, "tee", "") + `]`, `route "i" is of kind image, which attester phala does not serve`},
		"e2ee video":                    {`[` + attested(videoJSON, "e2ee", "") + `]`, `route "v" is of kind video, which attester phala does not serve`},
		"tee search":                    {`[` + attested(searchJSON, "tee", "") + `]`, `route "s" is of kind search, which attester phala does not serve`},
		"e2ee fetch":                    {`[` + attested(fetchJSON, "e2ee", "") + `]`, `route "f" is of kind fetch, which attester phala does not serve`},
		"tee research":                  {`[` + attested(researchJSON, "tee", "") + `]`, `route "r" is of kind research, which attester phala does not serve`},
		"e2ee default below max":        {`[` + strings.Replace(attested(strings.Replace(chatJSON, `"tier":"private"`, `"tier":"anon"`, 1), "e2ee", ""), `"default_max_tokens":16384`, `"default_max_tokens":1024`, 1) + `]`, `route "m" is tier e2ee, so default_max_tokens must equal max_output_tokens 16384`},
		"e2ee with a default effort":    {`[` + strings.TrimSuffix(attested(strings.Replace(chatJSON, `"tier":"private"`, `"tier":"anon"`, 1), "e2ee", ""), `}`) + `,"default_reasoning_effort":"high","reasoning_efforts":["high"]}]`, `route "m" is tier e2ee and must not set default_reasoning_effort`},
		"near at tee":                   {`[` + strings.Replace(attested(strings.Replace(chatJSON, `"tier":"private"`, `"tier":"anon"`, 1), "tee", ""), `"attester":"phala"`, `"attester":"near"`, 1) + `]`, `route "m" is tier tee, and attester near serves chat routes only at tiers [e2ee]`},
		"phala transcription":           {`[` + strings.Replace(nearWhisper, `"attester":"near"`, `"attester":"phala"`, 1) + `]`, `route "whisper-tee" is of kind transcription, which attester phala does not serve`},
		"near transcription at e2ee":    {`[` + strings.Replace(nearWhisper, `"tier":"tee"`, `"tier":"e2ee"`, 1) + `]`, `route "whisper-tee" is tier e2ee, and attester near serves transcription routes only at tiers [tee]`},
		"near transcription provided":   {`[` + strings.Replace(nearWhisper, `"kind"`, `"provider":"openai","kind"`, 1) + `]`, `route "whisper-tee" is tier tee, so attester near serves it and it takes no provider`},
		"near transcription unpriced":   {`[` + strings.Replace(nearWhisper, `"micros_per_call":1000`, `"micros_per_call":0`, 1) + `]`, `price.micros_per_call must be between 1 and`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestARouteItsUpstreamCannotServeAsDeclaredIsRefusedNamingWhy(t *testing.T) {
	anon := func(provider string, more map[string]any) map[string]any {
		return withRates(map[string]any{"provider": provider, "tier": "anon", "owned_by": "O", "api_key_env": "K"}, more)
	}
	efforts := func(provider string, efforts []string) map[string]any {
		return anon(provider, map[string]any{"reasoning_efforts": efforts})
	}
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  string
	}{
		"anthropic private":                {chatJSON, map[string]any{"provider": "anthropic", "api_key_env": "K", "reasoning_efforts": []string{}}, `route "m" is tier private, and provider anthropic serves chat routes only at tiers [anon]`},
		"responses private":                {chatJSON, map[string]any{"provider": "openai-responses", "api_key_env": "K", "reasoning_efforts": []string{}}, `route "m" is tier private, and provider openai-responses serves chat routes only at tiers [anon]`},
		"responses private zdr":            {chatJSON, map[string]any{"provider": "openai-responses", "api_key_env": "K", "reasoning_efforts": []string{}, "retention": "zdr"}, `route "m" is tier private, and provider openai-responses serves chat routes only at tiers [anon]`},
		"runware private image":            {imageJSON, map[string]any{"provider": "runware", "upstream_model": "bfl:5@1", "tier": "private"}, `route "i" is tier private, and provider runware serves image routes only at tiers [anon]`},
		"runware private video":            {videoJSON, map[string]any{"provider": "runware", "upstream_model": "alibaba:wan@3.0", "tier": "private"}, `route "v" is tier private, and provider runware serves video routes only at tiers [anon]`},
		"fal private image":                {imageJSON, map[string]any{"tier": "private"}, `route "i" is tier private, and provider fal serves image routes only at tiers [anon]`},
		"fal zdr private image":            {imageJSON, map[string]any{"tier": "private", "retention": "zdr"}, `route "i" is tier private, and provider fal serves image routes only at tiers [anon]`},
		"fal private video":                {videoJSON, map[string]any{"tier": "private"}, `route "v" is tier private, and provider fal serves video routes only at tiers [anon]`},
		"anon xai image":                   {imageJSON, map[string]any{"provider": "xai", "retention": "zdr"}, `route "i" is tier anon, and provider xai serves image routes only at tiers [private]`},
		"xai private chat no zdr":          {chatJSON, map[string]any{"provider": "xai", "api_key_env": "K"}, `route "m" uses provider xai at tier private and must set retention zdr, so every reply must confirm zero data retention`},
		"xai private image no zdr":         {imageJSON, map[string]any{"provider": "xai", "tier": "private"}, `route "i" uses provider xai at tier private and must set retention zdr`},
		"anon openrouter":                  {chatJSON, map[string]any{"provider": "openrouter", "api_key_env": "K", "retention": "zdr", "tier": "anon", "owned_by": "V"}, `route "m" is tier anon, and provider openrouter serves chat routes only at tiers [private]`},
		"openrouter private no zdr":        {chatJSON, map[string]any{"provider": "openrouter", "api_key_env": "K"}, `route "m" uses provider openrouter at tier private and must set retention zdr, because every request it sends is held to OpenRouter's zero data retention endpoints`},
		"openrouter without a key":         {chatJSON, map[string]any{"provider": "openrouter", "retention": "zdr"}, `route "m" uses provider openrouter and needs api_key_env`},
		"openrouter online model":          {chatJSON, map[string]any{"provider": "openrouter", "api_key_env": "K", "retention": "zdr", "upstream_model": "deepseek/deepseek-v4.1-flash-1017:online"}, `route "m" uses provider openrouter with upstream_model "deepseek/deepseek-v4.1-flash-1017:online", whose :online suffix runs a web search outside zero data retention`},
		"openrouter image":                 {imageJSON, map[string]any{"provider": "openrouter", "api_key_env": "K", "retention": "zdr", "tier": "private"}, `route "i" is of kind image, which provider openrouter does not serve`},
		"anon venice":                      {chatJSON, map[string]any{"provider": "venice", "api_key_env": "K", "retention": "zdr", "tier": "anon", "owned_by": "V"}, `route "m" is tier anon, and provider venice serves chat routes only at tiers [private]`},
		"anon fireworks":                   {chatJSON, map[string]any{"provider": "fireworks", "api_key_env": "K", "retention": "zdr", "tier": "anon", "owned_by": "V"}, `route "m" is tier anon, and provider fireworks serves chat routes only at tiers [private]`},
		"fireworks private no zdr":         {chatJSON, map[string]any{"provider": "fireworks", "api_key_env": "K"}, `route "m" uses provider fireworks at tier private and must set retention zdr, because Fireworks keeps no prompt or reply of an open model on /chat/completions`},
		"fireworks without a key":          {chatJSON, map[string]any{"provider": "fireworks", "retention": "zdr"}, `route "m" uses provider fireworks and needs api_key_env`},
		"fireworks image":                  {imageJSON, map[string]any{"provider": "fireworks", "api_key_env": "K", "retention": "zdr"}, `route "i" is of kind image, which provider fireworks does not serve`},
		"venice private no zdr":            {chatJSON, map[string]any{"provider": "venice", "api_key_env": "K"}, `route "m" uses provider venice at tier private and must set retention zdr, because Venice keeps no prompt or reply only for the models it serves in its Private mode`},
		"venice without a key":             {chatJSON, map[string]any{"provider": "venice", "retention": "zdr"}, `route "m" uses provider venice and needs api_key_env`},
		"venice video":                     {videoJSON, map[string]any{"provider": "venice", "api_key_env": "K"}, `route "v" is of kind video, which provider venice does not serve`},
		"venice private image":             {imageJSON, map[string]any{"provider": "venice", "api_key_env": "K", "retention": "zdr", "tier": "private"}, `route "i" is tier private, and provider venice serves image routes only at tiers [anon]`},
		"parallel private on vendor terms": {searchJSON, map[string]any{"tier": "private"}, `route "s" uses provider parallel at tier private and must set retention zdr, because its self-serve terms keep queries and pages`},
		"parallel private vendor explicit": {fetchJSON, map[string]any{"tier": "private", "retention": "vendor"}, `route "f" uses provider parallel at tier private and must set retention zdr, because its self-serve terms keep queries and pages`},
		"parallel private research":        {researchJSON, map[string]any{"tier": "private"}, `route "r" uses provider parallel at tier private and must set retention zdr`},
		"anthropic without a key":          {chatJSON, withRates(efforts("anthropic", []string{}), map[string]any{"api_key_env": nil}), `route "m" uses provider anthropic and needs api_key_env`},
		"xai without a key":                {chatJSON, map[string]any{"provider": "xai", "retention": "zdr"}, `route "m" uses provider xai and needs api_key_env`},
		"responses without a key":          {chatJSON, withRates(efforts("openai-responses", []string{}), map[string]any{"api_key_env": nil}), `route "m" uses provider openai-responses and needs api_key_env`},
		"fal without a key":                {imageJSON, map[string]any{"api_key_env": nil}, `route "i" uses provider fal and needs api_key_env`},
		"runware without a key":            {imageJSON, map[string]any{"provider": "runware", "upstream_model": "bfl:5@1", "api_key_env": nil}, `route "i" uses provider runware and needs api_key_env`},
		"parallel without a key":           {searchJSON, map[string]any{"api_key_env": nil}, `route "s" uses provider parallel and needs api_key_env`},
		"runware chat":                     {chatJSON, anon("runware", nil), `route "m" is of kind chat, which provider runware does not serve`},
		"fal chat":                         {chatJSON, anon("fal", nil), `route "m" is of kind chat, which provider fal does not serve`},
		"parallel chat":                    {chatJSON, anon("parallel", nil), `route "m" is of kind chat, which provider parallel does not serve`},
		"openai image":                     {imageJSON, map[string]any{"provider": nil}, `route "i" is of kind image, which provider openai does not serve`},
		"parallel image":                   {imageJSON, map[string]any{"provider": "parallel"}, `route "i" is of kind image, which provider parallel does not serve`},
		"responses image":                  {imageJSON, map[string]any{"provider": "openai-responses"}, `route "i" is of kind image, which provider openai-responses does not serve`},
		"responses video":                  {videoJSON, map[string]any{"provider": "openai-responses"}, `route "v" is of kind video, which provider openai-responses does not serve`},
		"search on openai":                 {searchJSON, map[string]any{"provider": nil}, `route "s" is of kind search, which provider openai does not serve`},
		"search on responses":              {searchJSON, map[string]any{"provider": "openai-responses"}, `route "s" is of kind search, which provider openai-responses does not serve`},
		"fetch on runware":                 {fetchJSON, map[string]any{"provider": "runware"}, `route "f" is of kind fetch, which provider runware does not serve`},
		"fetch on anthropic":               {fetchJSON, map[string]any{"provider": "anthropic"}, `route "f" is of kind fetch, which provider anthropic does not serve`},
		"research on xai":                  {researchJSON, map[string]any{"provider": "xai"}, `route "r" is of kind research, which provider xai does not serve`},
		"transcription on parallel":        {speechJSON, map[string]any{"provider": "parallel"}, `route "w" is of kind transcription, which provider parallel does not serve`},
		"transcription on responses":       {speechJSON, map[string]any{"provider": "openai-responses"}, `route "w" is of kind transcription, which provider openai-responses does not serve`},
		"transcription unpriced":           {speechJSON, map[string]any{"price": map[string]any{}}, `route "w" of kind transcription needs price.micros_per_call`},
		"anthropic none":                   {chatJSON, efforts("anthropic", []string{"none", "low"}), `route "m" uses provider anthropic, whose API has no effort "none"`},
		"gemini none":                      {chatJSON, efforts("gemini", []string{"none", "low"}), `route "m" uses provider gemini, whose API has no effort "none"`},
		"gemini xhigh":                     {chatJSON, efforts("gemini", []string{"low", "high", "xhigh"}), `route "m" uses provider gemini, whose API has no effort "xhigh"`},
		"gemini max":                       {chatJSON, efforts("gemini", []string{"high", "max"}), `route "m" uses provider gemini, whose API has no effort "max"`},
		"gemini private":                   {chatJSON, map[string]any{"provider": "gemini", "api_key_env": "K", "reasoning_efforts": []string{}}, `route "m" is tier private, and provider gemini serves chat routes only at tiers [anon]`},
		"gemini private image":             {imageJSON, map[string]any{"provider": "gemini", "upstream_model": "gemini-3-pro-image", "tier": "private"}, `route "i" is tier private, and provider gemini serves image routes only at tiers [anon]`},
		"gemini video":                     {videoJSON, map[string]any{"provider": "gemini"}, `route "v" is of kind video, which provider gemini does not serve`},
		"gemini without a key":             {imageJSON, map[string]any{"provider": "gemini", "upstream_model": "gemini-3-pro-image", "api_key_env": nil}, `route "i" uses provider gemini and needs api_key_env`},
		"gemini that hides nothing":        {chatJSON, efforts("gemini", []string{"low", "high"}), `route "m" uses provider gemini, which keeps a model's reasoning from the client, and must set hides_reasoning`},
		"unknown effort":                   {chatJSON, efforts("anthropic", []string{"low", "turbo"}), `route "m" reasoning_efforts must name each of none, minimal, low, medium, high, xhigh, max at most once, in that order`},
		"repeated effort":                  {chatJSON, efforts("anthropic", []string{"low", "low"}), `route "m" reasoning_efforts must name each of none, minimal, low, medium, high, xhigh, max at most once, in that order`},
		"efforts out of order":             {chatJSON, efforts("anthropic", []string{"high", "low"}), `route "m" reasoning_efforts must name each of none, minimal, low, medium, high, xhigh, max at most once, in that order`},
		"phala e2ee renamed":               {chatJSON, map[string]any{"tier": "e2ee", "attester": "phala"}, `route "m" is tier e2ee, so model must equal upstream_model "up/m": the body is forwarded verbatim and its receipt binds model`},
	} {
		if _, err := parse(patched(t, c.base, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	flash := efforts("gemini", []string{"minimal", "low", "medium", "high"})
	flash["hides_reasoning"], flash["hidden_reasoning_tps"], flash["decode_max_tps"] = true, 250, 450
	if _, err := parse(patched(t, chatJSON, flash)); err != nil {
		t.Errorf("gemini takes its four thinking levels: %v", err)
	}
	responses := efforts("openai-responses", []string{"none", "low"})
	responses["hides_reasoning"], responses["hidden_reasoning_tps"], responses["decode_max_tps"] = true, 100, 150
	if _, err := parse(patched(t, chatJSON, responses)); err != nil {
		t.Errorf("the responses API takes effort none: %v", err)
	}
	if _, err := parse(patched(t, researchJSON, map[string]any{"tier": "private", "retention": "zdr"})); err != nil {
		t.Errorf("parallel research at private with zdr: %v", err)
	}
}

func TestEveryProviderARouteCanNameServesSomeKind(t *testing.T) {
	for i := range providerNames {
		if p := Provider(i); providerNames.Valid(p) && len(capabilities[p].kinds) == 0 {
			t.Errorf("provider %s parses from a routes file but serves nothing", p)
		}
	}
	for _, p := range Providers() {
		if !providerNames.Valid(p) {
			t.Errorf("capability %d names no provider", p)
		}
	}
}

func TestEveryUpstreamServesAKindOnlyAtTiersTheTierTableServesItAt(t *testing.T) {
	served := map[string]capability{}
	for _, v := range attester.Vendors() {
		served["attester "+v.Name] = attestedCapability(v)
	}
	for _, p := range Providers() {
		served[p.String()] = capabilities[p]
	}
	for name, c := range served {
		for kind, tiers := range c.kinds {
			for _, tier := range tiers {
				if !tier.Serves(kind) {
					t.Errorf("%s serves %s at tier %s, which the tier table does not serve it at", name, kind, tier)
				}
			}
		}
	}
	for v, want := range map[*attester.Vendor]servedAt{
		attester.Phala: {catalog.KindChat: {catalog.TEE, catalog.E2EE}},
		attester.Near:  {catalog.KindChat: {catalog.E2EE}, catalog.KindTranscription: {catalog.TEE}},
	} {
		if got := attestedCapability(v).kinds; !maps.EqualFunc(got, want, slices.Equal) {
			t.Errorf("attester %s serves %v, want %v", v, got, want)
		}
	}
}

func TestALabelIsRequiredAndNamesNoTier(t *testing.T) {
	for name, label := range map[string]any{
		"no label":        nil,
		"empty label":     "",
		"blank label":     "  ",
		"e2ee in parens":  "GLM 5.3 (E2EE)",
		"bare tee":        "GLM 5.3 Flash TEE",
		"lowercase tee":   "glm 5.3 (tee)",
		"leading e2ee":    "E2EE Kimi K2.6",
		"hyphenated tier": "Kimi K3-TEE",
	} {
		_, err := parse(patched(t, chatJSON, map[string]any{"label": label}))
		if err == nil || !strings.Contains(err.Error(), `route "m"`) || !strings.Contains(err.Error(), "label") {
			t.Errorf("%s: err %v, want a refusal naming route \"m\" and its label", name, err)
		}
	}
	for _, ok := range []string{"DeepSeek V4 Flash 0731", "Steep Teeth", "Qwen3.8 27B"} {
		if rts, err := parse(patched(t, chatJSON, map[string]any{"label": ok})); err != nil || rts[0].Label != ok {
			t.Errorf("%q: %+v %v", ok, rts, err)
		}
	}
}

func TestABaseURLIsHTTPSExceptOnLoopbackBelowTEEAndCarriesNothingButAnOriginAndPath(t *testing.T) {
	for _, ok := range []string{"https://api.together.xyz", "https://vllm.internal:8443/v1", "http://localhost:8000", "http://127.0.0.1:9", "http://[::1]:8000"} {
		if rts, err := parse(patched(t, chatJSON, map[string]any{"base_url": ok})); err != nil || rts[0].BaseURL != ok {
			t.Errorf("%s: %+v %v", ok, rts, err)
		}
	}
	for bad, why := range map[string]string{
		"http://vllm:8000":                 "https",
		"http://10.0.0.5:8000":             "https",
		"http://127.0.0.1.example.com":     "https",
		"ftp://api.together.xyz":           "https",
		"https://user:pw@api.together.xyz": "credentials",
		"http://user@localhost:8000":       "credentials",
		"https://api.together.xyz?key=sk":  "query",
		"https://api.together.xyz?":        "query",
		"https://api.together.xyz#v1":      "fragment",
		"https://api.together.xyz#":        "fragment",
		"https:///v1":                      "absolute",
	} {
		if _, err := parse(patched(t, chatJSON, map[string]any{"base_url": bad})); err == nil || !strings.Contains(err.Error(), `route "m" base_url`) || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: err %v, want one naming route \"m\" base_url and %q", bad, err, why)
		}
	}
	for name, c := range map[string]struct {
		patch map[string]any
		says  string
	}{
		"tee over http":          {map[string]any{"tier": "tee", "attester": "phala", "base_url": "http://u"}, `route "m" base_url must use https`},
		"e2ee over http":         {map[string]any{"tier": "e2ee", "attester": "phala", "base_url": "http://u", "model": "up/m"}, `route "up/m" base_url must use https`},
		"tee over loopback http": {map[string]any{"tier": "tee", "attester": "phala", "base_url": "http://127.0.0.1:8000"}, `route "m" is tier tee and needs an https base_url`},
	} {
		if _, err := parse(patched(t, chatJSON, c.patch)); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: err %v, want %q", name, err, c.says)
		}
	}
}

func TestAnAttestedRouteMustNameItsAttesterAndNoOtherRouteMay(t *testing.T) {
	for name, c := range map[string]struct {
		patch map[string]any
		says  string
	}{
		"a tee route with no attester":     {map[string]any{"tier": "tee"}, "must name its attester"},
		"an e2ee route with no attester":   {map[string]any{"tier": "e2ee", "model": "up/m"}, "must name its attester"},
		"a tee route with an empty string": {map[string]any{"tier": "tee", "attester": ""}, "must name its attester"},
		"a tee route with an unknown one":  {map[string]any{"tier": "tee", "attester": "acme"}, `unknown attester "acme"`},
		"a private route naming one":       {map[string]any{"attester": "phala"}, "takes no attester"},
		"an anon route naming one":         {map[string]any{"tier": "anon", "owned_by": "V", "attester": "phala"}, "takes no attester"},
	} {
		if _, err := parse(patched(t, chatJSON, c.patch)); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: err %v, want one saying %q", name, err, c.says)
		}
	}
}

func TestAChatRouteNamesWhatItsModelReadsAndNoOtherKindMay(t *testing.T) {
	reads := func(file []byte) catalog.Inputs {
		t.Helper()
		rts, err := parse(file)
		if err != nil {
			t.Fatal(err)
		}
		return rts[0].Serves.(Chat).Inputs
	}
	if in := reads([]byte(`[` + chatJSON + `]`)); !in.TextOnly() {
		t.Errorf("a route without input_modalities reads %s, want text only", in)
	}
	if in := reads(patched(t, chatJSON, map[string]any{"input_modalities": []string{"text"}})); !in.TextOnly() {
		t.Errorf(`["text"] reads %s`, in)
	}
	if in := reads(patched(t, chatJSON, map[string]any{"input_modalities": []string{"text", "image"}})); !in.Reads(catalog.ModalityImage) {
		t.Errorf(`["text","image"] reads %s`, in)
	}
	phala := func(tier string) string {
		return strings.Replace(chatJSON, `"tier":"private"`, `"tier":"`+tier+`","attester":"phala"`, 1)
	}
	if in := reads(patched(t, phala("tee"), map[string]any{"input_modalities": []string{"text", "image"}})); !in.Reads(catalog.ModalityImage) {
		t.Errorf("a tee route with image reads %s", in)
	}
	if in := reads(patched(t, phala("e2ee"), map[string]any{"model": "up/m", "input_modalities": []string{"text", "image"}})); !in.Reads(catalog.ModalityImage) {
		t.Errorf("an e2ee route with image reads %s", in)
	}
	image := map[string]any{"input_modalities": []string{"text", "image"}}
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  string
	}{
		"unknown modality":    {chatJSON, map[string]any{"input_modalities": []string{"text", "audio"}}, `route "m" input_modalities names "audio", and each must be one of text, image`},
		"repeated modality":   {chatJSON, map[string]any{"input_modalities": []string{"text", "image", "image"}}, `route "m" input_modalities names image twice`},
		"list without text":   {chatJSON, map[string]any{"input_modalities": []string{"image"}}, `route "m" input_modalities must include text`},
		"empty list":          {chatJSON, map[string]any{"input_modalities": []string{}}, `route "m" input_modalities must include text`},
		"not a list":          {chatJSON, map[string]any{"input_modalities": "image"}, `route "m" of kind chat: json: cannot unmarshal string`},
		"on an image route":   {imageJSON, image, `route "i" of kind image: json: unknown field "input_modalities"`},
		"on a video route":    {videoJSON, image, `route "v" of kind video: json: unknown field "input_modalities"`},
		"on a search route":   {searchJSON, image, `route "s" of kind search: json: unknown field "input_modalities"`},
		"on a fetch route":    {fetchJSON, image, `route "f" of kind fetch: json: unknown field "input_modalities"`},
		"on a research route": {researchJSON, image, `route "r" of kind research: json: unknown field "input_modalities"`},
	} {
		if _, err := parse(patched(t, c.base, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestATokenizerAndHiddenReasoningAreDeclaredOnlyWhereTheProxyCanUseThem(t *testing.T) {
	anon := func(provider string, more map[string]any) map[string]any {
		return withRates(map[string]any{"provider": provider, "tier": "anon", "owned_by": "O", "api_key_env": "K"}, more)
	}
	for name, c := range map[string]struct {
		patch map[string]any
		want  string
	}{
		"tokenizer on a tee route":               {map[string]any{"tier": "tee", "attester": "phala", "tokenizer": "glm-5"}, `route "m" names a tokenizer, but attester phala relays its stream verbatim`},
		"tokenizer on an e2ee route":             {map[string]any{"tier": "e2ee", "attester": "phala", "model": "up/m", "default_max_tokens": 16384, "tokenizer": "glm-5"}, `names a tokenizer, but attester phala relays its stream verbatim`},
		"hidden reasoning undeclared":            {anon("anthropic", map[string]any{"reasoning_efforts": []string{"low"}}), `route "m" uses provider anthropic, which keeps a model's reasoning from the client, and must set hides_reasoning`},
		"xai undeclared":                         {map[string]any{"provider": "xai", "retention": "zdr", "api_key_env": "K", "reasoning_efforts": []string{"low"}}, `route "m" uses provider xai, which keeps a model's reasoning from the client, and must set hides_reasoning`},
		"declared on a model that cannot reason": {anon("anthropic", map[string]any{"reasoning_efforts": []string{}, "hides_reasoning": true}), `route "m" sets hides_reasoning, but provider anthropic streams whatever reasoning the model does`},
		"declared on a streaming provider":       {map[string]any{"hides_reasoning": true}, `route "m" sets hides_reasoning, but provider openai streams whatever reasoning the model does`},
		"declared on an attested route":          {map[string]any{"tier": "tee", "attester": "phala", "hides_reasoning": true}, `route "m" sets hides_reasoning, but attester phala streams whatever reasoning the model does`},
	} {
		if _, err := parse(patched(t, chatJSON, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	rs, err := parse(patched(t, chatJSON, map[string]any{"tokenizer": "glm-5"}))
	if err != nil {
		t.Fatal(err)
	}
	if c := rs[0].Serves.(Chat); c.Tokenizer != "glm-5" || c.HidesReasoning {
		t.Errorf("parsed %+v, want tokenizer glm-5 showing its reasoning", c)
	}
}

func TestAModelThatReasonsUnaskedStopsOnlyForAnEffortOfNoneTheRouteLists(t *testing.T) {
	for name, c := range map[string]struct {
		provider Provider
		efforts  []string
		want     chat.Reasoning
	}{
		"responses listing none":    {ProviderOpenAIResponses, []string{"none", "low", "high"}, chat.ReasonsUnlessNone},
		"responses without none":    {ProviderOpenAIResponses, []string{"low", "high"}, chat.ReasonsAlways},
		"gemini":                    {ProviderGemini, []string{"low", "medium", "high"}, chat.ReasonsAlways},
		"xai forwarding as sent":    {ProviderXAI, nil, chat.ReasonsAlways},
		"anthropic":                 {ProviderAnthropic, []string{"low", "high"}, chat.ReasonsWhenAsked},
		"openai forwarding as sent": {ProviderOpenAI, nil, chat.ReasonsWhenAsked},
	} {
		if got := c.provider.Reasoning(c.efforts); got != c.want {
			t.Errorf("%s: reasoning %d, want %d", name, got, c.want)
		}
	}
	for _, p := range Providers() {
		if c := capabilities[p]; c.reasonsUnasked && !c.hides {
			t.Errorf("%s reasons unasked but streams its reasoning, which no route bills as hidden", p)
		}
	}
}

func TestARouteThatHidesReasoningDeclaresAMeasuredThinkingRateWithinItsDecodeBound(t *testing.T) {
	hiding := func(more map[string]any) map[string]any {
		return withRates(map[string]any{"provider": "anthropic", "tier": "anon", "owned_by": "O", "api_key_env": "K", "reasoning_efforts": []string{"low"}, "hides_reasoning": true}, more)
	}
	for name, c := range map[string]struct {
		patch map[string]any
		want  string
	}{
		"no rate":               {hiding(map[string]any{"decode_max_tps": 150}), `route "m" sets hides_reasoning and needs a positive hidden_reasoning_tps and decode_max_tps, both measured`},
		"no decode bound":       {hiding(map[string]any{"hidden_reasoning_tps": 100}), `route "m" sets hides_reasoning and needs a positive hidden_reasoning_tps and decode_max_tps, both measured`},
		"rate past the bound":   {hiding(map[string]any{"hidden_reasoning_tps": 160, "decode_max_tps": 150}), `route "m" sets hidden_reasoning_tps 160 above its decode_max_tps 150`},
		"rate without hiding":   {map[string]any{"hidden_reasoning_tps": 100}, `route "m" sets hidden_reasoning_tps without hides_reasoning`},
		"decode without either": {map[string]any{"decode_max_tps": 100}, `route "m" sets decode_max_tps, which only a route that sets hides_reasoning takes`},
		"rate on a tee route":   {map[string]any{"tier": "tee", "attester": "phala", "hidden_reasoning_tps": 100}, `route "m" sets hidden_reasoning_tps without hides_reasoning`},
	} {
		if _, err := parse(patched(t, chatJSON, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	rs, err := parse(patched(t, chatJSON, hiding(map[string]any{"hidden_reasoning_tps": 100, "decode_max_tps": 150})))
	if err != nil {
		t.Fatal(err)
	}
	if got := rs[0].Serves.(Chat).ThinkingTerms(); got != (measure.ThinkingTerms{Seed: 100, DecodeMax: 150}) {
		t.Errorf("thinking terms %+v, want the seed 100 under the bound 150", got)
	}
}

func TestASealedRouteListsFallbackVendorsThatServeItsTermsUnderTheirOwnAttesterHostAndKey(t *testing.T) {
	const sealed = `{"model":"z/m","label":"M","tier":"e2ee","attester":"near","base_url":"https://cloud-api.near.ai","api_key_env":"NEAR_API_KEY","upstream_model":"z/m",` + tokenPriced
	phala := `{"attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY"}`
	withFallbacks := func(route string, fallbacks ...string) string {
		return route + `,"fallbacks":[` + strings.Join(fallbacks, ",") + `]}`
	}
	rts, err := parse([]byte(`[` + withFallbacks(sealed, phala) + `]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rts) != 1 || len(rts[0].Fallbacks) != 1 {
		t.Fatalf("one route with one fallback, got %+v", rts)
	}
	primary, fb := rts[0], rts[0].Fallbacks[0]
	if fb.Upstream != (Attested{Attester: attester.Phala}) || fb.Host != "inference.phala.com" || fb.APIKeyEnv != "PHALA_API_KEY" || fb.BaseURL != "https://inference.phala.com" {
		t.Errorf("fallback vendor: %+v", fb)
	}
	if fb.Model != primary.Model || fb.UpstreamModel != primary.UpstreamModel || fb.Tier != primary.Tier || fb.Label != primary.Label || !reflect.DeepEqual(fb.Serves, primary.Serves) || fb.Fallbacks != nil {
		t.Errorf("fallback terms %+v differ from the route's %+v", fb, primary)
	}
	if ups := primary.Upstreams(); len(ups) != 2 || ups[0].Host != "cloud-api.near.ai" || ups[1].Host != "inference.phala.com" {
		t.Errorf("upstreams in order: %+v", ups)
	}

	for name, c := range map[string]struct{ file, want string }{
		"on tier tee":                        {`[` + withFallbacks(strings.Replace(strings.Replace(sealed, `"tier":"e2ee"`, `"tier":"tee"`, 1), `"attester":"near"`, `"attester":"phala"`, 1), `{"attester":"near","base_url":"https://cloud-api.near.ai"}`) + `]`, `route "z/m" is tier tee and takes no fallbacks`},
		"on tier private":                    {`[` + strings.TrimSuffix(chatJSON, `}`) + `,"fallbacks":[` + phala + `]}]`, `route "m" is tier private and takes no fallbacks`},
		"naming the route's own attester":    {`[` + withFallbacks(sealed, `{"attester":"near","base_url":"https://other.near.ai"}`) + `]`, `route "z/m" names attester near twice`},
		"naming one attester twice":          {`[` + withFallbacks(sealed, phala, phala) + `]`, `route "z/m" names attester phala twice`},
		"naming its own upstream_model":      {`[` + withFallbacks(sealed, `{"attester":"phala","base_url":"https://inference.phala.com","upstream_model":"z/m"}`) + `]`, `json: unknown field "upstream_model"`},
		"with an unknown attester":           {`[` + withFallbacks(sealed, `{"attester":"acme","base_url":"https://acme.example"}`) + `]`, `fallback "acme": route "z/m" unknown attester "acme"`},
		"failing the vendor's own check":     {`[` + withFallbacks(sealed, `{"attester":"phala","base_url":"http://inference.phala.com"}`) + `]`, `fallback "phala": route "z/m" base_url must use https`},
		"on a host another attester gates":   {`[` + withFallbacks(sealed, `{"attester":"phala","base_url":"https://cloud-api.near.ai/phala"}`) + `]`, `share host cloud-api.near.ai but name attesters near and phala`},
		"beside another object of the model": {`[` + withFallbacks(sealed, phala) + `,` + strings.Replace(sealed, `"attester":"near","base_url":"https://cloud-api.near.ai"`, `"attester":"phala","base_url":"https://inference.phala.com"`, 1) + `}]`, `route 1 repeats model "z/m"`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	if _, err := parse([]byte(`[` + strings.TrimSuffix(imageJSON, `}`) + `,"fallbacks":[]}]`)); err == nil || !strings.Contains(err.Error(), `json: unknown field "fallbacks"`) {
		t.Errorf("an image route with fallbacks: %v", err)
	}
}

func TestEveryChatRouteOfEveryUpstreamAndTierListsItsEfforts(t *testing.T) {
	efforts := []string{"none", "low", "high"}
	for name, patch := range map[string]map[string]any{
		"openai":     {},
		"openrouter": {"provider": "openrouter", "retention": "zdr", "api_key_env": "K"},
		"venice":     {"provider": "venice", "retention": "zdr", "api_key_env": "K"},
		"fireworks":  {"provider": "fireworks", "retention": "zdr", "api_key_env": "K"},
		"xai":        {"provider": "xai", "retention": "zdr", "api_key_env": "K", "hides_reasoning": true, "hidden_reasoning_tps": 1, "decode_max_tps": 1},
		"phala tee":  {"tier": "tee", "attester": "phala"},
		"phala e2ee": {"tier": "e2ee", "attester": "phala", "model": "up/m"},
	} {
		patch["reasoning_efforts"] = efforts
		rts, err := parse(patched(t, chatJSON, patch))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c, _ := ChatOf(rts[0].Serves); !slices.Equal(c.ReasoningEfforts, efforts) {
			t.Errorf("%s: reasoning_efforts %v, want %v", name, c.ReasoningEfforts, efforts)
		}
	}
}

func TestAChatRouteNamesItsOpenRouterModelOrTakesItsUpstreamModel(t *testing.T) {
	for name, tc := range map[string]struct {
		patch map[string]any
		want  string
	}{
		"unset":   {nil, "up/m"},
		"setting": {map[string]any{"openrouter_id": "vendor/m"}, "vendor/m"},
	} {
		rs, err := parse(patched(t, chatJSON, tc.patch))
		if err != nil {
			t.Fatal(err)
		}
		if got := rs[0].Serves.(Chat).OpenRouterID; got != tc.want {
			t.Errorf("%s: OpenRouterID %q, want %q", name, got, tc.want)
		}
	}
	if _, err := parse(patched(t, imageJSON, map[string]any{"openrouter_id": "vendor/m"})); err == nil {
		t.Error("an image route took openrouter_id")
	}
}

func TestARouteHedgesUnlessItIsAttestedOrItsProviderIsSilentWhileReasoningOrSlowsTogether(t *testing.T) {
	anon := func(provider string) map[string]any {
		return withRates(map[string]any{"provider": provider, "tier": "anon", "owned_by": "O", "api_key_env": "K"}, nil)
	}
	for name, c := range map[string]struct {
		patch map[string]any
		want  bool
	}{
		"openai":    {map[string]any{}, true},
		"anthropic": {anon("anthropic"), false},
		"responses": {anon("openai-responses"), true},
		"gemini":    {anon("gemini"), false},
		"xai":       {map[string]any{"provider": "xai", "retention": "zdr", "api_key_env": "K"}, true},
	} {
		rts, err := parse(patched(t, chatJSON, c.patch))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := rts[0].Hedgeable(); got != c.want {
			t.Errorf("%s: Hedgeable %t, want %t", name, got, c.want)
		}
	}
	tee := strings.Replace(chatJSON, `"tier":"private"`, `"tier":"tee","attester":"phala"`, 1)
	rts, err := parse([]byte(`[` + tee + `]`))
	if err != nil {
		t.Fatal(err)
	}
	if rts[0].Hedgeable() {
		t.Error("an attested plaintext route hedges")
	}
}
