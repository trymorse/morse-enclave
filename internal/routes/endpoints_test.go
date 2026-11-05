package routes

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/catalog"
)

const (
	modelTerms   = `"label":"M","reasoning_efforts":[]`
	windowPriced = `"price":{"prompt_micros_per_mtok":150000,"cached_prompt_micros_per_mtok":15000,"completion_micros_per_mtok":600000},"max_output_tokens":16384,"default_max_tokens":16384,"context_tokens":131072`
	togetherEP   = `{"id":"together","tier":"private","base_url":"https://u","upstream_model":"up/m",` + windowPriced + `}`
	phalaTEEEP   = `{"id":"phala-tee","tier":"tee","attester":"phala","base_url":"https://inference.phala.com","upstream_model":"z/m",` + windowPriced + `}`
	nearEP       = `{"id":"near","tier":"e2ee","attester":"near","base_url":"https://cloud-api.near.ai","api_key_env":"NEAR_API_KEY","upstream_model":"z/m",` + windowPriced + `}`
	phalaEP      = `{"id":"phala","tier":"e2ee","attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY","upstream_model":"z/m",` + windowPriced + `}`
	tinfoilEP    = `{"id":"tinfoil","tier":"e2ee","attester":"tinfoil","base_url":"https://inference.tinfoil.sh","api_key_env":"TINFOIL_API_KEY","upstream_model":"z/m",` + windowPriced + `}`
	twoAliases   = `{"name":"m","model":"z/m","endpoint":"together"},{"name":"m-tee","model":"z/m","endpoint":"phala-tee"}`
)

func modelsFileOf(model, aliases string) string {
	return `{"models":[` + model + `],"aliases":[` + aliases + `]}`
}

func modelOf(endpoints ...string) string {
	return `{"id":"z/m",` + modelTerms + `,"endpoints":[` + strings.Join(endpoints, ",") + `]}`
}

func routeOf(name, endpoint string) string {
	_, rest, _ := strings.Cut(endpoint, ",")
	return `{"model":"` + name + `",` + modelTerms + `,` + rest
}

func TestAModelsObjectLoadsAsTheArrayOfOneRoutePerEndpointUnderItsAliasWithLaterSealedEndpointsAsFallbacks(t *testing.T) {
	object, err := parse([]byte(modelsFileOf(modelOf(togetherEP, phalaTEEEP, nearEP, phalaEP), twoAliases)))
	if err != nil {
		t.Fatal(err)
	}
	sealed := strings.TrimSuffix(routeOf("z/m", nearEP), "}") + `,"fallbacks":[{"attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY"}]}`
	array, err := parse([]byte(`[` + routeOf("m", togetherEP) + `,` + routeOf("m-tee", phalaTEEEP) + `,` + sealed + `]`))
	if err != nil {
		t.Fatal(err)
	}
	served := [][]catalog.EndpointID{}
	for i := range object {
		var ids []catalog.EndpointID
		for j, vendor := range object[i].Upstreams() {
			if vendor.ID != "z/m" {
				t.Errorf("route %q vendor %d is of model %q, want z/m", object[i].Model, j, vendor.ID)
			}
			ids = append(ids, vendor.Endpoint)
		}
		served = append(served, ids)
	}
	if want := [][]catalog.EndpointID{{"together"}, {"phala-tee"}, {"near", "phala"}}; !reflect.DeepEqual(served, want) {
		t.Errorf("the object's routes serve endpoints %v, want %v", served, want)
	}
	if !reflect.DeepEqual(unidentified(object), unidentified(array)) {
		t.Errorf("the object loads as\n%+v\nand its array as\n%+v", object, array)
	}

	qwen := strings.NewReplacer(`"id":"z/m"`, `"id":"z/q"`, `"id":"near",`, `"id":"near","sealed_model":"Z/Q",`, `"upstream_model":"z/m"`, `"upstream_model":"Z/Q"`).Replace(modelOf(nearEP))
	rts, err := parse([]byte(modelsFileOf(qwen, `{"name":"Z/Q","model":"z/q","endpoint":"near"}`)))
	if err != nil || len(rts) != 1 || rts[0].Model != "Z/Q" {
		t.Errorf("a sealed endpoint whose body names the model in another case serves under its alias: %+v %v", rts, err)
	}
}

func unidentified(rts []Route) []Route {
	out := make([]Route, len(rts))
	for i, rt := range rts {
		rt.ID, rt.Endpoint = "", ""
		rt.Fallbacks = unidentified(rt.Fallbacks)
		out[i] = rt
	}
	return out
}

func TestAnArrayRouteIsAModelOfItsOwnNameWhoseEndpointsAreNamedByAttesterOrTier(t *testing.T) {
	sealed := strings.TrimSuffix(routeOf("z/m", nearEP), "}") + `,"fallbacks":[{"attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY"}]}`
	rts, err := parse([]byte(`[` + routeOf("m", togetherEP) + `,` + sealed + `]`))
	if err != nil {
		t.Fatal(err)
	}
	if rts[0].ID != "m" || rts[0].Endpoint != "private" || rts[1].ID != "z/m" || rts[1].Endpoint != "near" || rts[1].Fallbacks[0].ID != "z/m" || rts[1].Fallbacks[0].Endpoint != "phala" {
		t.Errorf("the array routes are %+v", rts)
	}
}

func TestAModelsObjectThatBreaksARuleIsRefusedNamingTheRule(t *testing.T) {
	one := modelOf(togetherEP)
	for name, c := range map[string]struct{ file, want string }{
		"no models":                         {`{"models":[],"aliases":[]}`, "routes file has no models"},
		"an unknown top-level field":        {`{"models":[` + one + `],"groups":{}}`, `json: unknown field "groups"`},
		"an unknown alias field":            {modelsFileOf(one, `{"name":"m","model":"z/m","endpoint":"together","min_privacy":"private"}`), `json: unknown field "min_privacy"`},
		"a model id with capitals":          {modelsFileOf(strings.Replace(one, `"z/m"`, `"Z/M"`, 1), ``), `has id "Z/M"; a model id is lab/model in lowercase`},
		"a model id without a lab":          {modelsFileOf(strings.Replace(one, `"z/m"`, `"m"`, 1), ``), `has id "m"`},
		"a model with no endpoints":         {modelsFileOf(modelOf(), ``), `model "z/m" lists no endpoints`},
		"a model listed twice":              {`{"models":[` + one + `,` + one + `]}`, `model "z/m" is listed twice`},
		"a model setting an endpoint field": {modelsFileOf(strings.Replace(one, `"label":"M"`, `"label":"M","tier":"private"`, 1), ``), `model "z/m" sets "tier"`},
		"an endpoint setting a model field": {modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, `"label":"N","tier"`, 1)), ``), `model "z/m" endpoint "together" sets "label", which is not an endpoint field`},
		"an endpoint naming its route":      {modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, `"model":"m","tier"`, 1)), ``), `endpoint "together" sets "model"`},
		"an endpoint listing fallbacks":     {modelsFileOf(modelOf(strings.Replace(nearEP, `"tier"`, `"fallbacks":[],"tier"`, 1)), ``), `endpoint "near" sets "fallbacks"`},
		"an unknown endpoint field":         {modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, `"colour":"red","tier"`, 1)), ``), `json: unknown field "colour"`},
		"an endpoint id with capitals":      {modelsFileOf(modelOf(strings.Replace(togetherEP, `"together"`, `"Together"`, 1)), ``), `an endpoint with id "Together"`},
		"an endpoint listed twice":          {modelsFileOf(modelOf(togetherEP, togetherEP), ``), `model "z/m" lists endpoint "together" twice`},
		"two endpoints under the model id":  {modelsFileOf(modelOf(togetherEP, phalaTEEEP), ``), `endpoints "together" and "phala-tee" both have no alias`},
		"an alias listed twice":             {modelsFileOf(one, `{"name":"m","model":"z/m","endpoint":"together"},{"name":"m","model":"z/m","endpoint":"together"}`), `alias "m" is listed twice`},
		"an alias that is a model id":       {modelsFileOf(one, `{"name":"z/m","model":"z/m","endpoint":"together"}`), `alias "z/m" is a model id`},
		"an alias of no model":              {modelsFileOf(one, `{"name":"m","model":"z/n","endpoint":"together"}`), `alias "m" names model "z/n", which the file does not list`},
		"an alias of no endpoint":           {modelsFileOf(one, `{"name":"m","model":"z/m","endpoint":"fal"}`), `alias "m" names endpoint "fal", which model "z/m" does not list`},
		"two aliases of one endpoint":       {modelsFileOf(one, `{"name":"m","model":"z/m","endpoint":"together"},{"name":"n","model":"z/m","endpoint":"together"}`), `aliases "m" and "n" both name endpoint "together"`},
		"an alias of a fallback":            {modelsFileOf(modelOf(nearEP, phalaEP), `{"name":"m","model":"z/m","endpoint":"phala"}`), `alias "m" names endpoint "phala", which serves as a fallback of e2ee endpoint "near"`},
		"a fallback on other terms":         {modelsFileOf(modelOf(nearEP, strings.Replace(phalaEP, `"upstream_model":"z/m"`, `"upstream_model":"z/other"`, 1)), ``), `endpoint "phala" differs from e2ee endpoint "near" in upstream_model`},
		"a fallback that seals otherwise":   {modelsFileOf(modelOf(tinfoilEP, phalaEP), ``), `endpoint "phala" is a fallback of e2ee endpoint "tinfoil", but phala and tinfoil seal requests differently`},
		"a sealed endpoint under an alias":  {modelsFileOf(modelOf(nearEP), `{"name":"m","model":"z/m","endpoint":"near"}`), `endpoint "near" is e2ee and serves as "m", so a sealed body names "m" there; set its sealed_model to "m"`},
		"sealed_model below e2ee":           {modelsFileOf(modelOf(strings.Replace(phalaTEEEP, `"tier"`, `"sealed_model":"z/m","tier"`, 1)), ``), `endpoint "phala-tee" sets sealed_model but is not e2ee`},
		"an empty sealed_model":             {modelsFileOf(modelOf(strings.Replace(nearEP, `"tier"`, `"sealed_model":"","tier"`, 1)), ``), `endpoint "near" has sealed_model "", which must be a non-empty string`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

var testIncludedWindows = []int{100_000, 200_000}

func parseForRelay(data []byte) ([]Route, error) {
	rts, err := parse(data)
	if err != nil {
		return nil, err
	}
	return rts, FailoverOnOneTerm(rts, testIncludedWindows)
}

func TestAModelRefusesEndpointsAChatFailsOverBetweenOnDifferentTerms(t *testing.T) {
	cheaper := strings.Replace(phalaTEEEP, `"prompt_micros_per_mtok":150000`, `"prompt_micros_per_mtok":100000`, 1)
	included := strings.Replace(phalaTEEEP, `"context_tokens":131072`, `"context_tokens":131072,"included":{"from":"free"}`, 1)
	paid := strings.Replace(phalaTEEEP, `"context_tokens":131072`, `"context_tokens":131072,"requires_plan":"pro"`, 1)
	for name, c := range map[string]struct {
		tee, refusal string
	}{
		"a cheaper sibling":           {cheaper, "differ in price"},
		"an included sibling":         {included, "differ in included"},
		"a sibling that needs a plan": {paid, "differ in requires_plan"},
	} {
		_, err := parseForRelay([]byte(modelsFileOf(modelOf(togetherEP, c.tee), twoAliases)))
		if err == nil || !strings.Contains(err.Error(), c.refusal) || !strings.Contains(err.Error(), "give them the same terms") {
			t.Errorf("%s: %v, want a refusal that names %q and the fix", name, err, c.refusal)
		}
	}
	xai := strings.Replace(togetherEP, `"base_url":"https://u"`, `"provider":"xai","base_url":"https://api.x.ai","api_key_env":"XAI_API_KEY","retention":"zdr"`, 1)
	_, err := parseForRelay([]byte(modelsFileOf(modelOf(xai, phalaTEEEP), twoAliases)))
	if err == nil || !strings.Contains(err.Error(), "reasons past the output limit") {
		t.Errorf("a sibling on a provider that reasons past the output limit: %v, want a refusal", err)
	}
	cheaperSealed := strings.Replace(nearEP, `"prompt_micros_per_mtok":150000`, `"prompt_micros_per_mtok":100000`, 1)
	if _, err := parseForRelay([]byte(modelsFileOf(modelOf(togetherEP, phalaTEEEP, cheaperSealed), twoAliases))); err != nil {
		t.Errorf("a cheaper e2ee endpoint, which no plaintext chat fails over to: %v", err)
	}
}

func TestIncludedEndpointsMayDifferInAWindowNoPlanReaches(t *testing.T) {
	in := func(ep, window string) string {
		return strings.Replace(ep, `"context_tokens":131072`, `"context_tokens":`+window+`,"included":{"from":"free"}`, 1)
	}
	if _, err := parseForRelay([]byte(modelsFileOf(modelOf(in(togetherEP, "1048575"), in(phalaTEEEP, "1048576")), twoAliases))); err != nil {
		t.Errorf("windows past every plan's included window: %v", err)
	}
	_, err := parseForRelay([]byte(modelsFileOf(modelOf(in(togetherEP, "32768"), in(phalaTEEEP, "1048576")), twoAliases)))
	if err == nil || !strings.Contains(err.Error(), "context_tokens") {
		t.Errorf("a window smaller than a plan's included window: %v, want a refusal naming context_tokens", err)
	}
}

const fireworksEP = `{"id":"fireworks","unnamed":true,"tier":"private","provider":"fireworks","retention":"zdr","base_url":"https://api.fireworks.ai/inference","api_key_env":"FIREWORKS_API_KEY","upstream_model":"accounts/fireworks/models/m",` + windowPriced + `}`

func TestAnUnnamedEndpointServesBesideItsTiersNamedEndpointAndIsNoRouteOfItsOwn(t *testing.T) {
	together := strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1)
	rts, err := parseForRelay([]byte(modelsFileOf(modelOf(fireworksEP, together, phalaTEEEP), twoAliases)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, rt := range rts {
		names = append(names, rt.Model)
	}
	if !reflect.DeepEqual(names, []string{"m", "m-tee"}) {
		t.Fatalf("the routes are %v, want m and m-tee alone", names)
	}
	m := rts[0]
	if len(m.Unnamed) != 1 {
		t.Fatalf("m has unnamed endpoints %+v, want fireworks", m.Unnamed)
	}
	fw := m.Unnamed[0]
	if fw.Model != "m" || fw.ID != "z/m" || fw.Endpoint != "fireworks" || fw.Tier != catalog.Private || fw.UpstreamModel != "accounts/fireworks/models/m" {
		t.Errorf("the unnamed endpoint loads as %+v, want fireworks of z/m serving under m", fw)
	}
	if fw.Order >= m.Order || m.Order >= rts[1].Order {
		t.Errorf("orders fireworks %d, together %d, phala-tee %d, want the file's order", fw.Order, m.Order, rts[1].Order)
	}
	if got := KeyEnvs(rts); !slices.Contains(got, "FIREWORKS_API_KEY") {
		t.Errorf("the keys %v leave out the unnamed endpoint's", got)
	}
}

const genericEP = `{"id":"other","unnamed":true,"tier":"private","base_url":"https://v","upstream_model":"up/m",` + windowPriced + `}`

func withEffort(ep, effort string) string {
	return strings.Replace(ep, `"context_tokens"`, `"default_reasoning_effort":"`+effort+`","context_tokens"`, 1)
}

func reasoningModelOf(endpoints ...string) string {
	return strings.Replace(modelOf(endpoints...), `"reasoning_efforts":[]`, `"reasoning_efforts":["low","high"]`, 1)
}

func TestAnUnnamedEndpointThatBreaksARuleIsRefusedNamingTheRule(t *testing.T) {
	together := strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1)
	alias := `{"name":"m","model":"z/m","endpoint":"together"}`
	for name, c := range map[string]struct{ file, want string }{
		"alone at its tier":                          {modelsFileOf(modelOf(fireworksEP, phalaTEEEP), `{"name":"m-tee","model":"z/m","endpoint":"phala-tee"}`), `endpoint "fireworks" is unnamed, but no named endpoint of the model serves tier private`},
		"named by an alias":                          {modelsFileOf(modelOf(together, fireworksEP), alias+`,{"name":"fw","model":"z/m","endpoint":"fireworks"}`), `alias "fw" names endpoint "fireworks", which is unnamed`},
		"e2ee":                                       {modelsFileOf(modelOf(nearEP, strings.Replace(phalaEP, `"tier"`, `"unnamed":true,"tier"`, 1)), ``), `endpoint "phala" is unnamed and e2ee`},
		"unnamed false":                              {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"unnamed":true`, `"unnamed":false`, 1)), alias), `endpoint "fireworks" has unnamed false; set it to true or leave it out`},
		"a cheaper unnamed":                          {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"prompt_micros_per_mtok":150000`, `"prompt_micros_per_mtok":100000`, 1)), alias), `endpoints "together" and "fireworks" serve model "z/m" outside e2ee and differ in price`},
		"an unnamed on a plan":                       {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"tier"`, `"requires_plan":"pro","tier"`, 1)), alias), `differ in requires_plan`},
		"a second unaliased name":                    {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"unnamed":true,`, ``, 1)), ``), `a further endpoint at a tier the model already serves can be unnamed`},
		"an unnamed that keeps prompts":              {modelsFileOf(modelOf(together, genericEP), alias), `endpoints "together" and "other" serve model "z/m" at tier private and differ in retention`},
		"an unnamed that reasons at another default": {modelsFileOf(reasoningModelOf(withEffort(together, "high"), withEffort(fireworksEP, "low")), alias), `differ in default_reasoning_effort`},
	} {
		if _, err := parseForRelay([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}
