package routes

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/catalog"
)

const (
	modelTerms = `"label":"M","reasoning_efforts":[]`
	tierPrice  = `{"prompt_micros_per_mtok":150000,"cached_prompt_micros_per_mtok":15000,"completion_micros_per_mtok":600000}`
	windowed   = `"max_output_tokens":16384,"default_max_tokens":16384,"context_tokens":131072`
	togetherEP = `{"id":"together","provider_name":"together","tier":"private","base_url":"https://u","upstream_model":"up/m",` + windowed + `}`
	phalaTEEEP = `{"id":"phala-tee","provider_name":"phala","tier":"tee","attester":"phala","base_url":"https://inference.phala.com","upstream_model":"z/m",` + windowed + `}`
	nearEP     = `{"id":"near","provider_name":"near","tier":"e2ee","attester":"near","base_url":"https://cloud-api.near.ai","api_key_env":"NEAR_API_KEY","upstream_model":"z/m",` + windowed + `}`
	phalaEP    = `{"id":"phala","provider_name":"phala","tier":"e2ee","attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY","upstream_model":"z/m",` + windowed + `}`
	tinfoilEP  = `{"id":"tinfoil","provider_name":"tinfoil","tier":"e2ee","attester":"tinfoil","base_url":"https://inference.tinfoil.sh","api_key_env":"TINFOIL_API_KEY","upstream_model":"z/m",` + windowed + `}`
	twoAliases = `{"name":"m","model":"z/m","endpoint":"together"},{"name":"m-tee","model":"z/m","endpoint":"phala-tee"}`
)

func modelsFileOf(model, aliases string) string {
	return `{"models":[` + model + `],"aliases":[` + aliases + `]}`
}

var tierOfEndpoint = regexp.MustCompile(`"tier":"(\w+)"`)

// modelOf is a model of z/m that sells each tier its endpoints serve at tierPrice.
func modelOf(endpoints ...string) string {
	var tiers []string
	for _, e := range endpoints {
		tier := tierOfEndpoint.FindStringSubmatch(e)[1]
		if !slices.Contains(tiers, `"`+tier+`":`+tierPrice) {
			tiers = append(tiers, `"`+tier+`":`+tierPrice)
		}
	}
	return `{"id":"z/m",` + modelTerms + `,"prices":{` + strings.Join(tiers, ",") + `},"endpoints":[` + strings.Join(endpoints, ",") + `]}`
}

func routeOf(name, endpoint string) string {
	_, rest, _ := strings.Cut(endpoint, ",")
	return `{"model":"` + name + `",` + modelTerms + `,"price":` + tierPrice + `,` + rest
}

func TestAModelsObjectLoadsAsTheArrayOfOneRoutePerEndpointUnderItsAliasWithLaterSealedEndpointsAsFallbacks(t *testing.T) {
	object, err := parse([]byte(modelsFileOf(modelOf(togetherEP, phalaTEEEP, nearEP, phalaEP), twoAliases)))
	if err != nil {
		t.Fatal(err)
	}
	sealed := strings.TrimSuffix(routeOf("z/m", nearEP), "}") + `,"fallbacks":[{"provider_name":"phala","attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY"}]}`
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
	sealed := strings.TrimSuffix(routeOf("z/m", nearEP), "}") + `,"fallbacks":[{"provider_name":"phala","attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY"}]}`
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

func parseForRelay(data []byte) ([]Route, error) { return parseForRelayWith(data, false) }

// parseForRelayWith loads data and runs the relay's check with every provider declaring dry as its dry-account answer.
func parseForRelayWith(data []byte, dry bool) ([]Route, error) {
	rts, err := parse(data)
	if err != nil {
		return nil, err
	}
	return rts, FailoverOnOneTerm(rts, testIncludedWindows, func(Route) bool { return dry })
}

func TestTiersOfOneModelMayDifferInTermsOnlyWhenEveryPlaintextProviderMapsADryAccountToARefusal(t *testing.T) {
	cheaperPrice := strings.Replace(tierPrice, `"prompt_micros_per_mtok":150000`, `"prompt_micros_per_mtok":100000`, 1)
	cheaperTee := strings.Replace(modelOf(togetherEP, phalaTEEEP), `"tee":`+tierPrice, `"tee":`+cheaperPrice, 1)
	included := strings.Replace(phalaTEEEP, `"context_tokens":131072`, `"context_tokens":131072,"included":{"from":"free"}`, 1)
	paid := strings.Replace(phalaTEEEP, `"context_tokens":131072`, `"context_tokens":131072,"requires_plan":"pro"`, 1)
	xai := strings.Replace(togetherEP, `"base_url":"https://u"`, `"provider":"xai","base_url":"https://api.x.ai","api_key_env":"XAI_API_KEY","retention":"zdr"`, 1)
	for name, c := range map[string]struct {
		file, differs string
	}{
		"a tee that sells for less than its private":             {modelsFileOf(cheaperTee, twoAliases), "price or markup"},
		"a tee that is included beside a private that is not":    {modelsFileOf(modelOf(togetherEP, included), twoAliases), "included"},
		"a tee that needs a plan beside a private that does not": {modelsFileOf(modelOf(togetherEP, paid), twoAliases), "requires_plan"},
		"a provider that reasons past the output limit":          {modelsFileOf(modelOf(xai, phalaTEEEP), twoAliases), "reasons past the output limit"},
	} {
		_, err := parseForRelayWith([]byte(c.file), false)
		if err == nil || !strings.Contains(err.Error(), c.differs) || !strings.Contains(err.Error(), "does not map a dry account to an account refusal") {
			t.Errorf("%s, with a provider that declares no dry-account refusal: %v, want a refusal naming %q and the dry account", name, err, c.differs)
		}
		if _, err := parseForRelayWith([]byte(c.file), true); err != nil {
			t.Errorf("%s, with every provider mapping a dry account to a refusal: %v", name, err)
		}
	}
	cheaperSealed := strings.Replace(modelOf(togetherEP, phalaTEEEP, nearEP), `"e2ee":`+tierPrice, `"e2ee":`+cheaperPrice, 1)
	if _, err := parseForRelay([]byte(modelsFileOf(cheaperSealed, twoAliases))); err != nil {
		t.Errorf("a cheaper e2ee endpoint, which no plaintext chat fails over to: %v", err)
	}
}

func TestTwoEndpointsOfOneTierStillAgreeOnEveryTermWhateverTheirProvidersDeclare(t *testing.T) {
	together := strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1)
	for name, other := range map[string]string{
		"a plan":   strings.Replace(fireworksEP, `"tier"`, `"requires_plan":"pro","tier"`, 1),
		"included": strings.Replace(fireworksEP, `"context_tokens":131072`, `"context_tokens":131072,"included":{"from":"free"}`, 1),
	} {
		_, err := parseForRelayWith([]byte(modelsFileOf(modelOf(together, other), `{"name":"m","model":"z/m","endpoint":"together"}`)), true)
		if err == nil || !strings.Contains(err.Error(), "at tier private") {
			t.Errorf("a sibling at the same tier on other %s: %v, want a refusal", name, err)
		}
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

func TestAnIncludedTiersNamedEndpointsShareAWindowAndItsUnnamedBackupMayHaveASmallerOne(t *testing.T) {
	in := func(ep, window string) string {
		return strings.Replace(ep, `"context_tokens":131072`, `"context_tokens":`+window+`,"included":{"from":"free"}`, 1)
	}
	together := in(strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1), "262144")
	backup := in(fireworksEP, "131072")
	if _, err := parseForRelay([]byte(modelsFileOf(modelOf(together, backup), `{"name":"m","model":"z/m","endpoint":"together"}`))); err != nil {
		t.Errorf("an unnamed backup with a window smaller than a plan's included window: %v", err)
	}
	named := strings.Replace(backup, `"unnamed":true,`, ``, 1)
	_, err := parseForRelay([]byte(modelsFileOf(modelOf(together, named), `{"name":"m","model":"z/m","endpoint":"together"},{"name":"m-fw","model":"z/m","endpoint":"fireworks"}`)))
	if err == nil || !strings.Contains(err.Error(), "at tier private") || !strings.Contains(err.Error(), "context_tokens") {
		t.Errorf("a second named endpoint with that window: %v, want a refusal naming context_tokens", err)
	}
}

const fireworksEP = `{"id":"fireworks","provider_name":"fireworks","unnamed":true,"tier":"private","provider":"fireworks","retention":"zdr","base_url":"https://api.fireworks.ai/inference","api_key_env":"FIREWORKS_API_KEY","upstream_model":"accounts/fireworks/models/m",` + windowed + `}`

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

func TestAModelsPricesAreExactlyTheTiersItsEndpointsServeAndAnEndpointSetsNoPrice(t *testing.T) {
	price := tierPrice
	oneTier := func(prices string, endpoints ...string) string {
		return modelsFileOf(`{"id":"z/m",`+modelTerms+`,"prices":{`+prices+`},"endpoints":[`+strings.Join(endpoints, ",")+`]}`, ``)
	}
	media := func(extra string, endpoints ...string) string {
		return `{"models":[{"id":"z/i","kind":"image","label":"I",` + extra + `"endpoints":[` + strings.Join(endpoints, ",") + `]}],"aliases":[]}`
	}
	fal := `{"id":"fal","provider_name":"fal","tier":"anon","owned_by":"V","provider":"fal","base_url":"https://u","upstream_model":"fal-ai/x","api_key_env":"K","price":{"hold_micros_per_image":1}}`
	falTwice := strings.Replace(fal, `"id":"fal"`, `"id":"fal-b"`, 1)
	asPrice := strings.Replace(togetherEP, `"max_output_tokens"`, `"price":`+price+`,"max_output_tokens"`, 1)
	for name, c := range map[string]struct{ file, want string }{
		"a served tier with no price":           {oneTier(`"private":`+price, togetherEP, phalaTEEEP), `serves tier tee but its prices have none for it`},
		"a price for a tier no endpoint serves": {oneTier(`"private":`+price+`,"e2ee":`+price, togetherEP), `has a price for tier e2ee, which none of its endpoints serves`},
		"an endpoint that sets price":           {oneTier(`"private":`+price, asPrice), `endpoint "together" sets price`},
		"prices on a media model":               {media(`"prices":{"anon":{"hold_micros_per_image":1}},`, fal), `is a media model and sets prices`},
		"two media endpoints at one tier":       {media(``, fal, falTwice), `a media model has no retail price to keep them to`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	if _, err := parse([]byte(media(``, fal))); err != nil {
		t.Errorf("a media model with one endpoint at its tier and no prices: %v", err)
	}
}

const genericEP = `{"id":"other","provider_name":"together","unnamed":true,"tier":"private","base_url":"https://v","upstream_model":"up/m",` + windowed + `}`

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
		"alone at its tier":             {modelsFileOf(modelOf(fireworksEP, phalaTEEEP), `{"name":"m-tee","model":"z/m","endpoint":"phala-tee"}`), `endpoint "fireworks" is unnamed, but no named endpoint of the model serves tier private`},
		"named by an alias":             {modelsFileOf(modelOf(together, fireworksEP), alias+`,{"name":"fw","model":"z/m","endpoint":"fireworks"}`), `alias "fw" names endpoint "fireworks", which is unnamed`},
		"e2ee":                          {modelsFileOf(modelOf(nearEP, strings.Replace(phalaEP, `"tier"`, `"unnamed":true,"tier"`, 1)), ``), `endpoint "phala" is unnamed and e2ee`},
		"unnamed false":                 {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"unnamed":true`, `"unnamed":false`, 1)), alias), `endpoint "fireworks" has unnamed false; set it to true or leave it out`},
		"an unnamed on a plan":          {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"tier"`, `"requires_plan":"pro","tier"`, 1)), alias), `differ in requires_plan`},
		"a second unaliased name":       {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"unnamed":true,`, ``, 1)), ``), `a further endpoint at a tier the model already serves can be unnamed`},
		"an unnamed that keeps prompts": {modelsFileOf(modelOf(together, genericEP), alias), `endpoints "together" and "other" serve model "z/m" at tier private and differ in retention`},
		"an unnamed that reasons at another default":   {modelsFileOf(reasoningModelOf(withEffort(together, "high"), withEffort(fireworksEP, "low")), alias), `differ in default_reasoning_effort`},
		"an unnamed with another default output limit": {modelsFileOf(modelOf(together, strings.Replace(fireworksEP, `"default_max_tokens":16384`, `"default_max_tokens":8192`, 1)), alias), `differ in default_max_tokens`},
	} {
		if _, err := parseForRelay([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

const onBehalfEP = `{"id":"near-on-behalf","tier":"tee","on_behalf_of":"near","default_max_tokens":8192}`

// phalaTEEAtOnBehalfDefault serves the tee tier beside onBehalfEP at its default output limit, since a tier has one.
var phalaTEEAtOnBehalfDefault = strings.Replace(phalaTEEEP, `"default_max_tokens":16384`, `"default_max_tokens":8192`, 1)

func onBehalfFile(endpoints ...string) string {
	price := `{"prompt_micros_per_mtok":150000,"cached_prompt_micros_per_mtok":15000,"completion_micros_per_mtok":600000}`
	return modelsFileOf(`{"id":"z/m",`+modelTerms+`,"prices":{"private":`+price+`,"tee":`+price+`,"e2ee":`+price+`},"endpoints":[`+strings.Join(endpoints, ",")+`]}`, twoAliases)
}

func TestAnOnBehalfEndpointLoadsOntoItsSealedRouteInItsFilePlaceAndTakesWhatItNamesFromTheSealedEndpoint(t *testing.T) {
	rts, err := parseForRelay([]byte(onBehalfFile(togetherEP, onBehalfEP, phalaTEEAtOnBehalfDefault, nearEP)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, rt := range rts {
		names = append(names, rt.Model)
	}
	if !reflect.DeepEqual(names, []string{"m", "m-tee", "z/m"}) {
		t.Fatalf("the routes are %v, want the on-behalf endpoint to be none of them", names)
	}
	sealed := rts[2]
	if len(sealed.OnBehalf) != 1 || len(sealed.Upstreams()) != 1 {
		t.Fatalf("the sealed route has on-behalf endpoints %+v and upstreams %d, want one and the route alone", sealed.OnBehalf, len(sealed.Upstreams()))
	}
	b := sealed.OnBehalf[0]
	bc, _ := ChatOf(b.Serves)
	sc, _ := ChatOf(sealed.Serves)
	if b.Endpoint != "near-on-behalf" || b.OnBehalfOf != "near" || b.Tier != catalog.TEE || b.Model != "z/m" || b.ID != "z/m" || b.Host != "cloud-api.near.ai" || b.UpstreamModel != "z/m" || b.APIKeyEnv != "NEAR_API_KEY" {
		t.Errorf("the on-behalf endpoint loads as %+v, want near's host, upstream model, and key at tee under z/m", b)
	}
	if bc.Price != sc.Price || bc.ContextTokens != sc.ContextTokens || bc.MaxOutputTokens != sc.MaxOutputTokens || bc.DefaultMaxTokens != 8192 || sc.DefaultMaxTokens != 16384 {
		t.Errorf("the on-behalf endpoint serves %+v beside the sealed endpoint's %+v, want the sealed window and its own default", bc, sc)
	}
	if !(rts[0].Order < b.Order && b.Order < rts[1].Order) {
		t.Errorf("orders together %d, near-on-behalf %d, phala-tee %d, want the file's", rts[0].Order, b.Order, rts[1].Order)
	}
}

func TestAnOnBehalfEndpointThatBreaksARuleIsRefusedNamingTheRule(t *testing.T) {
	tinfoilOnBehalf := `{"id":"tinfoil-on-behalf","tier":"tee","on_behalf_of":"tinfoil","default_max_tokens":8192}`
	with := func(field string) string {
		return strings.Replace(onBehalfEP, `"on_behalf_of"`, field+`,"on_behalf_of"`, 1)
	}
	for name, c := range map[string]struct{ file, want string }{
		"naming no endpoint":       {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `"near"`, `"nowhere"`, 1), phalaTEEEP, nearEP), `which model "z/m" does not list`},
		"naming a plaintext one":   {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `"near"`, `"together"`, 1), phalaTEEEP, nearEP), "only an e2ee endpoint is sealed to"},
		"naming a whole-body seal": {onBehalfFile(togetherEP, tinfoilOnBehalf, phalaTEEEP, tinfoilEP), "seals a request whole"},
		"at private":               {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `"tier":"tee"`, `"tier":"private"`, 1), phalaTEEEP, nearEP), "must be tier tee"},
		"setting a cost":           {onBehalfFile(togetherEP, with(`"cost":{"prompt_micros_per_mtok":1,"cached_prompt_micros_per_mtok":1,"completion_micros_per_mtok":1}`), phalaTEEEP, nearEP), `sets "cost"`},
		"setting a window":         {onBehalfFile(togetherEP, with(`"context_tokens":1000`), phalaTEEEP, nearEP), `sets "context_tokens"`},
		"setting an output limit":  {onBehalfFile(togetherEP, with(`"max_output_tokens":1000`), phalaTEEEP, nearEP), `sets "max_output_tokens"`},
		"with no default":          {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `,"default_max_tokens":8192`, ``, 1), phalaTEEEP, nearEP), "default_max_tokens"},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	aliased := strings.Replace(onBehalfFile(togetherEP, onBehalfEP, phalaTEEEP, nearEP), `{"name":"m-tee"`, `{"name":"nb","model":"z/m","endpoint":"near-on-behalf"},{"name":"m-tee"`, 1)
	if _, err := parse([]byte(aliased)); err == nil || !strings.Contains(err.Error(), "which is on behalf of another") {
		t.Errorf("an alias naming the on-behalf endpoint: err %v", err)
	}
}

func TestCostRoleAndSpreadLiveInRelayJSONAndRoutesJSONRefusesThemInEitherForm(t *testing.T) {
	home := `which lives in relay.json: routes.json is public and says what the worker may call, and relay.json says how the relay uses those hosts`
	cost := `"cost":` + tierPrice + `,`
	for name, c := range map[string]struct{ file, want string }{
		"a cost on an endpoint":             {modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, cost+`"tier"`, 1)), ``), `model "z/m" endpoint "together" sets "cost", ` + home},
		"a role on an endpoint":             {modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, `"role":"backup","tier"`, 1)), ``), `model "z/m" endpoint "together" sets "role", ` + home},
		"a spread on a model":               {modelsFileOf(strings.Replace(modelOf(togetherEP), `"label":`, `"spread_bps":2500,"label":`, 1), ``), `model "z/m" sets "spread_bps", ` + home},
		"a cost on an on-behalf endpoint":   {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `"on_behalf_of"`, cost+`"on_behalf_of"`, 1), phalaTEEAtOnBehalfDefault, nearEP), `model "z/m" endpoint "near-on-behalf" sets "cost", ` + home},
		"a role on an on-behalf endpoint":   {onBehalfFile(togetherEP, strings.Replace(onBehalfEP, `"on_behalf_of"`, `"role":"backup","on_behalf_of"`, 1), phalaTEEAtOnBehalfDefault, nearEP), `model "z/m" endpoint "near-on-behalf" sets "role", ` + home},
		"a cost on an array route":          {`[` + strings.Replace(routeOf("m", togetherEP), `"price"`, cost+`"price"`, 1) + `]`, `route 0 sets "cost", ` + home},
		"a role on an array route":          {`[` + strings.Replace(routeOf("m", togetherEP), `"price"`, `"role":"backup","price"`, 1) + `]`, `route 0 sets "role", ` + home},
		"a spread on an array route":        {`[` + strings.Replace(routeOf("m", togetherEP), `"price"`, `"spread_bps":100,"price"`, 1) + `]`, `route 0 sets "spread_bps", ` + home},
		"a cost on an array route fallback": {`[` + strings.TrimSuffix(routeOf("z/m", nearEP), "}") + `,"fallbacks":[{"attester":"phala","base_url":"https://inference.phala.com","api_key_env":"PHALA_API_KEY",` + strings.TrimSuffix(cost, ",") + `}]}]`, `route 0 fallback sets "cost", ` + home},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func withOutputCap(ep string, cap int) string {
	return strings.Replace(ep, `"max_output_tokens":16384`, fmt.Sprintf(`"max_output_tokens":%d`, cap), 1)
}

func TestEveryEndpointOfATierCapsTheOutputAtTheTiersSmallestSoNoCallerCanTellWhichHostServed(t *testing.T) {
	together := withOutputCap(strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1), 131_072)
	small := withOutputCap(fireworksEP, 40_000)
	rts, err := parseForRelay([]byte(modelsFileOf(modelOf(together, small, phalaTEEEP), twoAliases)))
	if err != nil {
		t.Fatal(err)
	}
	named, _ := ChatOf(rts[0].Serves)
	unnamed, _ := ChatOf(rts[0].Unnamed[0].Serves)
	tee, _ := ChatOf(rts[1].Serves)
	if named.MaxOutputTokens != 40_000 || unnamed.MaxOutputTokens != 40_000 {
		t.Errorf("the private tier's endpoints cap output at %d and %d, want 40000 on both", named.MaxOutputTokens, unnamed.MaxOutputTokens)
	}
	if tee.MaxOutputTokens != 16384 {
		t.Errorf("the tee tier caps output at %d, want its own 16384", tee.MaxOutputTokens)
	}
}

func TestADefaultOutputAboveTheTiersSmallestCapIsRefused(t *testing.T) {
	together := strings.Replace(togetherEP, `"base_url"`, `"retention":"zdr","base_url"`, 1)
	_, err := parseForRelay([]byte(modelsFileOf(modelOf(together, withOutputCap(strings.Replace(fireworksEP, `"default_max_tokens":16384`, `"default_max_tokens":4096`, 1), 4096)), twoAliases[:strings.Index(twoAliases, `,{`)])))
	if err == nil || !strings.Contains(err.Error(), "default_max_tokens 16384 above the tier's smallest max_output_tokens 4096") {
		t.Errorf("parsed with error %v, want the default above the tier's cap refused", err)
	}
}
