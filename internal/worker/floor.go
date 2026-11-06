package worker

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
)

const floorField = "min_privacy"

type providerAsk struct {
	floor        catalog.Tier
	zdr          bool
	oneTier      bool
	maxPrice     money.PriceCap
	crossesTiers bool
}

var (
	errProviderNotObject = apierr.InvalidParameter(`provider must be an object, such as {"min_privacy":"tee"}.`)
	errFloorNotTier      = apierr.InvalidParameter("provider.min_privacy must be one of " + catalog.TierNames() + ".")
	errFloorSealed       = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_field_refused", Code: "e2ee_field_refused", Message: "Field provider.min_privacy is refused on e2ee models, which meet every privacy floor and forward the body verbatim, so leave min_privacy out of a sealed request."}
)

var providerKeys = map[string]func(*providerAsk, string, json.RawMessage) error{
	floorField:                 (*providerAsk).takeFloor,
	"zdr":                      (*providerAsk).takeZDR,
	"data_collection":          (*providerAsk).takeDataCollection,
	"allow_fallbacks":          (*providerAsk).takeFallbacks,
	"max_price":                (*providerAsk).takeMaxPrice,
	"order":                    ignored("an array of strings", isStrings),
	"sort":                     ignored("a string, or an object with by and partition strings", isSort),
	"preferred_min_throughput": ignored("a number, or an object of percentile numbers", isNumberOrObject),
	"preferred_max_latency":    ignored("a number, or an object of percentile numbers", isNumberOrObject),
	"require_parameters":       ignored("true or false", isBool),
	"only":                     refusedChoice,
	"ignore":                   refusedChoice,
	"quantizations":            refusedChoice,
	"enforce_distillable_text": refusedChoice,
}

func floorOf(req *chat.Request) (providerAsk, error) {
	raw, sent := req.Field("provider")
	if !sent {
		return providerAsk{}, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return providerAsk{}, errProviderNotObject
	}
	var ask providerAsk
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		take, known := providerKeys[key]
		if !known {
			return providerAsk{}, apierr.InvalidParameter(fmt.Sprintf("provider.%s is not a field Morse takes. See the API reference for the fields of provider.", key))
		}
		if err := take(&ask, key, fields[key]); err != nil {
			return providerAsk{}, err
		}
	}
	if ask.zdr {
		ask.floor = max(ask.floor, catalog.Private)
	}
	return ask, nil
}

func (a *providerAsk) takeFloor(_ string, raw json.RawMessage) error {
	var name string
	if json.Unmarshal(raw, &name) != nil {
		return errFloorNotTier
	}
	floor, err := catalog.ParseTier(name)
	if err != nil {
		return errFloorNotTier
	}
	a.floor, a.crossesTiers = max(a.floor, floor), true
	return nil
}

func (a *providerAsk) takeZDR(key string, raw json.RawMessage) error {
	var on bool
	if json.Unmarshal(raw, &on) != nil {
		return mustBe(key, "true or false")
	}
	a.zdr, a.crossesTiers = a.zdr || on, a.crossesTiers || on
	return nil
}

func (a *providerAsk) takeDataCollection(key string, raw json.RawMessage) error {
	var policy string
	if json.Unmarshal(raw, &policy) != nil || policy != "allow" && policy != "deny" {
		return mustBe(key, `"allow" or "deny"`)
	}
	deny := policy == "deny"
	a.zdr, a.crossesTiers = a.zdr || deny, a.crossesTiers || deny
	return nil
}

func (a *providerAsk) takeFallbacks(key string, raw json.RawMessage) error {
	var allowed bool
	if json.Unmarshal(raw, &allowed) != nil {
		return mustBe(key, "true or false")
	}
	a.oneTier = a.oneTier || !allowed
	return nil
}

var maxPriceRates = map[string]func(*money.PriceCap, money.Micros){
	"prompt":     func(c *money.PriceCap, m money.Micros) { c.Prompt = &m },
	"completion": func(c *money.PriceCap, m money.Micros) { c.Completion = &m },
}

var maxPriceUnpriced = []string{"audio", "image", "request"}

func (a *providerAsk) takeMaxPrice(key string, raw json.RawMessage) error {
	var rates map[string]json.RawMessage
	if json.Unmarshal(raw, &rates) != nil || rates == nil {
		return mustBe(key, `an object of dollars per million tokens, such as {"prompt":1,"completion":3}`)
	}
	for _, name := range slices.Sorted(maps.Keys(rates)) {
		set, priced := maxPriceRates[name]
		switch {
		case slices.Contains(maxPriceUnpriced, name):
			return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter", fmt.Sprintf("provider.max_price.%s is not supported. Morse prices a chat by its prompt and completion tokens, so max_price takes prompt and completion alone.", name))
		case !priced:
			return apierr.InvalidParameter(fmt.Sprintf("provider.max_price.%s is not a field Morse takes. max_price takes prompt and completion, in dollars per million tokens.", name))
		case string(rates[name]) == "null":
			continue
		}
		dollars, ok := dollarsOf(rates[name])
		if !ok {
			return apierr.InvalidParameter(fmt.Sprintf("provider.max_price.%s must be a number of dollars per million tokens, from 0 up.", name))
		}
		set(&a.maxPrice, money.CapMicros(dollars))
	}
	return nil
}

// dollarsOf reads a price as OpenRouter spells it, a JSON number or a string holding one.
func dollarsOf(raw json.RawMessage) (float64, bool) {
	var dollars float64
	if json.Unmarshal(raw, &dollars) != nil {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return 0, false
		}
		var err error
		if dollars, err = strconv.ParseFloat(text, 64); err != nil {
			return 0, false
		}
	}
	return dollars, dollars >= 0 && !math.IsNaN(dollars)
}

func mustBe(key, shape string) error {
	return apierr.InvalidParameter("provider." + key + " must be " + shape + ".")
}

func ignored(shape string, ok func(json.RawMessage) bool) func(*providerAsk, string, json.RawMessage) error {
	return func(_ *providerAsk, key string, raw json.RawMessage) error {
		if !ok(raw) {
			return mustBe(key, shape)
		}
		return nil
	}
}

func refusedChoice(_ *providerAsk, key string, _ json.RawMessage) error {
	return apierr.Invalid(http.StatusBadRequest, "provider_choice_unsupported", fmt.Sprintf("provider.%s is not supported. Morse chooses the provider within a privacy tier, and the Pricing page of the API docs lists the providers that serve each model at each tier. Use provider.min_privacy to require a tier.", key))
}

func isStrings(raw json.RawMessage) bool {
	var v []string
	return json.Unmarshal(raw, &v) == nil && v != nil
}

func isNumberOrObject(raw json.RawMessage) bool {
	var o map[string]float64
	return string(raw) != "null" && isNumber(raw) || json.Unmarshal(raw, &o) == nil && o != nil
}

func isSort(raw json.RawMessage) bool {
	var s string
	var o struct {
		By        *string `json:"by"`
		Partition *string `json:"partition"`
	}
	return string(raw) != "null" && (json.Unmarshal(raw, &s) == nil || json.Unmarshal(raw, &o) == nil)
}

func (a providerAsk) narrow(n chatName, routes []chatRoute, keyFloor catalog.Tier) ([]chatRoute, error) {
	if a.zdr {
		keyAdmits := func(r chatRoute) bool { return r.tier >= keyFloor }
		admitted := slices.ContainsFunc(routes, keyAdmits)
		routes = slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return r.retention != catalog.RetentionZDR })
		if len(routes) == 0 || admitted && !slices.ContainsFunc(routes, keyAdmits) {
			return nil, errNoZDREndpoint
		}
	}
	routes = n.optIn(routes, max(a.floor, keyFloor))
	if a.oneTier {
		routes = atTier(routes, routes[0].tier)
	}
	return routes, nil
}

var errNoZDREndpoint = apierr.Invalid(http.StatusBadRequest, "privacy_floor_unmet", "No endpoint at the tiers this request may run at keeps no data, so provider.zdr and provider.data_collection deny cannot be met. The model name, provider.min_privacy, and the API key's min_privacy set those tiers. Drop zdr and data_collection deny, or send a model or floor whose tiers include a zero-retention endpoint.")

func namesFloor(provider json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(provider, &fields) != nil {
		return false
	}
	_, named := fields[floorField]
	return named
}
