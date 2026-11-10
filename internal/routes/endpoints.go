package routes

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"morse/backend/internal/attester"
	"morse/backend/internal/catalog"
)

var (
	modelIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	endpointIDPattern = regexp.MustCompile(catalog.EndpointIDPattern)
)

var ModelFields = []string{"label", "lab", "open_weights", "kind", "reasoning_efforts", "input_modalities", "hides_reasoning", "answers_in_reasoning", "markup", "app_only", "prices", "rebate_share_bps"}

// FallbackFields are the fields in which a later e2ee endpoint of a model may differ from the first, whose fallback it
// is.
var FallbackFields = []string{"attester", "base_url", "api_key_env", "provider_name"}

// RelayFields are the keys that live in relay.json, which routes.json refuses.
var RelayFields = []string{"cost", "role", "spread_bps"}

func relayField(f fields) (string, bool) {
	for _, k := range RelayFields {
		if _, ok := f[k]; ok {
			return k, true
		}
	}
	return "", false
}

const relayFieldHome = "which lives in relay.json: routes.json is public and says what the worker may call, and relay.json says how the relay uses those hosts"

type Alias struct {
	Name     string             `json:"name"`
	Model    catalog.ModelID    `json:"model"`
	Endpoint catalog.EndpointID `json:"endpoint"`
}

type fields map[string]json.RawMessage

type model struct {
	id catalog.ModelID
	// fields are the model's own fields, prices left out.
	fields fields
	// prices is what a customer pays at each tier, a price object that each route of that tier gets as its price. A
	// media model has none: it bills the vendor's reported cost, and its endpoint's price is its hold.
	prices    map[string]json.RawMessage
	endpoints []endpoint
}

func (m model) media() bool {
	var kind catalog.Kind
	json.Unmarshal(m.fields["kind"], &kind)
	return kind == catalog.KindImage || kind == catalog.KindVideo
}

// route is the object a model's endpoint loads as: the model's fields, the endpoint's, and the price its tier sells at.
func (m model) route(e endpoint) (fields, error) {
	rt := maps.Clone(m.fields)
	maps.Copy(rt, e.fields)
	if m.media() {
		return rt, nil
	}
	price, ok := m.prices[e.tier()]
	if !ok {
		return nil, fmt.Errorf("endpoint %q serves tier %s, which the model's prices do not list", e.id, e.tier())
	}
	rt["price"] = price
	return rt, nil
}

type endpoint struct {
	id          catalog.EndpointID
	sealedModel string
	// onBehalfOf makes the endpoint an on-behalf endpoint of the sealed endpoint it names.
	onBehalfOf catalog.EndpointID
	// unnamed keeps the endpoint off every list and request name: it serves in its model's candidate set at its tier,
	// under the names of the named endpoint there.
	unnamed bool
	fields  fields
}

func (e endpoint) tier() string {
	var name string
	json.Unmarshal(e.fields["tier"], &name)
	return name
}

func (e endpoint) sealed() bool {
	tier, err := catalog.ParseTier(e.tier())
	return err == nil && tier.Sealed()
}

type modelsFile struct {
	Models      []json.RawMessage `json:"models"`
	Aliases     []Alias           `json:"aliases"`
	PrivacyVeil json.RawMessage   `json:"privacy_veil"`
}

type served struct {
	named  flatEndpoint
	beside []flatEndpoint
}

type flatEndpoint struct {
	object fields
	model  catalog.ModelID
	id     catalog.EndpointID
	// fileOrder is the endpoint's place among every endpoint of the routes file.
	fileOrder int
	place     catalog.Place
}

func flatten(data []byte) ([]served, error) {
	var file modelsFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("routes file: %w", err)
	}
	if len(file.Models) == 0 {
		return nil, errors.New("routes file has no models")
	}
	models := make([]model, 0, len(file.Models))
	for i, raw := range file.Models {
		m, err := parseModel(raw)
		if err != nil {
			return nil, fmt.Errorf("model %d: %w", i, err)
		}
		if slices.ContainsFunc(models, func(o model) bool { return o.id == m.id }) {
			return nil, fmt.Errorf("model %q is listed twice", m.id)
		}
		models = append(models, m)
	}
	names, err := aliasNames(file.Aliases, models)
	if err != nil {
		return nil, err
	}
	var rts []served
	fileOrder := 0
	for _, m := range models {
		flat, err := m.endpointsServed(names[m.id], fileOrder)
		if err != nil {
			return nil, fmt.Errorf("model %q: %w", m.id, err)
		}
		rts = append(rts, flat...)
		fileOrder += len(m.endpoints)
	}
	return rts, nil
}

func parseModel(raw json.RawMessage) (model, error) {
	var top fields
	if err := json.Unmarshal(raw, &top); err != nil {
		return model{}, err
	}
	var m model
	if json.Unmarshal(top["id"], &m.id) != nil || !modelIDPattern.MatchString(string(m.id)) {
		return model{}, fmt.Errorf("has id %s; a model id is lab/model in lowercase", top["id"])
	}
	var endpoints []fields
	if raw, ok := top["endpoints"]; ok {
		if err := json.Unmarshal(raw, &endpoints); err != nil {
			return model{}, fmt.Errorf("model %q: endpoints: %w", m.id, err)
		}
	}
	if len(endpoints) == 0 {
		return model{}, fmt.Errorf("model %q lists no endpoints", m.id)
	}
	delete(top, "id")
	delete(top, "endpoints")
	if k, ok := relayField(top); ok {
		return model{}, fmt.Errorf("model %q sets %q, %s", m.id, k, relayFieldHome)
	}
	if raw, ok := top["prices"]; ok {
		if err := json.Unmarshal(raw, &m.prices); err != nil {
			return model{}, fmt.Errorf("model %q: prices must be an object of a price for each tier: %w", m.id, err)
		}
		delete(top, "prices")
	}
	for _, k := range slices.Sorted(maps.Keys(top)) {
		if !slices.Contains(ModelFields, k) {
			return model{}, fmt.Errorf("model %q sets %q; a model sets id, endpoints, and %s, and every other field belongs to an endpoint", m.id, k, strings.Join(ModelFields, ", "))
		}
	}
	m.fields = top
	for _, ef := range endpoints {
		e := endpoint{fields: ef}
		if json.Unmarshal(ef["id"], &e.id) != nil || !endpointIDPattern.MatchString(string(e.id)) {
			return model{}, fmt.Errorf("model %q has an endpoint with id %s; an endpoint id is up to 32 lowercase letters, digits, and hyphens", m.id, ef["id"])
		}
		if slices.ContainsFunc(m.endpoints, func(o endpoint) bool { return o.id == e.id }) {
			return model{}, fmt.Errorf("model %q lists endpoint %q twice", m.id, e.id)
		}
		if k, ok := relayField(ef); ok {
			return model{}, fmt.Errorf("model %q endpoint %q sets %q, %s", m.id, e.id, k, relayFieldHome)
		}
		if raw, ok := ef["sealed_model"]; ok {
			if err := json.Unmarshal(raw, &e.sealedModel); err != nil || e.sealedModel == "" {
				return model{}, fmt.Errorf("model %q endpoint %q has sealed_model %s, which must be a non-empty string", m.id, e.id, raw)
			}
		}
		if raw, ok := ef["on_behalf_of"]; ok {
			if err := json.Unmarshal(raw, &e.onBehalfOf); err != nil || !endpointIDPattern.MatchString(string(e.onBehalfOf)) {
				return model{}, fmt.Errorf("model %q endpoint %q has on_behalf_of %s, which must name an e2ee endpoint of the model", m.id, e.id, raw)
			}
			if err := e.checkOnBehalf(m.id); err != nil {
				return model{}, err
			}
		}
		if raw, ok := ef["unnamed"]; ok {
			if err := json.Unmarshal(raw, &e.unnamed); err != nil || !e.unnamed {
				return model{}, fmt.Errorf("model %q endpoint %q has unnamed %s; set it to true or leave it out", m.id, e.id, raw)
			}
		}
		delete(ef, "id")
		delete(ef, "sealed_model")
		delete(ef, "unnamed")
		for _, k := range slices.Sorted(maps.Keys(ef)) {
			if slices.Contains(ModelFields, k) || k == "model" || k == "fallbacks" {
				return model{}, fmt.Errorf("model %q endpoint %q sets %q, which is not an endpoint field", m.id, e.id, k)
			}
		}
		m.endpoints = append(m.endpoints, e)
	}
	return m, m.checkPrices()
}

// checkPrices holds a model to one price per tier it serves: the keys of prices are exactly the tiers of its
// endpoints, and a media model, which bills the vendor's reported cost, has none.
func (m model) checkPrices() error {
	tiers := map[string]bool{}
	for _, e := range m.endpoints {
		_, hasPrice := e.fields["price"]
		if e.onBehalfOf != "" {
			tiers[e.tier()] = true
			continue
		}
		if !m.media() && hasPrice {
			return fmt.Errorf("model %q endpoint %q sets price; the model's prices set what a customer pays at each tier, and relay.json what the endpoint costs Morse", m.id, e.id)
		}
		if m.media() && tiers[e.tier()] {
			return fmt.Errorf("model %q lists two endpoints at tier %s; a media model has no retail price to keep them to, so it serves one endpoint at each tier", m.id, e.tier())
		}
		tiers[e.tier()] = true
	}
	if m.media() {
		if m.prices != nil {
			return fmt.Errorf("model %q is a media model and sets prices; it bills the vendor's reported cost", m.id)
		}
		return nil
	}
	for _, tier := range slices.Sorted(maps.Keys(tiers)) {
		if _, ok := m.prices[tier]; !ok {
			return fmt.Errorf("model %q serves tier %s but its prices have none for it", m.id, tier)
		}
	}
	for _, tier := range slices.Sorted(maps.Keys(m.prices)) {
		if !tiers[tier] {
			return fmt.Errorf("model %q has a price for tier %s, which none of its endpoints serves", m.id, tier)
		}
	}
	return nil
}

func aliasNames(aliases []Alias, models []model) (map[catalog.ModelID]map[catalog.EndpointID]string, error) {
	names := map[catalog.ModelID]map[catalog.EndpointID]string{}
	seen := map[string]bool{}
	for _, a := range aliases {
		i := slices.IndexFunc(models, func(m model) bool { return m.id == a.Model })
		switch {
		case a.Name == "":
			return nil, errors.New("an alias has no name")
		case seen[a.Name]:
			return nil, fmt.Errorf("alias %q is listed twice", a.Name)
		case slices.ContainsFunc(models, func(m model) bool { return string(m.id) == a.Name }):
			return nil, fmt.Errorf("alias %q is a model id", a.Name)
		case i < 0:
			return nil, fmt.Errorf("alias %q names model %q, which the file does not list", a.Name, a.Model)
		case !slices.ContainsFunc(models[i].endpoints, func(e endpoint) bool { return e.id == a.Endpoint }):
			return nil, fmt.Errorf("alias %q names endpoint %q, which model %q does not list", a.Name, a.Endpoint, a.Model)
		case slices.ContainsFunc(models[i].endpoints, func(e endpoint) bool { return e.id == a.Endpoint && e.unnamed }):
			return nil, fmt.Errorf("alias %q names endpoint %q, which is unnamed", a.Name, a.Endpoint)
		case slices.ContainsFunc(models[i].endpoints, func(e endpoint) bool { return e.id == a.Endpoint && e.onBehalfOf != "" }):
			return nil, fmt.Errorf("alias %q names endpoint %q, which is on behalf of another and serves under that endpoint's name", a.Name, a.Endpoint)
		}
		seen[a.Name] = true
		if names[a.Model] == nil {
			names[a.Model] = map[catalog.EndpointID]string{}
		}
		if other, ok := names[a.Model][a.Endpoint]; ok {
			return nil, fmt.Errorf("aliases %q and %q both name endpoint %q of model %q; an endpoint serves under one name", other, a.Name, a.Endpoint, a.Model)
		}
		names[a.Model][a.Endpoint] = a.Name
	}
	return names, nil
}

// endpointsServed is m's endpoints as they serve, each named by names. m's first endpoint is at firstFileOrder among
// the routes file's endpoints.
func (m model) endpointsServed(names map[catalog.EndpointID]string, firstFileOrder int) ([]served, error) {
	var out []served
	var sealedBy endpoint
	sealedAt := -1
	var underID catalog.EndpointID
	var unnamed, onBehalf []int
	for i, e := range m.endpoints {
		if e.onBehalfOf != "" {
			onBehalf = append(onBehalf, i)
			continue
		}
		if e.unnamed {
			if e.sealed() {
				return nil, fmt.Errorf("endpoint %q is unnamed and e2ee; a later e2ee endpoint is already a fallback of the first, so leave unnamed out", e.id)
			}
			unnamed = append(unnamed, i)
			continue
		}
		name, aliased := names[e.id]
		if e.sealed() && sealedAt >= 0 {
			sealed := &out[sealedAt]
			if aliased {
				return nil, fmt.Errorf("alias %q names endpoint %q, which serves as a fallback of e2ee endpoint %q under its name", name, e.id, sealedBy.id)
			}
			if err := sameTerms(e, sealedBy); err != nil {
				return nil, err
			}
			if err := sameSeal(e, sealedBy); err != nil {
				return nil, err
			}
			if err := sealsAs(m, e, sealed.named.object); err != nil {
				return nil, err
			}
			if err := oneAttesterEach(e, sealed); err != nil {
				return nil, err
			}
			rt, err := m.route(e)
			if err != nil {
				return nil, err
			}
			rt["model"] = sealed.named.object["model"]
			sealed.beside = append(sealed.beside, flatEndpoint{object: rt, model: m.id, id: e.id, fileOrder: firstFileOrder + i, place: catalog.PlaceFallback})
			continue
		}
		if !aliased {
			if underID != "" {
				return nil, fmt.Errorf("endpoints %q and %q both have no alias; at most one endpoint serves under the model id, and a further endpoint at a tier the model already serves can be unnamed", underID, e.id)
			}
			underID, name = e.id, string(m.id)
		}
		rt, err := m.route(e)
		if err != nil {
			return nil, err
		}
		rt["model"] = marshal(name)
		if e.sealedModel != "" && !e.sealed() {
			return nil, fmt.Errorf("endpoint %q sets sealed_model but is not e2ee", e.id)
		}
		if e.sealed() {
			if err := sealsAs(m, e, rt); err != nil {
				return nil, err
			}
			sealedBy, sealedAt = e, len(out)
		}
		out = append(out, served{named: flatEndpoint{object: rt, model: m.id, id: e.id, fileOrder: firstFileOrder + i}})
	}
	for _, i := range unnamed {
		e := m.endpoints[i]
		at := slices.IndexFunc(out, func(s served) bool { return sameJSON(s.named.object["tier"], e.fields["tier"]) })
		if at < 0 {
			return nil, fmt.Errorf("endpoint %q is unnamed, but no named endpoint of the model serves tier %s for it to serve beside", e.id, e.tier())
		}
		rt, err := m.route(e)
		if err != nil {
			return nil, err
		}
		rt["model"] = out[at].named.object["model"]
		out[at].beside = append(out[at].beside, flatEndpoint{object: rt, model: m.id, id: e.id, fileOrder: firstFileOrder + i, place: catalog.PlaceUnnamed})
	}
	for _, i := range onBehalf {
		e := m.endpoints[i]
		rt, at, err := m.onBehalfRoute(e, out)
		if err != nil {
			return nil, err
		}
		out[at].beside = append(out[at].beside, flatEndpoint{object: rt, model: m.id, id: e.id, fileOrder: firstFileOrder + i, place: catalog.PlaceOnBehalf})
	}
	return out, nil
}

func oneAttesterEach(e endpoint, sealed *served) error {
	var name string
	json.Unmarshal(e.fields["attester"], &name)
	for _, o := range append([]flatEndpoint{sealed.named}, sealed.beside...) {
		var other string
		json.Unmarshal(o.object["attester"], &other)
		if other == name {
			return fmt.Errorf("endpoints %q and %q are e2ee and both name attester %s; a sealed request names its vendor by the protocol the attester speaks, so each e2ee endpoint of a model names its own", o.id, e.id, name)
		}
	}
	return nil
}

// OnBehalfFields are the only fields an on-behalf endpoint sets besides its id: everything else it takes from the
// sealed endpoint it names, so the two cannot drift.
var OnBehalfFields = []string{"on_behalf_of", "tier", "default_max_tokens", "default_reasoning_effort", "included", "requires_plan"}

// ownTerms are the fields of a sealed endpoint that an on-behalf endpoint sets for itself.
var ownTerms = []string{"tier", "default_max_tokens", "default_reasoning_effort", "included", "requires_plan"}

func (e endpoint) checkOnBehalf(model catalog.ModelID) error {
	for _, k := range slices.Sorted(maps.Keys(e.fields)) {
		if k != "id" && !slices.Contains(OnBehalfFields, k) {
			return fmt.Errorf("model %q endpoint %q is on behalf of endpoint %q and sets %q; it takes its host, upstream model, key, attester, window, and retention from that endpoint and sets only %s", model, e.id, e.onBehalfOf, k, strings.Join(OnBehalfFields, ", "))
		}
	}
	if e.tier() != catalog.OnBehalfTier.String() {
		return fmt.Errorf("model %q endpoint %q is on behalf of endpoint %q and must be tier %s, the tier of a plaintext chat the worker seals for its client", model, e.id, e.onBehalfOf, catalog.OnBehalfTier)
	}
	return nil
}

// onBehalfRoute builds the object an on-behalf endpoint loads as: the sealed endpoint's fields, with the endpoint's own
// terms and defaults over them, at the model's tee price. The int is the route that serves the sealed endpoint.
func (m model) onBehalfRoute(e endpoint, out []served) (fields, int, error) {
	i := slices.IndexFunc(m.endpoints, func(o endpoint) bool { return o.id == e.onBehalfOf })
	if i < 0 {
		return nil, 0, fmt.Errorf("endpoint %q is on behalf of endpoint %q, which model %q does not list", e.id, e.onBehalfOf, m.id)
	}
	sealed := m.endpoints[i]
	if !sealed.sealed() {
		return nil, 0, fmt.Errorf("endpoint %q is on behalf of endpoint %q, which is tier %s; only an e2ee endpoint is sealed to", e.id, sealed.id, sealed.tier())
	}
	var name string
	json.Unmarshal(sealed.fields["attester"], &name)
	if v, err := attester.Parse(name); err != nil || v.SealsBody() {
		return nil, 0, fmt.Errorf("endpoint %q is on behalf of endpoint %q, whose attester %s seals a request whole, so it has no seal for a plaintext chat", e.id, sealed.id, name)
	}
	at := slices.IndexFunc(out, func(s served) bool {
		return s.named.id == sealed.id || slices.ContainsFunc(s.beside, func(b flatEndpoint) bool { return b.id == sealed.id })
	})
	if at < 0 {
		return nil, 0, fmt.Errorf("endpoint %q is on behalf of endpoint %q, which serves no route", e.id, sealed.id)
	}
	rt := maps.Clone(m.fields)
	maps.Copy(rt, sealed.fields)
	for _, k := range ownTerms {
		delete(rt, k)
	}
	maps.Copy(rt, e.fields)
	price, ok := m.prices[e.tier()]
	if !ok {
		return nil, 0, fmt.Errorf("endpoint %q serves tier %s, which the model's prices do not list", e.id, e.tier())
	}
	rt["price"] = price
	rt["model"] = out[at].named.object["model"]
	return rt, at, nil
}

func sealsAs(m model, e endpoint, rt fields) error {
	var name string
	json.Unmarshal(rt["model"], &name)
	if want := cmp.Or(e.sealedModel, string(m.id)); want != name {
		return fmt.Errorf("endpoint %q is e2ee and serves as %q, so a sealed body names %q there; set its sealed_model to %q", e.id, name, name, name)
	}
	return nil
}

// sameSeal holds a fallback to the way its first endpoint is sealed: a client that seals each message's content
// can't be sent on to an attester that opens a body sealed whole, nor the other way.
func sameSeal(e, first endpoint) error {
	var a, b string
	json.Unmarshal(e.fields["attester"], &a)
	json.Unmarshal(first.fields["attester"], &b)
	va, errA := attester.Parse(a)
	vb, errB := attester.Parse(b)
	if errA != nil || errB != nil || va.SealsBody() == vb.SealsBody() {
		return nil
	}
	return fmt.Errorf("endpoint %q is a fallback of e2ee endpoint %q, but %s and %s seal requests differently; a fallback must seal as its first endpoint does", e.id, first.id, va, vb)
}

func sameTerms(e, first endpoint) error {
	keys := append(slices.Collect(maps.Keys(e.fields)), slices.Collect(maps.Keys(first.fields))...)
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		if !slices.Contains(FallbackFields, k) && !sameJSON(e.fields[k], first.fields[k]) {
			return fmt.Errorf("endpoint %q differs from e2ee endpoint %q in %s; a later e2ee endpoint is a fallback of the first and serves on its terms, so only %s may differ", e.id, first.id, k, strings.Join(FallbackFields, ", "))
		}
	}
	return nil
}

func sameJSON(a, b json.RawMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	var ca, cb bytes.Buffer
	return json.Compact(&ca, a) == nil && json.Compact(&cb, b) == nil && bytes.Equal(ca.Bytes(), cb.Bytes())
}

func marshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
