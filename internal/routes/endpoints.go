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

	"morse/backend/internal/catalog"
)

var (
	modelIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	endpointIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

var ModelFields = []string{"label", "lab", "open_weights", "kind", "reasoning_efforts", "input_modalities", "hides_reasoning", "markup", "app_only"}

var fallbackFields = []string{"attester", "base_url", "api_key_env"}

type Alias struct {
	Name     string             `json:"name"`
	Model    catalog.ModelID    `json:"model"`
	Endpoint catalog.EndpointID `json:"endpoint"`
}

type fields map[string]json.RawMessage

type model struct {
	id        catalog.ModelID
	fields    fields
	endpoints []endpoint
}

type endpoint struct {
	id          catalog.EndpointID
	sealedModel string
	fields      fields
}

func (e endpoint) sealed() bool {
	var name string
	json.Unmarshal(e.fields["tier"], &name)
	tier, err := catalog.ParseTier(name)
	return err == nil && tier.Sealed()
}

type modelsFile struct {
	Models  []json.RawMessage `json:"models"`
	Aliases []Alias           `json:"aliases"`
}

type Flat struct {
	Route     json.RawMessage
	Model     catalog.ModelID
	Endpoints []catalog.EndpointID
}

func Flatten(data []byte) ([]Flat, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{")) {
		var rts []json.RawMessage
		if err := json.Unmarshal(data, &rts); err != nil {
			return nil, fmt.Errorf("routes must be a JSON array of routes or an object of models and aliases: %w", err)
		}
		flat := make([]Flat, len(rts))
		for i, rt := range rts {
			flat[i].Route = rt
		}
		return flat, nil
	}
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
	var rts []Flat
	for _, m := range models {
		flat, err := m.routes(names[m.id])
		if err != nil {
			return nil, fmt.Errorf("model %q: %w", m.id, err)
		}
		rts = append(rts, flat...)
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
		if raw, ok := ef["sealed_model"]; ok {
			if err := json.Unmarshal(raw, &e.sealedModel); err != nil || e.sealedModel == "" {
				return model{}, fmt.Errorf("model %q endpoint %q has sealed_model %s, which must be a non-empty string", m.id, e.id, raw)
			}
		}
		delete(ef, "id")
		delete(ef, "sealed_model")
		for _, k := range slices.Sorted(maps.Keys(ef)) {
			if slices.Contains(ModelFields, k) || k == "model" || k == "fallbacks" {
				return model{}, fmt.Errorf("model %q endpoint %q sets %q, which is not an endpoint field", m.id, e.id, k)
			}
		}
		m.endpoints = append(m.endpoints, e)
	}
	return m, nil
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

func (m model) routes(names map[catalog.EndpointID]string) ([]Flat, error) {
	var flat []fields
	var served [][]catalog.EndpointID
	var sealed fields
	var sealedBy endpoint
	var sealedAt int
	var unnamed catalog.EndpointID
	for _, e := range m.endpoints {
		name, aliased := names[e.id]
		if e.sealed() && sealed != nil {
			if aliased {
				return nil, fmt.Errorf("alias %q names endpoint %q, which serves as a fallback of e2ee endpoint %q under its name", name, e.id, sealedBy.id)
			}
			if err := sameTerms(e, sealedBy); err != nil {
				return nil, err
			}
			if err := sealsAs(m, e, sealed); err != nil {
				return nil, err
			}
			var fbs []fields
			json.Unmarshal(sealed["fallbacks"], &fbs)
			fb := fields{}
			for _, k := range fallbackFields {
				if v, ok := e.fields[k]; ok {
					fb[k] = v
				}
			}
			sealed["fallbacks"] = marshal(append(fbs, fb))
			served[sealedAt] = append(served[sealedAt], e.id)
			continue
		}
		if !aliased {
			if unnamed != "" {
				return nil, fmt.Errorf("endpoints %q and %q both have no alias; at most one endpoint serves under the model id", unnamed, e.id)
			}
			unnamed, name = e.id, string(m.id)
		}
		rt := maps.Clone(m.fields)
		maps.Copy(rt, e.fields)
		rt["model"] = marshal(name)
		if e.sealedModel != "" && !e.sealed() {
			return nil, fmt.Errorf("endpoint %q sets sealed_model but is not e2ee", e.id)
		}
		if e.sealed() {
			if err := sealsAs(m, e, rt); err != nil {
				return nil, err
			}
			sealed, sealedBy, sealedAt = rt, e, len(flat)
		}
		flat = append(flat, rt)
		served = append(served, []catalog.EndpointID{e.id})
	}
	out := make([]Flat, len(flat))
	for i, rt := range flat {
		out[i] = Flat{Route: marshal(rt), Model: m.id, Endpoints: served[i]}
	}
	return out, nil
}

func sealsAs(m model, e endpoint, rt fields) error {
	var name string
	json.Unmarshal(rt["model"], &name)
	if want := cmp.Or(e.sealedModel, string(m.id)); want != name {
		return fmt.Errorf("endpoint %q is e2ee and serves as %q, so a sealed body names %q there; set its sealed_model to %q", e.id, name, name, name)
	}
	return nil
}

func sameTerms(e, first endpoint) error {
	keys := append(slices.Collect(maps.Keys(e.fields)), slices.Collect(maps.Keys(first.fields))...)
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		if !slices.Contains(fallbackFields, k) && !sameJSON(e.fields[k], first.fields[k]) {
			return fmt.Errorf("endpoint %q differs from e2ee endpoint %q in %s; a later e2ee endpoint is a fallback of the first and serves on its terms, so only %s may differ", e.id, first.id, k, strings.Join(fallbackFields, ", "))
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
