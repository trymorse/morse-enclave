package routes

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/plankind"
)

const defaultOwner = "morse"

func parseRetention(raw string) (catalog.Retention, error) {
	if raw == "" {
		return catalog.RetentionVendor, nil
	}
	return catalog.ParseRetention(raw)
}

var tierInLabel = regexp.MustCompile(`(?i)\b(tee|e2ee)\b`)

func Load(path string, defaultMarkup money.Markup) ([]Route, error) {
	rts, _, err := Read(path, defaultMarkup)
	return rts, err
}

func Read(path string, defaultMarkup money.Markup) (rts []Route, digest string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	rts, err = Parse(raw, defaultMarkup)
	return rts, hex.EncodeToString(sum[:]), err
}

func Parse(data []byte, defaultMarkup money.Markup) ([]Route, error) {
	flat, err := Flatten(data)
	if err != nil {
		return nil, err
	}
	if len(flat) == 0 {
		return nil, errors.New("routes file has no routes")
	}
	seen := map[string]bool{}
	routes := make([]Route, 0, len(flat))
	for i, f := range flat {
		parsed, err := parseRoute(f.Route, defaultMarkup)
		if err != nil {
			return nil, fmt.Errorf("route %d: %w", i, err)
		}
		for j := range parsed {
			parsed[j].identify(f)
		}
		for _, rt := range parsed {
			if seen[rt.Model] {
				return nil, fmt.Errorf("route %d repeats model %q", i, rt.Model)
			}
			seen[rt.Model] = true
		}
		routes = append(routes, parsed...)
	}
	if err := oneAttesterPerHost(routes); err != nil {
		return nil, err
	}
	return routes, nil
}

func parseRoute(object json.RawMessage, defaultMarkup money.Markup) ([]Route, error) {
	var peek struct {
		Kind catalog.Kind `json:"kind"`
	}
	if err := json.Unmarshal(object, &peek); err != nil {
		return nil, err
	}
	switch peek.Kind {
	case catalog.KindImage:
		return one[imageRoute](object, defaultMarkup)
	case catalog.KindVideo:
		return one[videoRoute](object, defaultMarkup)
	case catalog.KindSearch, catalog.KindFetch, catalog.KindResearch, catalog.KindTranscription:
		return one[callRoute](object, defaultMarkup)
	}
	return chatRoutes(object, defaultMarkup)
}

func chatRoutes(object json.RawMessage, defaultMarkup money.Markup) ([]Route, error) {
	r, err := decode[chatRoute](object)
	if err != nil {
		return nil, err
	}
	rt, err := build(r, defaultMarkup)
	if err != nil {
		return nil, err
	}
	if len(r.Fallbacks) > 0 && !rt.Tier.Sealed() {
		return nil, fmt.Errorf("route %q is tier %s and takes no fallbacks: only a sealed route's client can reseal a request for another attester", rt.Model, rt.Tier)
	}
	named := map[string]bool{r.Attester: true}
	for _, fb := range r.Fallbacks {
		if named[fb.Attester] {
			return nil, fmt.Errorf("route %q names attester %s twice; the proxy tells a route's vendors apart by the protocol each attester speaks", rt.Model, fb.Attester)
		}
		named[fb.Attester] = true
		vendor := r
		vendor.Attester, vendor.BaseURL, vendor.APIKeyEnv, vendor.Fallbacks = fb.Attester, fb.BaseURL, fb.APIKeyEnv, nil
		f, err := build(vendor, defaultMarkup)
		if err != nil {
			return nil, fmt.Errorf("fallback %q: %w", fb.Attester, err)
		}
		rt.Fallbacks = append(rt.Fallbacks, f)
	}
	return []Route{rt}, nil
}

type kindRoute interface {
	base() common
	serves(defaultMarkup money.Markup) (Serves, error)
}

func decode[R kindRoute](object json.RawMessage) (R, error) {
	var r R
	dec := json.NewDecoder(bytes.NewReader(object))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		var c common
		json.Unmarshal(object, &c)
		return r, fmt.Errorf("route %q of kind %s: %w", c.Model, c.Kind, err)
	}
	return r, nil
}

func one[R kindRoute](object json.RawMessage, defaultMarkup money.Markup) ([]Route, error) {
	r, err := decode[R](object)
	if err != nil {
		return nil, err
	}
	rt, err := build(r, defaultMarkup)
	if err != nil {
		return nil, err
	}
	return []Route{rt}, nil
}

func build(r kindRoute, defaultMarkup money.Markup) (Route, error) {
	model := r.base().Model
	if model == "" {
		return Route{}, errors.New("has no model")
	}
	serves, err := r.serves(defaultMarkup)
	var rt Route
	if err == nil {
		rt, err = r.base().route(serves)
	}
	if err != nil {
		return Route{}, fmt.Errorf("route %q %w", model, err)
	}
	return rt, nil
}

func (c common) base() common { return c }

func (c common) route(serves Serves) (Route, error) {
	tier, err := catalog.ParseTier(c.Tier)
	if err != nil {
		return Route{}, err
	}
	if c.UpstreamModel == "" {
		return Route{}, errors.New("has no upstream_model")
	}
	if strings.TrimSpace(c.Label) == "" {
		return Route{}, errors.New("has no label")
	}
	if tag := tierInLabel.FindString(c.Label); tag != "" {
		return Route{}, fmt.Errorf("label %q names tier %s; /v1/models lists the tier beside the label, so the label names only the model", c.Label, tag)
	}
	base, err := checkBaseURL(c.BaseURL, tier)
	if err != nil {
		return Route{}, err
	}
	up, err := c.upstream(tier)
	if err != nil {
		return Route{}, err
	}
	retention, err := parseRetention(c.Retention)
	if err != nil {
		return Route{}, err
	}
	if tier == catalog.Anon && c.OwnedBy == "" {
		return Route{}, fmt.Errorf("is tier %s and must name owned_by", catalog.Anon)
	}
	requires, err := requiredPlan(c.RequiresPlan)
	if err != nil {
		return Route{}, err
	}
	rt := Route{
		Model:         c.Model,
		Tier:          tier,
		Upstream:      up,
		BaseURL:       strings.TrimRight(c.BaseURL, "/"),
		Host:          base.Hostname(),
		UpstreamModel: c.UpstreamModel,
		APIKeyEnv:     c.APIKeyEnv,
		Label:         c.Label,
		OwnedBy:       cmp.Or(c.OwnedBy, defaultOwner),
		Lab:           c.Lab,
		OpenWeights:   c.OpenWeights,
		Retention:     retention,
		Serves:        serves,
		Included:      c.Included,
		RequiresPlan:  requires,
		AppOnly:       c.AppOnly,
	}
	return rt, up.check(rt)
}

func requiredPlan(raw string) (plankind.Kind, error) {
	if raw == "" {
		return plankind.Free, nil
	}
	plan, ok := plankind.Parse(raw)
	if !ok || !plan.Paid() {
		return 0, fmt.Errorf("requires_plan %q must be a paid plan, %s; leave it out to let every plan use the route", raw, strings.Join(paidPlanNames(), ", "))
	}
	return plan, nil
}

func paidPlanNames() []string {
	var names []string
	for _, p := range plankind.All() {
		if p.Paid() {
			names = append(names, p.String())
		}
	}
	return names
}
