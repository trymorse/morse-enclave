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
	"reflect"
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
	flat, err := flatten(data)
	if err != nil {
		return nil, err
	}
	if len(flat) == 0 {
		return nil, errors.New("routes file has no routes")
	}
	seen := map[string]bool{}
	routes := make([]Route, 0, len(flat))
	for _, s := range flat {
		rt, err := parseRoute(s.named, defaultMarkup)
		if err != nil {
			return nil, err
		}
		for _, b := range s.beside {
			beside, err := parseRoute(b, defaultMarkup)
			if err != nil {
				return nil, err
			}
			if _, chats := ChatOf(beside.Serves); b.place == catalog.PlaceUnnamed && !chats {
				return nil, fmt.Errorf("model %s endpoint %s: is unnamed and serves %s; only a chat fails over to an unnamed endpoint", b.model, b.id, beside.Serves.Kind())
			}
			rt.Beside = append(rt.Beside, beside)
		}
		if seen[rt.Model] {
			return nil, fmt.Errorf("model %s endpoint %s repeats model %q", s.named.model, s.named.id, rt.Model)
		}
		seen[rt.Model] = true
		routes = append(routes, rt)
	}
	if err := oneAttesterPerHost(routes); err != nil {
		return nil, err
	}
	return routes, nil
}

func parseRoute(f flatEndpoint, defaultMarkup money.Markup) (Route, error) {
	object := marshal(f.object)
	var peek struct {
		Kind catalog.Kind `json:"kind"`
	}
	if err := json.Unmarshal(object, &peek); err != nil {
		return Route{}, err
	}
	var rt Route
	var err error
	switch peek.Kind {
	case catalog.KindImage:
		rt, err = one[imageRoute](object, defaultMarkup)
	case catalog.KindVideo:
		rt, err = one[videoRoute](object, defaultMarkup)
	case catalog.KindSearch, catalog.KindFetch, catalog.KindResearch, catalog.KindTranscription:
		rt, err = one[callRoute](object, defaultMarkup)
	default:
		rt, err = one[chatRoute](object, defaultMarkup)
	}
	if err != nil {
		return Route{}, fmt.Errorf("model %s endpoint %s: %w", f.model, f.id, err)
	}
	rt.ID, rt.Endpoint, rt.Order, rt.Place = f.model, f.id, f.fileOrder, f.place
	return rt, nil
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

func one[R kindRoute](object json.RawMessage, defaultMarkup money.Markup) (Route, error) {
	r, err := decode[R](object)
	if err != nil {
		return Route{}, err
	}
	return build(r, defaultMarkup)
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
	share := money.DefaultRebateShare
	if c.RebateShare != nil {
		share = money.RebateShare(*c.RebateShare)
	}
	if !share.Valid() {
		return Route{}, fmt.Errorf("rebate_share_bps %d must be from 0 to %d basis points of the margin; leave it out for %d", share, money.WholeMargin, money.DefaultRebateShare)
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
		ProviderName:  c.ProviderName,
		Serves:        serves,
		Included:      c.Included,
		RequiresPlan:  requires,
		AppOnly:       c.AppOnly,
		RebateShare:   share,
		OnBehalfOf:    c.OnBehalfOf,
	}
	if err := up.check(rt); err != nil {
		return Route{}, err
	}
	return rt, c.checkProviderName(up)
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

// FailoverOnOneTerm refuses a model whose chat endpoints at one tier outside e2ee differ in a term the relay bills or
// gates by: a tier has one retail price and one set of plan terms, and a chat fails over between its endpoints, paying
// the endpoint it bound. Two tiers of one model may differ, but only when every plaintext endpoint of the model has a
// provider that maps a dry account to an account refusal (refusesDryAccount): only the breaker can then move a bind off a
// dry tier, since the refusal neither fails over to the other tier nor, otherwise, opens the circuit.
// includedWindows are the plans' included context windows, on which the named endpoints of a tier must agree. An
// unnamed endpoint may have any window: it sells on its named endpoint's, and the relay sends it only a chat that fits
// its own with the output the named endpoint would give. The relay runs it rather than Parse, because the windows come
// from the plan table, which the worker must not link.
func FailoverOnOneTerm(routes []Route, includedWindows []int, refusesDryAccount func(Route) bool) error {
	type at struct {
		id   catalog.ModelID
		tier catalog.Tier
	}
	type endpointOf struct {
		id       catalog.ModelID
		endpoint catalog.EndpointID
	}
	firstAt, firstOf := map[at]Route{}, map[catalog.ModelID]Route{}
	var served []Route
	unnamed := map[endpointOf]bool{}
	for _, rt := range routes {
		served = append(append(served, rt), rt.Beside...)
		for _, u := range rt.At(catalog.PlaceUnnamed) {
			unnamed[endpointOf{u.ID, u.Endpoint}] = true
		}
	}
	tiersDiffer := map[catalog.ModelID]string{}
	for _, rt := range served {
		if _, chats := ChatOf(rt.Serves); !chats || rt.Tier.Sealed() {
			continue
		}
		if f, seen := firstAt[at{rt.ID, rt.Tier}]; seen {
			windows := includedWindows
			if unnamed[endpointOf{rt.ID, rt.Endpoint}] {
				windows = nil
			}
			if differs := termsDiffer(rt, f, windows); differs != "" {
				return fmt.Errorf("endpoints %q and %q serve model %q at tier %s and differ in %s; a tier has one retail price and one set of plan terms, and a chat fails over between its endpoints and pays the terms of the endpoint it bound, so give them the same terms or serve one as another model", f.Endpoint, rt.Endpoint, rt.ID, rt.Tier, differs)
			}
			continue
		}
		firstAt[at{rt.ID, rt.Tier}] = rt
		f, seen := firstOf[rt.ID]
		if !seen {
			firstOf[rt.ID] = rt
			continue
		}
		if differs := termsDiffer(rt, f, includedWindows); differs != "" {
			tiersDiffer[rt.ID] = fmt.Sprintf("tiers %s and %s differ in %s", f.Tier, rt.Tier, differs)
		}
	}
	for _, rt := range served {
		if _, chats := ChatOf(rt.Serves); !chats || rt.Tier.Sealed() || tiersDiffer[rt.ID] == "" {
			continue
		}
		if !refusesDryAccount(rt) {
			return fmt.Errorf("model %q has %s, but endpoint %q is served through %s, which does not map a dry account to an account refusal; a dry account on one tier would then strand requests bound to it, since the refusal neither fails over to the other tier nor opens the circuit, so give the tiers the same terms or serve one as another model", rt.ID, tiersDiffer[rt.ID], rt.Endpoint, rt.Upstream)
		}
	}
	return samePromiseAtATier(served)
}

// termsDiffer names the first term the relay bills or gates by on which the two endpoints differ, or "". With no
// includedWindows it leaves the windows uncompared.
func termsDiffer(rt, f Route, includedWindows []int) string {
	c, _ := ChatOf(rt.Serves)
	fc, _ := ChatOf(f.Serves)
	switch {
	case !reflect.DeepEqual(c.Billed(), fc.Billed()):
		return "price or markup"
	case !reflect.DeepEqual(rt.Included, f.Included):
		return "included"
	case rt.Included != nil && !sameIncludedWindow(c.ContextTokens, fc.ContextTokens, includedWindows):
		return "context_tokens, which bounds an included request"
	case rt.RequiresPlan != f.RequiresPlan:
		return "requires_plan"
	case rt.ReasoningUncapped() != f.ReasoningUncapped():
		return "whether the provider reasons past the output limit, which sizes the hold"
	}
	return ""
}

// samePromiseAtATier refuses a model whose chat endpoints at one tier outside e2ee differ in a term the tier promises a
// client: a chat fails over between them, so whichever endpoint serves must keep it.
func samePromiseAtATier(served []Route) error {
	type at struct {
		id   catalog.ModelID
		tier catalog.Tier
	}
	first := map[at]Route{}
	for _, rt := range served {
		c, chats := ChatOf(rt.Serves)
		if !chats || rt.Tier.Sealed() {
			continue
		}
		f, seen := first[at{rt.ID, rt.Tier}]
		if !seen {
			first[at{rt.ID, rt.Tier}] = rt
			continue
		}
		fc, _ := ChatOf(f.Serves)
		var differs string
		switch {
		case rt.Retention != f.Retention:
			differs = "retention, which GET /v1/models shows"
		case c.DefaultReasoningEffort != fc.DefaultReasoningEffort:
			differs = "default_reasoning_effort, the effort a request that names none reasons at"
		case c.DefaultMaxTokens != fc.DefaultMaxTokens:
			differs = "default_max_tokens, the output limit a request that names none is held for and sent"
		default:
			continue
		}
		return fmt.Errorf("endpoints %q and %q serve model %q at tier %s and differ in %s; a chat fails over between them, so give them the same value", f.Endpoint, rt.Endpoint, rt.ID, rt.Tier, differs)
	}
	return nil
}

func sameIncludedWindow(a, b int, windows []int) bool {
	for _, w := range windows {
		if min(w, a) != min(w, b) {
			return false
		}
	}
	return true
}
