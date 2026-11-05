// Package openrouter serves chat on OpenRouter, held to its zero data retention endpoints.
package openrouter

import (
	"encoding/json"
	"math/big"
	"net/http"
	"slices"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

// Constraint rides every request. zdr routes it only to an endpoint OpenRouter lists as keeping nothing, max_price
// only to one whose prompt and completion rates are at most the route's, so an endpoint dearer than the price
// billed never serves it, and a client cannot loosen it: the proxy forwards no provider field of its own.
func Constraint(price money.Price, ignore ...string) json.RawMessage {
	c := `{"zdr":true,"data_collection":"deny","max_price":{"prompt":` + perMillion(price.PromptPerMTok) +
		`,"completion":` + perMillion(price.CompletionPerMTok) + `}`
	if len(ignore) > 0 {
		names, _ := json.Marshal(ignore)
		c += `,"ignore":` + string(names)
	}
	return json.RawMessage(c + `}`)
}

// max_price is in dollars per million tokens.
func perMillion(m money.Micros) string { return strconv.FormatFloat(float64(m)/1e6, 'f', -1, 64) }

type Chat struct {
	openaicompat.Provider
	vendor upstream.Endpoint
	model  string
	price  money.Price
}

var _ chat.Provider = (*Chat)(nil)

func NewChat(baseURL, apiKey, model string, price money.Price, client *http.Client) *Chat {
	c := &Chat{vendor: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}, model: model, price: price}
	c.Provider = c.routed(nil)
	return c
}

// routed serves under the constraint with the providers in ignore left out. OpenRouter does not fall back to another
// endpoint when the one it picked answers 429, so a busy refusal that names its provider reroutes past it, and past
// every provider already ignored. Once every provider is ignored OpenRouter answers 404, and the busy refusal stands
// for the caller to wait and retry.
func (c *Chat) routed(ignore []string) openaicompat.Provider {
	vendor := c.vendor
	vendor.Refuse = func(r upstream.Reply) error { return c.refuse(r, ignore) }
	return openaicompat.Provider{
		Sender:             openaicompat.HTTPSender{Endpoint: vendor},
		Model:              c.model,
		Force:              map[string]json.RawMessage{"provider": Constraint(c.price, ignore...)},
		LimitField:         openaicompat.MaxTokens,
		UsageOnFinalChoice: true,
		AnswersInReasoning: true,
		NamesHost:          true,
		// OpenRouter runs a server tool on its own backends and parses a file with Mistral OCR when the model reads
		// no files, and its zdr filter covers neither.
		Admit:        openaicompat.FunctionToolsTextAndImages,
		ChargeFields: []string{"cost", "cost_details", "is_byok"},
		VendorCost:   vendorCost,
	}
}

// vendorCost reads usage.cost, in dollars. On a call through our own provider key (is_byok) cost is only
// OpenRouter's fee, and the provider's charge is cost_details.upstream_inference_cost, so the two add. A call that
// does not say it is BYOK and still reports a positive upstream cost takes the larger figure, which is cost when the
// call was not BYOK and the provider's charge, short of the fee, when it was.
func vendorCost(usage json.RawMessage) chat.VendorCost {
	var u struct {
		Cost        *json.Number `json:"cost"`
		CostDetails struct {
			Upstream *json.Number `json:"upstream_inference_cost"`
		} `json:"cost_details"`
		BYOK bool `json:"is_byok"`
	}
	if json.Unmarshal(usage, &u) != nil {
		return chat.VendorCost{Read: chat.CostUnreadable}
	}
	upstream, hasUpstream := microsRoundedUp(u.CostDetails.Upstream)
	switch {
	case u.BYOK && u.CostDetails.Upstream == nil:
		return chat.VendorCost{Read: chat.CostBYOKUpstreamMissing, BYOK: true}
	case u.Cost == nil:
		return chat.VendorCost{BYOK: u.BYOK}
	}
	cost, ok := microsRoundedUp(u.Cost)
	if !ok || u.CostDetails.Upstream != nil && !hasUpstream {
		return chat.VendorCost{Read: chat.CostUnreadable, BYOK: u.BYOK}
	}
	switch {
	case u.BYOK:
		cost += upstream
	case upstream > 0:
		cost = max(cost, upstream)
	}
	return chat.VendorCost{Read: chat.CostReported, Micros: cost, BYOK: u.BYOK}
}

func microsRoundedUp(dollars *json.Number) (int64, bool) {
	if dollars == nil {
		return 0, false
	}
	r, ok := new(big.Rat).SetString(dollars.String())
	if !ok {
		return 0, false
	}
	r.Mul(r, big.NewRat(1_000_000, 1))
	q, rem := new(big.Int).QuoRem(r.Num(), r.Denom(), new(big.Int))
	if rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q.Int64(), q.IsInt64()
}

func (c *Chat) refuse(r upstream.Reply, ignore []string) error {
	if len(ignore) > 0 && r.Status == http.StatusNotFound {
		return apierr.ErrUpstreamBusy
	}
	var body struct {
		Error struct {
			Metadata struct {
				ProviderName string   `json:"provider_name"`
				Reasons      []string `json:"reasons"`
				FlaggedInput string   `json:"flagged_input"`
			} `json:"metadata"`
		} `json:"error"`
	}
	json.Unmarshal(r.Body, &body)
	meta := body.Error.Metadata
	if r.Status == http.StatusForbidden && (len(meta.Reasons) > 0 || meta.FlaggedInput != "") {
		return apierr.ErrContentFilter
	}
	e := apierr.SanitizedUpstreamError(r.Status, r.Body)
	if e != apierr.ErrUpstreamBusy || meta.ProviderName == "" {
		return e
	}
	return refusedBy{err: e, chat: c, ignore: append(slices.Clone(ignore), meta.ProviderName)}
}

type refusedBy struct {
	err    apierr.Error
	chat   *Chat
	ignore []string
}

func (r refusedBy) Error() string { return r.err.Error() }
func (r refusedBy) Unwrap() error { return r.err }

func (r refusedBy) Reroute() chat.Provider {
	p := r.chat.routed(r.ignore)
	return &p
}
