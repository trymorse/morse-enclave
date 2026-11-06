package worker

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
)

type chatName struct {
	model     catalog.ModelID
	named     []chatRoute
	plaintext []chatRoute
	onBehalf  []chatRoute
	alias     bool
	idOnly    bool
	sealsAs   string
}

func indexChats(models map[string]Model) map[string]chatName {
	named := map[string][]chatRoute{}
	plaintext := map[catalog.ModelID][]chatRoute{}
	sealedName := map[catalog.ModelID]string{}
	for name, m := range models {
		for _, vendor := range append([]Model{m}, m.Fallbacks...) {
			c, chats := vendor.Serves.(Chat)
			if !chats {
				continue
			}
			r := c.route(m.ID, vendor)
			r.aliased = name != string(m.ID)
			named[name] = append(named[name], r)
			if r.tier.Sealed() {
				sealedName[m.ID] = name
			} else {
				plaintext[m.ID] = append(plaintext[m.ID], r)
			}
		}
		for _, vendor := range m.Unnamed {
			plaintext[m.ID] = append(plaintext[m.ID], vendor.Serves.(Chat).route(m.ID, vendor))
		}
		for _, vendor := range m.OnBehalf {
			r := vendor.Serves.(Chat).route(m.ID, vendor)
			r.seals = true
			plaintext[m.ID] = append(plaintext[m.ID], r)
		}
	}
	for _, routes := range plaintext {
		slices.SortFunc(routes, mostPrivateFirst)
	}
	chats := make(map[string]chatName, len(named))
	for name, routes := range named {
		n := chatName{model: routes[0].model, named: routes, onBehalf: onBehalfOf(routes), alias: string(routes[0].model) != name}
		if !n.alias {
			n.sealsAs = sealedName[n.model]
		}
		own := routes[0]
		switch {
		case !n.alias:
			n.plaintext = plaintext[n.model]
		case !own.tier.Sealed():
			n.plaintext = atTier(plaintext[n.model], own.tier)
		}
		if tee := atTier(plaintext[n.model], catalog.OnBehalfTier); len(n.onBehalf) > 0 && len(tee) > 0 {
			n.onBehalf = tee
		}
		chats[name] = n
	}
	for _, routes := range named {
		id := routes[0].model
		if _, taken := chats[string(id)]; !taken {
			sealsAs := sealedName[id]
			chats[string(id)] = chatName{model: id, named: named[sealsAs], plaintext: plaintext[id], sealsAs: sealsAs, idOnly: true}
		}
	}
	return chats
}

func onBehalfOf(named []chatRoute) []chatRoute {
	var routes []chatRoute
	for _, r := range named {
		tier, sealable := catalog.OnBehalf(r.aliased, r.tier, r.speaks != nil && r.speaks.SealsBody)
		if !sealable {
			continue
		}
		v := r.Upstream.(Verbatim)
		r.Upstream = Plain{Provider: v.Route.OnBehalf(), Attester: v.Route}
		r.speaks, r.tier, r.onBehalf = nil, tier, true
		routes = append(routes, r)
	}
	return routes
}

func mostPrivateFirst(a, b chatRoute) int {
	return cmp.Or(cmp.Compare(b.tier, a.tier), cmp.Compare(a.order, b.order), cmp.Compare(a.endpoint, b.endpoint))
}

type chatAsk uint8

const (
	askSealed chatAsk = iota + 1
	askPlain
	askOnBehalf
	askLooksSealed
)

func askOf(p protocol, keyCaller bool, req *chat.Request) chatAsk {
	switch {
	case p.scheme != nil:
		return askSealed
	case !keyCaller:
		return askPlain
	case openaicompat.LooksSealed(req):
		return askLooksSealed
	}
	return askOnBehalf
}

// inTheClear is a key caller's plaintext chat that the relay read on its way in, so a digest of it tells the relay
// nothing new (DESIGN.md Section 7, sk_ keys). A sealed body (cek) or one the vendor seals is never digested.
func (o Opening) inTheClear(ask chatAsk) bool { return o.cek == nil && ask == askOnBehalf }

func (n chatName) reach(p protocol, ask chatAsk, compaction bool, want providerAsk, keyFloor catalog.Tier) ([]chatRoute, error) {
	if ask == askSealed && n.idOnly {
		return nil, n.sealedElsewhere()
	}
	if ask != askSealed && n.alias && len(n.plaintext) > 0 {
		return n.plaintext, nil
	}
	crossing := want.crossesTiers && len(n.plaintext) > 0
	if ask == askOnBehalf && n.runsOnBehalf(max(want.floor, keyFloor), crossing) {
		return n.onBehalf, nil
	}
	if ask != askSealed && crossing {
		return n.plaintext, nil
	}
	if n.floorlessInTheClear(ask) {
		return n.plaintext, nil
	}
	if (ask == askPlain || ask == askOnBehalf) && n.idOnly && p.scheme == nil && p.err == nil && !compaction {
		return nil, n.sealUnder()
	}
	r := vendorFor(n.named, p)
	if err := r.misserved(p, compaction); err != nil {
		return nil, err
	}
	if !r.tier.Sealed() {
		return atTier(n.plaintext, r.tier), nil
	}
	return []chatRoute{r}, nil
}

func (n chatName) floorlessInTheClear(ask chatAsk) bool {
	return !n.alias && len(n.plaintext) > 0 && (ask == askOnBehalf || ask != askSealed && n.sealsAs == "")
}

func (n chatName) runsOnBehalf(floor catalog.Tier, crossing bool) bool {
	return len(n.onBehalf) > 0 && !slices.ContainsFunc(n.plaintext, inTheClearAt(floor)) && (floor <= catalog.OnBehalfTier || !crossing)
}

func (n chatName) optIn(routes []chatRoute, floor catalog.Tier) []chatRoute {
	clear := slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return !inTheClearAt(floor)(r) })
	if n.alias || len(clear) == 0 {
		return routes
	}
	return clear
}

func inTheClearAt(floor catalog.Tier) func(chatRoute) bool {
	return func(r chatRoute) bool { return !r.tier.Attested() && r.tier >= floor }
}

func (n chatName) sealUnder() error {
	return apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_header_missing", Code: "e2ee_header_missing", Message: fmt.Sprintf("A chat on this model is sealed to its e2ee endpoint, which serves it as %q, the name its receipt binds: seal the request and send model %q.", n.sealsAs, n.sealsAs)}
}

func (n chatName) sealedElsewhere() error {
	if n.sealsAs == "" {
		return errE2EEUnsupportedModel
	}
	return apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_unsupported_model", Code: "e2ee_unsupported_model", Message: fmt.Sprintf("A sealed request names the model its e2ee endpoint serves under, which the receipt binds: send model %q.", n.sealsAs)}
}

// atTier is the routes of one tier, in the order mostPrivateFirst gave them.
func atTier(routes []chatRoute, tier catalog.Tier) []chatRoute {
	return slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return r.tier != tier })
}

func (n chatName) sealable() bool {
	return !n.alias && slices.ContainsFunc(n.named, func(r chatRoute) bool { return r.tier.Sealed() })
}

func (n chatName) atFloor(routes []chatRoute, floor catalog.Tier) ([]chatRoute, error) {
	kept := slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return r.tier < floor })
	if len(kept) > 0 {
		return kept, nil
	}
	highest := slices.MaxFunc(routes, func(a, b chatRoute) int { return cmp.Compare(a.tier, b.tier) }).tier
	sealed := n.sealable()
	return nil, catalog.FloorError{Tier: highest, Floor: floor, InTheClear: !n.alias && (len(routes) > 1 || sealed), Sealable: sealed}
}

func endpointsOf(routes []chatRoute) []catalog.EndpointID {
	ids := make([]catalog.EndpointID, len(routes))
	for i, r := range routes {
		ids[i] = r.endpoint
	}
	return ids
}

func (o *openedChat) granted(ids []catalog.EndpointID) ([]chatRoute, bool) {
	if len(ids) == 0 {
		return nil, false
	}
	routes := make([]chatRoute, 0, len(ids))
	for i, id := range ids {
		at := slices.IndexFunc(o.routes, func(r chatRoute) bool { return r.endpoint == id })
		if at < 0 || slices.Contains(ids[:i], id) {
			return nil, false
		}
		routes = append(routes, o.routes[at])
	}
	return routes, true
}
