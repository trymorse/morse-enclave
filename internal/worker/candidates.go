package worker

import (
	"cmp"
	"slices"

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
}

func indexChats(models map[string]Model) map[string]chatName {
	named := map[string][]chatRoute{}
	plaintext := map[catalog.ModelID][]chatRoute{}
	for name, m := range models {
		for _, vendor := range append([]Model{m}, m.Fallbacks...) {
			c, chats := vendor.Serves.(Chat)
			if !chats {
				continue
			}
			r := c.route(m.ID, vendor)
			named[name] = append(named[name], r)
			if !r.tier.Sealed() {
				plaintext[m.ID] = append(plaintext[m.ID], r)
			}
		}
		for _, vendor := range m.Unnamed {
			plaintext[m.ID] = append(plaintext[m.ID], vendor.Serves.(Chat).route(m.ID, vendor))
		}
	}
	for _, routes := range plaintext {
		slices.SortFunc(routes, mostPrivateFirst)
	}
	chats := make(map[string]chatName, len(named))
	for name, routes := range named {
		n := chatName{model: routes[0].model, named: routes, onBehalf: onBehalfOf(name, routes), alias: string(routes[0].model) != name}
		own := routes[0]
		switch {
		case !n.alias:
			n.plaintext = plaintext[n.model]
		case !own.tier.Sealed():
			n.plaintext = atTier(plaintext[n.model], own.tier)
		}
		chats[name] = n
	}
	return chats
}

func onBehalfOf(name string, named []chatRoute) []chatRoute {
	var routes []chatRoute
	for _, r := range named {
		tier, sealable := catalog.OnBehalf(name, r.model, r.tier, r.speaks != nil && r.speaks.SealsBody)
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

func (n chatName) reach(p protocol, ask chatAsk, compaction, crossing bool) ([]chatRoute, error) {
	if ask != askSealed && (n.alias || crossing) && len(n.plaintext) > 0 {
		return n.plaintext, nil
	}
	if ask == askOnBehalf && len(n.onBehalf) > 0 {
		return n.onBehalf, nil
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
