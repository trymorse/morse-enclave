package routes

import (
	"fmt"
	"maps"
	"slices"

	"morse/backend/internal/attester"
	"morse/backend/internal/catalog"
	"morse/backend/internal/enum"
)

type Held uint8

const (
	HeldPublishedTerms Held = iota + 1
	HeldRequestHeader
	HeldReplyCheck
	HeldAccountAgreement
)

var heldNames = enum.Names[Held]{
	HeldPublishedTerms:   "published_terms",
	HeldRequestHeader:    "request_header",
	HeldReplyCheck:       "reply_check",
	HeldAccountAgreement: "account_agreement",
}

func (h Held) String() string { return heldNames.String(h) }

func (h Held) MarshalText() ([]byte, error) { return heldNames.MarshalText(h) }

type ZeroRetention struct {
	Tiers       []catalog.Tier
	Why         string
	Link        string
	LinkChecked string
	Agreed      string
	Held        Held
}

type HostProfile struct {
	Name          string
	Attested      bool
	Kinds         map[catalog.Kind][]catalog.Tier
	ZeroRetention *ZeroRetention
	Makes         map[string]string
}

func (p HostProfile) KeepsNothingAt(t catalog.Tier, k catalog.Kind) bool {
	if p.Attested {
		return slices.Contains(p.Kinds[k], t)
	}
	return p.ZeroRetention != nil && slices.Contains(p.ZeroRetention.Tiers, t) && slices.Contains(p.Kinds[k], t)
}

func (p HostProfile) Maker(host, lab string) bool {
	made, ok := p.Makes[host]
	return ok && lab != "" && made == lab
}

func HostProfiles() []HostProfile {
	var all []HostProfile
	for _, p := range Providers() {
		all = append(all, p.profile())
	}
	for _, v := range attester.Vendors() {
		all = append(all, attestedProfile(v))
	}
	return all
}

func (p Provider) profile() HostProfile {
	c := capabilities[p]
	profile := HostProfile{Name: p.String(), Kinds: maps.Clone(c.kinds), Makes: maps.Clone(c.makes)}
	if len(c.zdrAt) > 0 {
		profile.ZeroRetention = &ZeroRetention{Tiers: slices.Clone(c.zdrAt), Why: c.zdrWhy, Link: c.zdrLink, LinkChecked: c.zdrLinkChecked, Agreed: c.zdrAgreed, Held: c.zdrHeld}
	}
	return profile
}

func attestedProfile(v *attester.Vendor) HostProfile {
	return HostProfile{Name: v.Name, Attested: true, Kinds: attestedCapability(v).kinds}
}

func (rt Route) Profile() HostProfile {
	switch up := rt.Upstream.(type) {
	case Attested:
		return attestedProfile(up.Attester)
	case Vendor:
		return up.Provider.profile()
	}
	panic(fmt.Sprintf("routes: route %q has no upstream", rt.Model))
}
