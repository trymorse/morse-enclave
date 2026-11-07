package routes

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"morse/backend/internal/attester"
	"morse/backend/internal/baseurl"
	"morse/backend/internal/catalog"
)

var providerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func (c common) upstream(tier catalog.Tier) (Upstream, error) {
	vendor, err := parseAttester(c.Attester, tier)
	if err != nil {
		return nil, err
	}
	if vendor == nil {
		provider, err := ParseProvider(c.Provider)
		if err != nil {
			return nil, err
		}
		return Vendor{Provider: provider}, nil
	}
	if c.Provider != "" {
		return nil, fmt.Errorf("is tier %s, so attester %s serves it and it takes no provider", tier, vendor)
	}
	return Attested{Attester: vendor}, nil
}

func (c common) checkProviderName(up Upstream) error {
	switch {
	case c.ProviderName == "":
		return errors.New("has no provider_name; set it to the lowercase name a customer knows the provider by, such as together, and an attested route's is its attester")
	case !providerNamePattern.MatchString(c.ProviderName):
		return fmt.Errorf("has provider_name %q; a provider name is lowercase letters, digits, and hyphens", c.ProviderName)
	}
	if a, attested := up.(Attested); attested && c.ProviderName != a.Attester.Name {
		return fmt.Errorf("has provider_name %q but attester %s; an attested route's provider_name is its attester", c.ProviderName, a.Attester.Name)
	}
	return nil
}

func parseAttester(raw string, tier catalog.Tier) (*attester.Vendor, error) {
	switch {
	case !tier.Attested() && raw != "":
		return nil, fmt.Errorf("is tier %s and takes no attester", tier)
	case !tier.Attested():
		return nil, nil
	case raw == "":
		return nil, fmt.Errorf("is tier %s and must name its attester, one of %v", tier, attester.Vendors())
	}
	return attester.Parse(raw)
}

func oneAttesterPerHost(routes []Route) error {
	type gate struct {
		model    string
		attester *attester.Vendor
	}
	named := map[string]gate{}
	for _, rt := range routes {
		for _, rt := range rt.Upstreams() {
			up, attested := rt.Upstream.(Attested)
			if !attested {
				continue
			}
			if first, ok := named[rt.Host]; ok && first.attester != up.Attester {
				return fmt.Errorf("routes %q and %q share host %s but name attesters %s and %s; one host has one attestation gate", first.model, rt.Model, rt.Host, first.attester, up.Attester)
			}
			named[rt.Host] = gate{rt.Model, up.Attester}
		}
	}
	return nil
}

func checkBaseURL(raw string, tier catalog.Tier) (*url.URL, error) {
	u, err := baseurl.Parse("base_url", "https://api.together.xyz", raw)
	if err != nil {
		return nil, err
	}
	if tier.Attested() && u.Scheme != "https" {
		return nil, fmt.Errorf("is tier %s and needs an https base_url", tier)
	}
	return u, nil
}
