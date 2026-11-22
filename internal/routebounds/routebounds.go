package routebounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"morse/backend/internal/catalog"
)

type Rule uint8

const (
	NewValue Rule = iota + 1
	NewPairing
	AttestedChanged
	ClaimRaised
)

var ValueKeys = [...]string{"api_key_env", "provider", "base_url"}

type Breach struct {
	Rule  Rule
	Key   string
	Names []string
}

func (b Breach) String() string {
	names := strings.Join(b.Names, ", ")
	switch b.Rule {
	case NewValue:
		return fmt.Sprintf("names the %s %s, which the base does not", b.Key, names)
	case NewPairing:
		return fmt.Sprintf("pairs a provider, api_key_env and base_url on the endpoints %s as no endpoint of the base does", names)
	case AttestedChanged:
		return fmt.Sprintf("adds or changes the tee or e2ee endpoints %s", names)
	case ClaimRaised:
		return fmt.Sprintf("gives the endpoints %s a higher tier or a stronger retention than any endpoint of the base on the same base_url has", names)
	}
	return fmt.Sprintf("breaks the unnamed rule %d on %s", b.Rule, names)
}

type claim struct {
	tier      catalog.Tier
	retention catalog.Retention
}

func (c claim) known() bool { return c.tier.Valid() && c.retention != 0 }

func (c claim) above(top claim) bool {
	return !c.known() || c.tier > top.tier || c.retention > top.retention
}

type endpoint struct {
	name     string
	pairing  string
	identity string
	host     string
	attested bool
	claim    claim
}

type Table struct {
	values    map[string][]string
	endpoints []endpoint
}

func canonical(v any) (string, error) {
	out, err := json.Marshal(v)
	return string(out), err
}

func stringsAt(v any, key string, into *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t[key].(string); ok {
			*into = append(*into, s)
		}
		for _, child := range t {
			stringsAt(child, key, into)
		}
	case []any:
		for _, child := range t {
			stringsAt(child, key, into)
		}
	}
}

func claimOf(object map[string]any) claim {
	var c claim
	if name, ok := object["tier"].(string); ok {
		c.tier, _ = catalog.ParseTier(name)
	}
	switch retention := object["retention"].(type) {
	case nil:
		c.retention = catalog.RetentionVendor
	case string:
		if retention == "" {
			c.retention = catalog.RetentionVendor
		} else {
			c.retention, _ = catalog.ParseRetention(retention)
		}
	}
	return c
}

func decode(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data follows the JSON value")
	}
	return nil
}

func Read(routes []byte) (Table, error) {
	var whole any
	if err := decode(routes, &whole); err != nil {
		return Table{}, err
	}
	var file struct {
		Models []struct {
			ID        string           `json:"id"`
			Endpoints []map[string]any `json:"endpoints"`
		} `json:"models"`
	}
	if err := decode(routes, &file); err != nil {
		return Table{}, err
	}
	t := Table{values: map[string][]string{}}
	for _, key := range ValueKeys {
		var found []string
		stringsAt(whole, key, &found)
		slices.Sort(found)
		t.values[key] = slices.Compact(found)
	}
	for _, m := range file.Models {
		for _, object := range m.Endpoints {
			id, _ := object["id"].(string)
			e := endpoint{name: m.ID + " " + id, claim: claimOf(object)}
			var err error
			if e.pairing, err = canonical(map[string]any{"provider": object["provider"], "api_key_env": object["api_key_env"], "base_url": object["base_url"]}); err != nil {
				return Table{}, fmt.Errorf("%s: %w", e.name, err)
			}
			if e.identity, err = canonical(map[string]any{"model": m.ID, "endpoint": object}); err != nil {
				return Table{}, fmt.Errorf("%s: %w", e.name, err)
			}
			if e.host, err = canonical(object["base_url"]); err != nil {
				return Table{}, fmt.Errorf("%s: %w", e.name, err)
			}
			e.attested = e.claim.tier.Attested()
			t.endpoints = append(t.endpoints, e)
		}
	}
	return t, nil
}

func (boot Table) Breaches(offered Table) []Breach {
	var breaches []Breach
	for _, key := range ValueKeys {
		var added []string
		for _, value := range offered.values[key] {
			if !slices.Contains(boot.values[key], value) {
				added = append(added, value)
			}
		}
		if len(added) > 0 {
			breaches = append(breaches, Breach{Rule: NewValue, Key: key, Names: added})
		}
	}
	pairings, attested, ceilings := map[string]bool{}, map[string]bool{}, map[string]claim{}
	for _, e := range boot.endpoints {
		pairings[e.pairing] = true
		if e.attested {
			attested[e.identity] = true
		}
		top := ceilings[e.host]
		ceilings[e.host] = claim{tier: max(top.tier, e.claim.tier), retention: max(top.retention, e.claim.retention)}
	}
	var repaired, changed, raised []string
	for _, e := range offered.endpoints {
		if !pairings[e.pairing] {
			repaired = append(repaired, e.name)
		}
		if e.attested && !attested[e.identity] {
			changed = append(changed, e.name)
		}
		if top, served := ceilings[e.host]; served && e.claim.above(top) {
			raised = append(raised, e.name)
		}
	}
	slices.Sort(changed)
	for _, b := range []Breach{{Rule: NewPairing, Names: repaired}, {Rule: AttestedChanged, Names: changed}, {Rule: ClaimRaised, Names: raised}} {
		if len(b.Names) > 0 {
			breaches = append(breaches, b)
		}
	}
	return breaches
}
