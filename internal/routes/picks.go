package routes

import (
	"encoding/json"
	"fmt"
	"slices"

	"morse/backend/internal/catalog"
)

func (m model) checkPicks() error {
	raw, ok := m.fields["picks"]
	if !ok {
		return nil
	}
	var picks []string
	if err := json.Unmarshal(raw, &picks); err != nil || len(picks) == 0 {
		return fmt.Errorf("model %q has picks %s, which must be a non-empty list of the tiers whose menu Morse picks it for; leave it out to pick it for none", m.id, raw)
	}
	for i, p := range picks {
		if _, err := catalog.ParseTier(p); err != nil {
			return fmt.Errorf("model %q picks %w", m.id, err)
		}
		if slices.Contains(picks[:i], p) {
			return fmt.Errorf("model %q picks tier %s twice", m.id, p)
		}
		if !slices.ContainsFunc(m.endpoints, func(e endpoint) bool { return e.tier() == p && !e.unnamed }) {
			return fmt.Errorf("model %q picks tier %s, which none of its named endpoints serves; GET /v1/models lists a model only at the tiers of its named endpoints", m.id, p)
		}
	}
	return nil
}

func (m model) checkFlag() error {
	if _, ok := m.fields["flag"]; !ok {
		return nil
	}
	for _, e := range m.endpoints {
		if tier, err := catalog.ParseTier(e.tier()); err == nil && tier.Attested() {
			return fmt.Errorf("model %q sets flag and serves tier %s; a flag keeps a model's chats from a caller it does not admit, but its attestation and receipts would still name it, so only a model served wholly in the clear may set one", m.id, tier)
		}
	}
	return nil
}
