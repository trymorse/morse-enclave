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
		if !slices.ContainsFunc(m.endpoints, func(e endpoint) bool { return e.tier() == p && e.onBehalfOf == "" && !e.unnamed }) {
			return fmt.Errorf("model %q picks tier %s, which none of its named endpoints serves; GET /v1/models lists a model only at the tiers of its named endpoints, and an on-behalf endpoint only on the entry of the sealed endpoint it seals to", m.id, p)
		}
	}
	return nil
}
