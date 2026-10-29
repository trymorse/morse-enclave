package vendors

import (
	"maps"
	"slices"
	"testing"

	"morse/backend/internal/catalog"
	"morse/backend/internal/routes"
)

func TestEveryProviderAndKindRoutesAcceptsHasABuilderAndNoBuilderIsUnreachable(t *testing.T) {
	for _, p := range routes.Providers() {
		for _, kind := range catalog.Kinds() {
			if built := builders[p][kind] != nil; built != p.Serves(kind) {
				t.Errorf("provider %s, kind %s: the routes file accepts it %t, the proxy builds it %t", p, kind, p.Serves(kind), built)
			}
		}
	}
	for p, kinds := range builders {
		if !slices.Contains(routes.Providers(), p) {
			t.Errorf("provider %s has builders for %v but no capabilities", p, slices.Collect(maps.Keys(kinds)))
		}
	}
}
