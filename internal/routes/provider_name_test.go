package routes

import (
	"strings"
	"testing"
)

func TestARouteNamesItsPublicProviderInLowercaseAndAnAttestedRoutesIsItsAttester(t *testing.T) {
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  string
	}{
		"none":                        {chatJSON, map[string]any{"provider_name": nil}, `route "m" has no provider_name`},
		"an empty one":                {chatJSON, map[string]any{"provider_name": ""}, `route "m" has no provider_name`},
		"capitals":                    {chatJSON, map[string]any{"provider_name": "Together"}, `route "m" has provider_name "Together"; a provider name is lowercase letters, digits, and hyphens`},
		"a space":                     {chatJSON, map[string]any{"provider_name": "together ai"}, `has provider_name "together ai"`},
		"a leading hyphen":            {chatJSON, map[string]any{"provider_name": "-together"}, `has provider_name "-together"`},
		"a dot":                       {chatJSON, map[string]any{"provider_name": "together.xyz"}, `has provider_name "together.xyz"`},
		"none on an image":            {imageJSON, map[string]any{"provider_name": nil}, `route "i" has no provider_name`},
		"none on a search":            {searchJSON, map[string]any{"provider_name": nil}, `route "s" has no provider_name`},
		"none on a transcription":     {nearWhisper, map[string]any{"provider_name": nil}, `route "whisper-tee" has no provider_name`},
		"another name on a tee route": {chatJSON, map[string]any{"tier": "tee", "attester": "phala", "provider_name": "together"}, `route "m" has provider_name "together" but attester phala; an attested route's provider_name is its attester`},
		"another name on an e2ee one": {chatJSON, map[string]any{"tier": "e2ee", "attester": "near", "model": "up/m", "default_max_tokens": 16384, "provider_name": "phala"}, `has provider_name "phala" but attester near`},
	} {
		if _, err := parse(patched(t, c.base, c.patch)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		base  string
		patch map[string]any
		want  string
	}{
		"a plain endpoint":      {chatJSON, map[string]any{"provider_name": "together-ai"}, "together-ai"},
		"digits":                {chatJSON, map[string]any{"provider_name": "3m"}, "3m"},
		"an attested endpoint":  {chatJSON, map[string]any{"tier": "tee", "attester": "phala"}, "phala"},
		"a media endpoint":      {imageJSON, nil, "fal"},
		"a per-call endpoint":   {searchJSON, nil, "parallel"},
		"a provider of its own": {chatJSON, map[string]any{"provider": "deepinfra", "provider_name": "open-router", "api_key_env": "K", "retention": "zdr"}, "open-router"},
	} {
		rts, err := parse(patched(t, c.base, c.patch))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if rts[0].ProviderName != c.want {
			t.Errorf("%s: provider name %q, want %q", name, rts[0].ProviderName, c.want)
		}
	}
}

func TestAFallbackNamesItsOwnAttesterAsItsProvider(t *testing.T) {
	const sealed = `{"model":"z/m","provider_name":"near","label":"M","tier":"e2ee","attester":"near","base_url":"https://cloud-api.near.ai","api_key_env":"NEAR_API_KEY","upstream_model":"z/m",` + tokenPriced
	for name, c := range map[string]struct{ fallback, want string }{
		"naming none":               {`{"attester":"phala","base_url":"https://inference.phala.com"}`, `fallback "phala": route "z/m" has no provider_name`},
		"naming the route's own":    {`{"attester":"phala","provider_name":"near","base_url":"https://inference.phala.com"}`, `fallback "phala": route "z/m" has provider_name "near" but attester phala`},
		"naming its own attester":   {`{"attester":"phala","provider_name":"phala","base_url":"https://inference.phala.com"}`, ``},
		"naming it in capital":      {`{"attester":"phala","provider_name":"Phala","base_url":"https://inference.phala.com"}`, `has provider_name "Phala"`},
		"naming another attester":   {`{"attester":"phala","provider_name":"tinfoil","base_url":"https://inference.phala.com"}`, `has provider_name "tinfoil" but attester phala`},
		"on a host of its attester": {`{"attester":"tinfoil","provider_name":"tinfoil","base_url":"https://inference.tinfoil.sh"}`, ``},
	} {
		rts, err := parse([]byte(`[` + sealed + `,"fallbacks":[` + c.fallback + `]}]`))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		case c.want == "" && (rts[0].ProviderName != "near" || rts[0].Fallbacks[0].ProviderName != rts[0].Fallbacks[0].Upstream.(Attested).Attester.Name):
			t.Errorf("%s: route %q fallback %q", name, rts[0].ProviderName, rts[0].Fallbacks[0].ProviderName)
		}
	}
}

func TestAnEndpointOfAModelsObjectNamesItsProviderAndSealedFallbacksEachNameTheirOwn(t *testing.T) {
	for name, c := range map[string]struct{ file, want string }{
		"an endpoint with none":                    {modelsFileOf(modelOf(strings.Replace(togetherEP, `"provider_name":"together",`, ``, 1)), ``), `route "z/m" has no provider_name`},
		"an endpoint with a malformed one":         {modelsFileOf(modelOf(strings.Replace(togetherEP, `"provider_name":"together"`, `"provider_name":"Together AI"`, 1)), ``), `has provider_name "Together AI"`},
		"an attested endpoint with another":        {modelsFileOf(modelOf(strings.Replace(phalaTEEEP, `"provider_name":"phala"`, `"provider_name":"near"`, 1)), ``), `has provider_name "near" but attester phala`},
		"a later sealed endpoint with the first's": {modelsFileOf(modelOf(nearEP, strings.Replace(phalaEP, `"provider_name":"phala"`, `"provider_name":"near"`, 1)), ``), `has provider_name "near" but attester phala`},
	} {
		if _, err := parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	rts, err := parse([]byte(modelsFileOf(modelOf(nearEP, phalaEP), ``)))
	if err != nil || len(rts) != 1 || rts[0].ProviderName != "near" || rts[0].Fallbacks[0].ProviderName != "phala" {
		t.Fatalf("a sealed endpoint and its fallback load as %+v, %v, want provider names near and phala", rts, err)
	}
}

func TestAnOnBehalfEndpointTakesTheProviderNameOfTheSealedEndpointItNames(t *testing.T) {
	rts, err := parseForRelay([]byte(onBehalfFile(togetherEP, onBehalfEP, phalaTEEAtOnBehalfDefault, nearEP)))
	if err != nil {
		t.Fatal(err)
	}
	sealed := rts[2]
	if got := sealed.OnBehalf[0].ProviderName; got != "near" || got != sealed.ProviderName {
		t.Errorf("near-on-behalf has provider name %q beside its sealed endpoint's %q, want near", got, sealed.ProviderName)
	}
	own := strings.Replace(onBehalfEP, `"tier"`, `"provider_name":"together","tier"`, 1)
	if _, err := parseForRelay([]byte(onBehalfFile(nearEP, own))); err == nil || !strings.Contains(err.Error(), `endpoint "near-on-behalf" is on behalf of endpoint "near" and sets "provider_name"`) {
		t.Errorf("an on-behalf endpoint naming its own provider: err %v, want a refusal naming provider_name", err)
	}
}
