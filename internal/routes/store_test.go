package routes

import (
	"strings"
	"testing"
)

func TestARoutesFileCannotSetAFieldOfTheVendorRequestSuchAsStore(t *testing.T) {
	for _, field := range []string{`"store":true`, `"store":false`, `"force":{"store":true}`} {
		name, _, _ := strings.Cut(field, ":")
		name = strings.Trim(name, `"`)
		flat := `[` + strings.Replace(chatJSON, `{"model":"m",`, `{"model":"m",`+field+`,`, 1) + `]`
		endpoint := modelsFileOf(modelOf(strings.Replace(togetherEP, `"tier"`, field+`,"tier"`, 1)), ``)
		model := modelsFileOf(strings.Replace(modelOf(togetherEP), `"id":"z/m",`, `"id":"z/m",`+field+`,`, 1), ``)
		for form, file := range map[string]string{"a route": flat, "an endpoint": endpoint, "a model": model} {
			if _, err := parse([]byte(file)); err == nil || !strings.Contains(err.Error(), `"`+name+`"`) {
				t.Errorf("%s with %s: err %v, want a refusal naming %q", form, field, err, name)
			}
		}
	}
}
