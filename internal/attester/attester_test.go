package attester

import (
	"strings"
	"testing"
)

func TestAtDefaultsToTheProductionGatewayAndHoldsAnOverrideToTheBaseURLRule(t *testing.T) {
	for _, v := range Vendors() {
		if up, err := v.At(""); err != nil || up != (Upstream{BaseURL: v.Gateway, Host: strings.TrimPrefix(v.Gateway, "https://")}) {
			t.Errorf("%s at its default: %+v %v", v, up, err)
		}
	}
	if up, err := Phala.At("http://127.0.0.1:8080/"); err != nil || up != (Upstream{BaseURL: "http://127.0.0.1:8080", Host: "127.0.0.1"}) {
		t.Errorf("loopback override: %+v %v", up, err)
	}
	if _, err := Phala.At("inference.phala.com"); err == nil || err.Error() != "gateway must be an absolute URL such as https://inference.phala.com" {
		t.Errorf("bare host: %v, want the rule with the production gateway as its example", err)
	}
	for _, bad := range []string{"http://inference.phala.com", "https://u:p@inference.phala.com", "https://inference.phala.com?x=1", "https://inference.phala.com#f"} {
		if _, err := Phala.At(bad); err == nil || !strings.HasPrefix(err.Error(), "gateway must") {
			t.Errorf("%s: %v, want a refusal naming the gateway rule", bad, err)
		}
	}
}
