package privacyveil

import (
	"errors"
	"testing"
)

func TestHoldsJSONReadsEveryTextButIdentifiersAndMedia(t *testing.T) {
	v := veilOf([]string{"Call Jane Doe or Claude at 415-555-0199, at Smith & Sons"},
		map[string]Type{"Jane Doe": Name, "Claude": Name, "415-555-0199": Phone, "Smith & Sons": Address})
	for body, want := range map[string]bool{
		`{"model":"claude-opus","messages":[{"role":"user","content":"Call [NAME_1] or [NAME_2] at [PHONE_1]"}]}`:     false,
		`{"messages":[{"role":"user","content":"Call Jane Doe"}]}`:                                                    true,
		`{"system":[{"type":"text","text":"Ring 4155550199"}]}`:                                                       true,
		`{"tools":[{"type":"function","function":{"name":"claude","description":"Dial [PHONE_1]"}}]}`:                 false,
		`{"tools":[{"function":{"parameters":{"properties":{"to":{"enum":["Jane Doe"]}}}}}]}`:                         true,
		`{"content":[{"type":"image_url","image_url":{"url":"https://x.test/Jane Doe.png"}}]}`:                        false,
		`{"tool_calls":[{"id":"Claude","function":{"name":"Claude","arguments":"{\"to\":\"Smith \\u0026 Sons\"}"}}]}`: true,
		`{"tool_calls":[{"function":{"arguments":"{\"Jane Doe\":1}"}}]}`:                                              true,
		`{"content":[{"type":"tool_use","name":"dial","input":{"name":"Jane Doe"}}]}`:                                 true,
		`{"contents":[{"parts":[{"functionCall":{"name":"dial","args":{"to":4155550199}}}]}]}`:                        true,
		`{"n":4155550199}`: true,
		`Call Jane Doe`:    true,
	} {
		if got := v.HoldsJSON([]byte(body)); got != want {
			t.Errorf("HoldsJSON(%s) = %v, want %v", body, got, want)
		}
	}
	if err := v.Egress([]byte(`{"messages":[{"content":"Jane Doe"}]}`)); !errors.Is(err, ErrLeak) {
		t.Errorf("Egress of a leak = %v, want ErrLeak", err)
	}
	if New(nil, nil).HoldsJSON([]byte(`{"content":"Jane Doe"}`)) {
		t.Error("an empty veil found a leak")
	}
}
