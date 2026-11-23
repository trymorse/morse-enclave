package near

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

const (
	plainTools = `[{"type":"function","function":{"name":"get_weather","description":"Reads the weather.","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}},{"type":"function","function":{"name":"now"}}]`
	plainCalls = `[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}}]`
)

func TestAPlainToolListPassesOnlyWithTheFieldsV3Labels(t *testing.T) {
	if !Tools(json.RawMessage(plainTools), Plain) {
		t.Fatalf("%s does not pass, want a name with or without a description and parameters to pass", plainTools)
	}
	for name, tools := range map[string]string{
		"strict, which v3 has no label for": `[{"type":"function","function":{"name":"f","strict":true}}]`,
		"no name":                           `[{"type":"function","function":{"description":"d"}}]`,
		"parameters that are no object":     `[{"type":"function","function":{"name":"f","parameters":"{}"}}]`,
		"a description that is no string":   `[{"type":"function","function":{"name":"f","description":null}}]`,
		"a tool of another type":            `[{"type":"custom","function":{"name":"f"}}]`,
		"a key beside the function":         `[{"type":"function","function":{"name":"f"},"cache_control":{}}]`,
		"an empty list":                     `[]`,
		"no list":                           `{"type":"function"}`,
	} {
		if Tools(json.RawMessage(tools), Plain) {
			t.Errorf("%s: %s passes, want it refused", name, tools)
		}
	}
}

func TestAPlainCallListPassesOnlyWithAnIDNEARMayReadAndANameAndArguments(t *testing.T) {
	if !Calls(json.RawMessage(plainCalls), Plain) {
		t.Fatalf("%s does not pass", plainCalls)
	}
	for name, calls := range map[string]string{
		"an id that names the tool": `[{"id":"functions.get_weather:0","type":"function","function":{"name":"get_weather","arguments":"{}"}}]`,
		"no arguments":              `[{"id":"call_1","type":"function","function":{"name":"get_weather"}}]`,
		"arguments as an object":    `[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":{}}}]`,
		"a key beside the call":     `[{"id":"call_1","type":"function","index":0,"function":{"name":"f","arguments":"{}"}}]`,
		"no id":                     `[{"type":"function","function":{"name":"f","arguments":"{}"}}]`,
	} {
		if Calls(json.RawMessage(calls), Plain) {
			t.Errorf("%s: %s passes, want it refused", name, calls)
		}
	}
}

func TestSealedToolsAndCallsOpenUnderTheirOwnLabelsAndHoldNoPlaintext(t *testing.T) {
	model, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params := Params{Client: client, Model: model, V3: true}
	tools, err := SealTools(json.RawMessage(plainTools), params.Seal)
	if err != nil {
		t.Fatal(err)
	}
	calls, err := SealCalls(json.RawMessage(plainCalls), params.Seal)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"get_weather", "Reads the weather", "city", "Oslo"} {
		if strings.Contains(string(tools)+string(calls), plain) {
			t.Errorf("the sealed fields hold %q in the clear: %s %s", plain, tools, calls)
		}
	}
	ciphertext := func(_ string, raw json.RawMessage) bool { return IsCiphertext(raw) }
	if !Tools(tools, ciphertext) || !Calls(calls, ciphertext) {
		t.Fatalf("the sealed lists %s %s are not ciphertext in every labelled field", tools, calls)
	}
	var sealedTools []struct{ Function map[string]string }
	var sealedCalls []struct {
		ID       string
		Function map[string]string
	}
	json.Unmarshal(tools, &sealedTools)
	json.Unmarshal(calls, &sealedCalls)
	opened := func(label, sealed string) string {
		plain, err := params.Open(private, label, sealed)
		if err != nil {
			t.Errorf("%s does not open under its label: %v", label, err)
		}
		return string(plain)
	}
	weather := sealedTools[0].Function
	if got := opened(LabelToolName, weather["name"]) + "|" + opened(LabelToolDescription, weather["description"]) + "|" + opened(LabelToolParameters, weather["parameters"]); got != `get_weather|Reads the weather.|{"type":"object","properties":{"city":{"type":"string"}}}` {
		t.Errorf("the first tool opens to %q", got)
	}
	if _, set := sealedTools[1].Function["description"]; set || opened(LabelToolName, sealedTools[1].Function["name"]) != "now" {
		t.Errorf("the second tool seals to %v, want its name alone", sealedTools[1].Function)
	}
	call := sealedCalls[0]
	if got := call.ID + "|" + opened(LabelCallName, call.Function["name"]) + "|" + opened(LabelCallArguments, call.Function["arguments"]); got != `call_1|get_weather|{"city":"Oslo"}` {
		t.Errorf("the call opens to %q, want its id kept and its name and arguments sealed", got)
	}
	if _, err := params.Open(private, LabelToolDescription, weather["name"]); err == nil {
		t.Error("a tool's name opens under the description's label, want each field bound to its own")
	}
}
