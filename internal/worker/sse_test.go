package worker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPaddedObjectIsValidJSONAndKeepsEveryOriginalFieldRaw(t *testing.T) {
	for _, object := range []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"content":"<b> & \"q\" é"}}],"usage":null}`,
		`{"id":"c1","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":40}}` + "\n",
		`{ "a" : [1,  2.50] , "b":{"c":"}"} }`,
		`{}`,
		`{  }`,
	} {
		out := string(padObject([]byte(object), "Filler42"))
		if !json.Valid([]byte(out)) {
			t.Errorf("padding %q produced invalid JSON %q", object, out)
			continue
		}
		var before, after map[string]json.RawMessage
		json.Unmarshal([]byte(object), &before)
		json.Unmarshal([]byte(out), &after)
		if string(after["obfuscation"]) != `"Filler42"` || len(after) != len(before)+1 {
			t.Errorf("padding %q gave %q", object, out)
		}
		for key, raw := range before {
			if !bytes.Equal(after[key], raw) {
				t.Errorf("padding %q changed %s from %s to %s", object, key, raw, after[key])
			}
		}
		trimmed := strings.TrimRight(object, " \n")
		if prefix := trimmed[:len(trimmed)-1]; !strings.HasPrefix(out, prefix) {
			t.Errorf("padding %q rewrote original bytes: %q", object, out)
		}
	}
}

func TestObjectAlreadyCarryingPaddingIsForwardedByteIdentical(t *testing.T) {
	for _, object := range []string{
		`{"id":"c1","choices":[],"obfuscation":"abc"}`,
		`{"id":"c1","choices":[],"p":"abcdef"}`,
		`{"obfuscation":null,"choices":[]}`,
	} {
		if out := string(padObject([]byte(object), "Filler42")); out != object {
			t.Errorf("padded an already padded chunk: %q became %q", object, out)
		}
	}
}

func TestPaddingKeysMatchExactlySoCaseVariantsStillGetPadded(t *testing.T) {
	for _, object := range []string{
		`{"id":"c1","P":"abc"}`,
		`{"id":"c1","Obfuscation":"abc"}`,
	} {
		out := string(padObject([]byte(object), "Filler42"))
		if !strings.HasSuffix(out, `,"obfuscation":"Filler42"}`) {
			t.Errorf("case variant %q was treated as padded: %q", object, out)
		}
	}
}

func TestNonObjectIsForwardedUnchanged(t *testing.T) {
	for _, data := range []string{`null`, `[1,{}]`, `"x}"`, `42`, `not json}`, `{"a":}`, `{"a":1`, ``} {
		if out := string(padObject([]byte(data), "Filler42")); out != data {
			t.Errorf("non-object %q became %q", data, out)
		}
	}
}
