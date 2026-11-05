package pinsig

import (
	"encoding/json"
	"testing"
)

// FuzzVerifyBundle proves that no bundle, however malformed, panics the
// verifier.
func FuzzVerifyBundle(f *testing.F) {
	root, err := ParseTrustRoot(readTestdata(f, "forged/trusted_root.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, index := range []string{"real.json", "forged/cases.json"} {
		var cases []storedCase
		if err := json.Unmarshal(readTestdata(f, index), &cases); err != nil {
			f.Fatal(err)
		}
		for _, c := range cases {
			f.Add(readTestdata(f, c.Bundle))
		}
	}
	blob := readTestdata(f, "statements/prod.json")
	f.Fuzz(func(t *testing.T, bundle []byte) {
		_, _ = VerifyBundle(blob, bundle, root, pinsIdentity)
	})
}

func FuzzParseStatement(f *testing.F) {
	f.Add(readTestdata(f, "statements/prod.json"))
	f.Add(readTestdata(f, "statements/dev.json"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseStatement(raw)
	})
}
