package exactjson

import (
	"testing"
)

func TestKeysMatchExactlyAndTheLastDuplicateWins(t *testing.T) {
	doc := Parse([]byte(`{"Key": 1, "key": 2, "KEY": 3, "key": 4, "other": null}`))
	if got := doc.Key("key").Uint(); got != 4 || doc.Err() != nil {
		t.Fatalf("key = %d, %v; want the last exact spelling, 4", got, doc.Err())
	}
	if !doc.Has("other") || !doc.Has("KEY") || doc.Has("kEy") {
		t.Fatal("a null member is present, and a case variant is a key of its own")
	}
	if doc.Key("other").Uint() != 0 || doc.Err() == nil {
		t.Fatal("a null member reads as nothing")
	}
	folded := Parse([]byte(`{"ſequence": 1}`))
	if folded.Has("sequence") {
		t.Fatal("ſ folds to s under encoding/json, never here")
	}
}

func TestTheReadKeepsItsFirstErrorAndReadsNothingAfterIt(t *testing.T) {
	doc := Parse([]byte(`{"a": {"b": "x"}}`))
	missing := doc.Key("a").Key("c").Key("d")
	if missing.Text() != "" || doc.Err() == nil || doc.Err().Error() != "a.c: absent" {
		t.Fatalf("got %v", doc.Err())
	}
	if doc.Key("a").Key("b").Text() != "" {
		t.Fatal("a read past the failure must read nothing")
	}
	if Parse([]byte(`{`)).Err() == nil || Parse([]byte(`[1]`)).Key("a").Err() == nil {
		t.Fatal("invalid JSON and a non-object fail")
	}
	if items := Parse([]byte(`{"a": "x"}`)).Key("a").Items(); items != nil {
		t.Fatal("a string has no items")
	}
}

func TestUintAcceptsEveryLexicalFormOfASafeIntegerAndNothingElse(t *testing.T) {
	for raw, want := range map[string]uint64{
		`1`: 1, `1.0`: 1, `1e3`: 1000, `1.793849732e9`: 1793849732, `-0`: 0, `1e-400`: 0,
		`9007199254740991`: 9007199254740991, `"1793849732"`: 1793849732, `"\u0031793849732"`: 1793849732, `"007"`: 7,
	} {
		doc := Parse([]byte(`{"n": ` + raw + `}`))
		if got := doc.Key("n").Uint(); got != want || doc.Err() != nil {
			t.Errorf("%s: got %d, %v, want %d", raw, got, doc.Err(), want)
		}
	}
	for _, raw := range []string{`-1`, `1.5`, `9007199254740992`, `9007199254740993`, `1e400`, `"9007199254740992"`, `"1 "`, `" 1"`, `"+1"`, `"1.0"`, `""`, `"\"1"`, `true`, `null`, `[1]`} {
		if doc := Parse([]byte(`{"n": ` + raw + `}`)); doc.Key("n").Uint() != 0 || doc.Err() == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

func TestBytesAcceptsPaddedStandardBase64WithNoWhitespace(t *testing.T) {
	for raw, want := range map[string]string{`"QUJD"`: "ABC", `"QUI="`: "AB", `"QQ=="`: "A", `""`: ""} {
		doc := Parse([]byte(`{"b": ` + raw + `}`))
		if got := string(doc.Key("b").Bytes()); got != want || doc.Err() != nil {
			t.Errorf("%s: got %q, %v", raw, got, doc.Err())
		}
	}
	for _, raw := range []string{`"QU\nJD"`, `"QU\r\nJD"`, `"QUJD\n"`, `"QUJD "`, `"QU\tJD"`, `"QUI"`, `"QUJ-"`, `"QUJ_"`, `"QQ="`, `"Q==="`, `"QQ==QQ=="`, `1`, `null`} {
		if doc := Parse([]byte(`{"b": ` + raw + `}`)); doc.Key("b").Bytes() != nil || doc.Err() == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}
