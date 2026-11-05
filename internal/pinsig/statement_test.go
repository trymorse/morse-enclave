package pinsig

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/jcs"
)

func TestTheSignedStatementsParse(t *testing.T) {
	for name, want := range map[string]struct {
		environment string
		images      int
	}{"prod": {"prod", 11}, "dev": {"dev", 5}} {
		st, err := ParseStatement(readTestdata(t, "statements/"+name+".json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Environment != want.environment || st.Sequence != 101 || len(st.Images) != want.images || len(st.PinsCommit) != 40 || st.Time.IsZero() {
			t.Errorf("%s: parsed %+v", name, st)
		}
		if !st.Lists(st.Images[0].PCRs) {
			t.Errorf("%s: the first image is not listed", name)
		}
		if st.Lists([3][48]byte{}) {
			t.Errorf("%s: all-zero PCRs are listed", name)
		}
	}
}

func TestAStatementIsRefusedWhenItIsNotTheCanonicalShape(t *testing.T) {
	raw := readTestdata(t, "statements/prod.json")
	if !bytes.Contains(raw, []byte(`"sequence":101,`)) {
		t.Fatal("the prod statement no longer carries sequence 101; update this test's raw edits")
	}
	reshape := func(edit func(map[string]any)) []byte {
		var w map[string]any
		_ = json.Unmarshal(raw, &w)
		edit(w)
		out, _ := json.Marshal(w)
		canonical, err := jcs.Canonicalize(out)
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	first := func(m map[string]any) map[string]any { return m["images"].([]any)[0].(map[string]any) }
	for name, bad := range map[string][]byte{
		"indented":       append([]byte("{ "), raw[1:]...),
		"trailing byte":  append(append([]byte{}, raw...), '\n'),
		"unknown field":  reshape(func(m map[string]any) { m["note"] = "x" }),
		"missing type":   reshape(func(m map[string]any) { delete(m, "type") }),
		"other type":     reshape(func(m map[string]any) { m["type"] = "morse-enclave-pins-v2" }),
		"no environment": reshape(func(m map[string]any) { m["environment"] = "" }),
		"short commit":   reshape(func(m map[string]any) { m["pins_commit"] = "abc" }),
		"bad time":       reshape(func(m map[string]any) { m["time"] = "yesterday" }),
		"short pcr":      reshape(func(m map[string]any) { first(m)["pcr1"] = "ab" }),
		"all-zero pcrs": reshape(func(m map[string]any) {
			for _, k := range []string{"pcr0", "pcr1", "pcr2"} {
				first(m)[k] = strings.Repeat("0", 96)
			}
		}),
		"sequence float":  bytes.Replace(raw, []byte(`"sequence":101`), []byte(`"sequence":101.5`), 1),
		"sequence string": reshape(func(m map[string]any) { m["sequence"] = "101" }),
		"folded key":      reshape(func(m map[string]any) { m["\u017fequence"] = 999999 }),
		"folded image key": reshape(func(m map[string]any) {
			delete(first(m), "revoked")
			first(m)["revo\u212aed"] = true
		}),
		"null revoked":     reshape(func(m map[string]any) { first(m)["revoked"] = nil }),
		"null images":      reshape(func(m map[string]any) { m["images"] = nil }),
		"no images":        reshape(func(m map[string]any) { m["images"] = []any{} }),
		"missing pcr":      reshape(func(m map[string]any) { delete(first(m), "pcr2") }),
		"extra image key":  reshape(func(m map[string]any) { first(m)["note"] = "x" }),
		"revoked string":   reshape(func(m map[string]any) { first(m)["revoked"] = "false" }),
		"image not object": reshape(func(m map[string]any) { m["images"] = []any{"x"} }),
	} {
		if _, err := ParseStatement(bad); !errors.Is(err, ErrStatement) {
			t.Errorf("%s: got %v, want ErrStatement", name, err)
		}
	}
}

func TestAdmitRequiresTheEnvironmentTheFloorAndFreshness(t *testing.T) {
	st := Statement{Environment: "prod", Sequence: 101}
	logged := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		env   string
		floor uint64
		now   time.Time
		ok    bool
	}{
		"fresh at the floor":     {"prod", 101, logged.Add(29 * 24 * time.Hour), true},
		"above the floor":        {"prod", 7, logged, true},
		"other environment":      {"dev", 101, logged, false},
		"below the floor":        {"prod", 102, logged, false},
		"older than the max age": {"prod", 101, logged.Add(30*24*time.Hour + time.Second), false},
		"now before logging":     {"prod", 101, logged.Add(-time.Second), false},
		"zero now":               {"prod", 101, time.Time{}, false},
	} {
		err := Admit(st, c.env, c.floor, logged, c.now, 30*24*time.Hour)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrAdmit)) {
			t.Errorf("%s: got %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestARevokedEntryVetoesItsPCRs(t *testing.T) {
	var a, b [3][48]byte
	a[0][0], b[0][0] = 1, 2
	st := Statement{Images: []Image{{PCRs: a}, {PCRs: a, Revoked: true}, {PCRs: b, Revoked: true}}}
	if st.Lists(a) || st.Lists(b) {
		t.Error("a revoked entry still admits its PCRs")
	}
	if !(Statement{Images: []Image{{PCRs: a}}}).Lists(a) {
		t.Error("an unrevoked entry does not admit its PCRs")
	}
}
