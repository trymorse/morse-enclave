package enum

import (
	"fmt"
	"slices"
	"testing"
)

type colour uint8

const (
	red colour = iota + 1
	green
)

var colours = Names[colour]{red: "red", green: "green"}

func TestATableNamesOnlyItsFilledSlotsAndPrintsTheRest(t *testing.T) {
	if got := colours.String(green); got != "green" || !colours.Valid(green) {
		t.Errorf("green prints as %s", got)
	}
	for _, v := range []colour{0, 3, 200} {
		if got := colours.String(v); colours.Valid(v) || got != fmt.Sprintf("enum.colour(%d)", v) {
			t.Errorf("%d prints as %s", v, got)
		}
		if _, err := colours.MarshalText(v); err == nil {
			t.Errorf("%d marshalled", v)
		}
	}
	for name, want := range map[string]colour{"red": red, "green": green} {
		if got, ok := colours.Parse(name); !ok || got != want {
			t.Errorf("%q parsed as %d %t", name, got, ok)
		}
	}
	for _, name := range []string{"", "Red", "blue"} {
		if _, ok := colours.Parse(name); ok {
			t.Errorf("%q parsed", name)
		}
	}
	if got := colours.Values(); !slices.Equal(got, []colour{red, green}) {
		t.Errorf("values %v", got)
	}
	if got := colours.List(); got != "red, green" {
		t.Errorf("list %q", got)
	}
}
