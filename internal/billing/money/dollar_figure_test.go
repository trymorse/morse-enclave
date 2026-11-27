package money

import (
	"encoding/json"
	"testing"
)

func TestADollarFigureIsTheMicrosAsAnExactJSONNumberOfDollars(t *testing.T) {
	for micros, want := range map[Micros]string{
		0:                     "0",
		1:                     "0.000001",
		412:                   "0.000412",
		100_000:               "0.1",
		1_000_000:             "1",
		2_500_000:             "2.5",
		12_345_678:            "12.345678",
		9_007_199_254_740_993: "9007199254.740993",
		-1_500:                "-0.0015",
	} {
		got := micros.DollarFigure()
		if got != want || !json.Valid([]byte(got)) {
			t.Errorf("%d micros read %s, want %s", micros, got, want)
		}
	}
}
