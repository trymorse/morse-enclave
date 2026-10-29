package money_test

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"morse/backend/internal/billing/money"
)

func TestCreditsAreAHundredToTheDollarAndPrintExactlyWithoutTrailingZeros(t *testing.T) {
	for micros, want := range map[money.Micros]string{
		0:                      "0",
		1:                      "0.0001",
		10:                     "0.001",
		1_000:                  "0.1",
		10_000:                 "1",
		1_000_000:              "100",
		1_234_567:              "123.4567",
		5_000_000:              "500",
		-5:                     "-0.0005",
		-1_250_000:             "-125",
		math.MaxInt64:          "922337203685477.5807",
		math.MinInt64:          "-922337203685477.5808",
		money.MaxMicrosPerUnit: "1000",
	} {
		if got := micros.Credits().String(); got != want {
			t.Errorf("%d micros = %s credits, want %s", micros, got, want)
		}
		got, err := json.Marshal(struct {
			Balance money.Credits `json:"balance"`
		}{micros.Credits()})
		if err != nil || string(got) != `{"balance":`+want+`}` {
			t.Errorf("%d micros marshal to %s (%v)", micros, got, err)
		}
		var back struct{ Balance float64 }
		if err := json.Unmarshal(got, &back); err != nil {
			t.Errorf("%s is not a JSON number: %v", got, err)
		}
	}
}

func TestParseCreditsIsExactToTheMicroAndRefusesAnythingElse(t *testing.T) {
	for text, want := range map[string]money.Micros{
		"0":                    0,
		"1":                    10_000,
		"500":                  5_000_000,
		"0.5":                  5_000,
		"12.3456":              123_456,
		"0.0001":               1,
		"007.10":               71_000,
		"922337203685477.5807": math.MaxInt64,
	} {
		if got, err := money.ParseCredits(text); err != nil || got != want {
			t.Errorf("%q = %d (%v), want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", ".", "1.", ".5", "-1", "+1", "1.23456", "1e3", " 1", "1,000", "0x10", "1.2.3", "922337203685477.5808", "99999999999999999999"} {
		if got, err := money.ParseCredits(text); !errors.Is(err, money.ErrInvalidCredits) {
			t.Errorf("%q = %d (%v), want ErrInvalidCredits", text, got, err)
		}
	}
}
