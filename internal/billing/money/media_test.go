package money_test

import (
	"encoding/json"
	"testing"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
)

func TestMediaHoldIsUnitsTimesThePerUnitAndPerReferencePricesAtTheMarkupAndAtLeastACreditAnOutput(t *testing.T) {
	list := money.MediaPrice{PerUnit: 80_000, PerReference: 65_000}
	marked := money.MediaPrice{PerUnit: 75_000, PerReference: 60_000, Markup: testMarkup}
	cheap := money.MediaPrice{PerUnit: 5_000, Markup: testMarkup}
	for _, c := range []struct {
		price                money.MediaPrice
		units, refs, outputs int
		want                 money.Micros
	}{
		{list, 1, 0, 0, 80_000},
		{list, 4, 0, 0, 320_000},
		{list, 2, 3, 0, 2 * (80_000 + 3*65_000)},
		{list, 0, 5, 0, 0},
		{list, 90, 20, 0, 90 * (80_000 + 20*65_000)},
		{marked, 1, 0, 1, 112_500},
		{marked, 2, 1, 2, 405_000},
		{cheap, 1, 0, 1, 10_000},
		{cheap, 4, 0, 4, 40_000},
		{money.MediaPrice{PerUnit: 200_000, Markup: testMarkup}, 5, 0, 1, 1_500_000},
		{money.MediaPrice{PerUnit: 1_000, Markup: testMarkup}, 2, 0, 1, 10_000},
	} {
		if got := c.price.Hold(c.units, c.refs, c.outputs); got != c.want {
			t.Errorf("%+v Hold(%d, %d, %d) = %d, want %d", c.price, c.units, c.refs, c.outputs, got, c.want)
		}
	}
}

func TestMediaPriceValidateNeedsAPositiveUnitPriceUnderTheCeiling(t *testing.T) {
	for _, p := range []money.MediaPrice{{PerUnit: 1}, {PerUnit: money.MaxMicrosPerUnit, PerReference: money.MaxMicrosPerUnit}} {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", p, err)
		}
	}
	for _, p := range []money.MediaPrice{{}, {PerUnit: -1}, {PerUnit: 1, PerReference: -1}, {PerUnit: money.MaxMicrosPerUnit + 1}} {
		if p.Validate() == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestReportedUSDRoundsUpExactlyAndLeavesNonsenseUnreported(t *testing.T) {
	for in, want := range map[string]money.Micros{"0": 0, "0.0963": 96_300, "0.04815": 48_150, "1e-7": 1, "0.0000001": 1, "0.1234565": 123_457, "2": 2_000_000} {
		if got := money.ReportedUSD(in); got != money.ReportedCost(want) {
			t.Errorf("ReportedUSD(%q) = %+v, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "-0.01", "abc", "NaN", "1e400"} {
		if got := money.ReportedUSD(in); got != (money.Reported{}) {
			t.Errorf("ReportedUSD(%q) = %+v, want unreported", in, got)
		}
	}
}

func TestReportedUnitsMultipliesVendorUnitsByTheUnitPriceAndRoundsUp(t *testing.T) {
	for _, c := range []struct {
		units   string
		perUnit money.Micros
		want    money.Micros
	}{{"1.5", 30_000, 45_000}, {"5.0", 25_000, 125_000}, {"0", 70_000, 0}, {"108.0", 21_400, 2_311_200}, {"0.6667", 67_500, 45_003}, {"1e-9", 1, 1}, {"30", 1_000, 30_000}} {
		if got := money.ReportedUnits(c.units, c.perUnit); got != money.ReportedCost(c.want) {
			t.Errorf("ReportedUnits(%q, %d) = %+v, want %d", c.units, c.perUnit, got, c.want)
		}
	}
	for _, in := range []string{"", "-1", "one", "NaN", "Inf", "1e400"} {
		if got := money.ReportedUnits(in, 1_000); got != (money.Reported{}) {
			t.Errorf("ReportedUnits(%q) = %+v, want unreported", in, got)
		}
	}
	if got := money.ReportedUnits("1", -1); got != (money.Reported{}) {
		t.Errorf("negative unit price reported %+v", got)
	}
}

func TestAReportedCostSettlesAsReportedAndAnUnreportedOneAsTheHoldOnlyOnDeliveryAndNamesWhichApplied(t *testing.T) {
	var list money.MediaPrice
	for _, c := range []struct {
		name      string
		reported  money.Reported
		delivered int
		want      money.Micros
		source    measure.UsageSource
	}{
		{"reported success", money.ReportedCost(96_300), 1, 96_300, measure.UsageReported},
		{"reported failure", money.ReportedCost(40_000), 0, 40_000, measure.UsageReported},
		{"reported zero on a failure", money.ReportedCost(0), 0, 0, measure.UsageReported},
		{"unreported success", money.Reported{}, 1, 500_000, measure.UsageHold},
		{"unreported failure", money.Reported{}, 0, 0, measure.UsageNone},
		{"sum of items", money.ReportedCost(30_100).Add(money.ReportedCost(30_100)).Add(money.Reported{}), 2, 60_200, measure.UsageReported},
		{"sum with nothing reported", money.Reported{}.Add(money.Reported{}), 2, 500_000, measure.UsageHold},
		{"a delivered item without a cost", money.ReportedCost(30_100).Add(money.Reported{}.Delivered()), 2, 500_000, measure.UsageHold},
		{"a delivered item without a cost added first", money.Reported{}.Delivered().Add(money.ReportedCost(30_100)), 2, 500_000, measure.UsageHold},
		{"delivered items with costs", money.ReportedCost(30_100).Delivered().Add(money.ReportedCost(30_100).Delivered()), 2, 60_200, measure.UsageReported},
	} {
		if got := list.Settle(measure.Completed, c.reported, c.delivered, 500_000); got != (money.Settlement{Outcome: measure.Completed, Cost: c.want, Source: c.source}) {
			t.Errorf("%s: %+v, want %d from %s with no sides", c.name, got, c.want, c.source)
		}
	}
}

func TestADeliveredOutputCostsTheMarkedUpVendorCostAndAtLeastACreditButAFailureIsNeverFloored(t *testing.T) {
	marked := money.MediaPrice{PerUnit: 80_000, Markup: testMarkup}
	for _, c := range []struct {
		name      string
		reported  money.Reported
		delivered int
		want      money.Micros
		source    measure.UsageSource
	}{
		{"marked up", money.ReportedCost(30_000), 1, 45_000, measure.UsageReported},
		{"rounded up to the micro", money.ReportedCost(5), 0, 8, measure.UsageReported},
		{"a cheap image floored", money.ReportedCost(1_300), 1, 10_000, measure.UsageReported},
		{"four cheap images floored", money.ReportedCost(5_200), 4, 40_000, measure.UsageReported},
		{"two of four delivered", money.ReportedCost(2_600), 2, 20_000, measure.UsageReported},
		{"a free delivery floored", money.ReportedCost(0), 1, 10_000, measure.UsageReported},
		{"a billed failure marked up but not floored", money.ReportedCost(1), 0, 2, measure.UsageReported},
		{"an unbilled failure", money.Reported{}, 0, 0, measure.UsageNone},
		{"an unpriced delivery", money.Reported{}.Delivered(), 1, 96_000, measure.UsageHold},
	} {
		if got := marked.Settle(measure.Failed, c.reported, c.delivered, 96_000); got != (money.Settlement{Outcome: measure.Failed, Cost: c.want, Source: c.source}) {
			t.Errorf("%s: %+v, want %d from %s with no sides", c.name, got, c.want, c.source)
		}
	}
}

func TestAReportedCostRoundTripsThroughJSONWithWhatItKnows(t *testing.T) {
	for name, r := range map[string]money.Reported{
		"unreported": {},
		"known":      money.ReportedCost(1_250),
		"unpriced":   money.ReportedCost(1_250).Delivered(),
	} {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var back money.Reported
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("%s: %s: %v", name, data, err)
		}
		if back != r {
			t.Errorf("%s: %s decoded as %+v, want %+v", name, data, back, r)
		}
	}
	var bad money.Reported
	if err := json.Unmarshal([]byte(`{"micros":1,"known":"guessed"}`), &bad); err == nil {
		t.Error("a cost known in no listed way decoded")
	}
}
