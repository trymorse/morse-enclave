package schedule

import (
	"testing"
	"time"
)

// runs lists a schedule's first n runs after from, as Next gives them one after another.
func runs(sch Schedule, from time.Time, n int) []time.Time {
	var out []time.Time
	for at := from; len(out) < n; {
		next, ok := sch.Next(at)
		if !ok {
			break
		}
		out = append(out, next)
		at = next
	}
	return out
}

func formatted(times []time.Time) []string {
	out := make([]string, len(times))
	for i, at := range times {
		out[i] = at.UTC().Format(time.RFC3339)
	}
	return out
}

// Hand-worked from the zones' 2026 changes of clock (wall_test.go lists each change's instants).
func TestRunsAroundChangesOfClockAreTheHandWorkedInstants(t *testing.T) {
	for _, c := range []struct {
		name string
		spec Spec
		now  string
		want []string
	}{
		{"New York hourly over the skipped 02:00", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "America/New_York"}, "2026-03-08T04:00:00Z",
			[]string{"2026-03-08T04:30:00Z", "2026-03-08T05:30:00Z", "2026-03-08T06:30:00Z", "2026-03-08T07:30:00Z", "2026-03-08T08:30:00Z"}},
		{"New York hourly over the repeated 01:00", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "America/New_York"}, "2026-11-01T03:00:00Z",
			[]string{"2026-11-01T03:30:00Z", "2026-11-01T04:30:00Z", "2026-11-01T05:30:00Z", "2026-11-01T07:30:00Z", "2026-11-01T08:30:00Z"}},
		{"London hourly over the skipped 01:00", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "Europe/London"}, "2026-03-28T22:00:00Z",
			[]string{"2026-03-28T22:30:00Z", "2026-03-28T23:30:00Z", "2026-03-29T00:30:00Z", "2026-03-29T01:30:00Z", "2026-03-29T02:30:00Z"}},
		{"London hourly over the repeated 01:00", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "Europe/London"}, "2026-10-24T22:00:00Z",
			[]string{"2026-10-24T22:30:00Z", "2026-10-24T23:30:00Z", "2026-10-25T00:30:00Z", "2026-10-25T02:30:00Z", "2026-10-25T03:30:00Z"}},
		{"Lord Howe hourly at :15 over the half hour skipped", Spec{Kind: Hourly, Cron: "15 * * * *", TZ: "Australia/Lord_Howe"}, "2026-10-03T12:00:00Z",
			[]string{"2026-10-03T12:45:00Z", "2026-10-03T13:45:00Z", "2026-10-03T14:45:00Z", "2026-10-03T15:45:00Z", "2026-10-03T16:15:00Z", "2026-10-03T17:15:00Z"}},
		{"Lord Howe hourly at :45 beside the half hour skipped", Spec{Kind: Hourly, Cron: "45 * * * *", TZ: "Australia/Lord_Howe"}, "2026-10-03T12:00:00Z",
			[]string{"2026-10-03T12:15:00Z", "2026-10-03T13:15:00Z", "2026-10-03T14:15:00Z", "2026-10-03T15:15:00Z", "2026-10-03T15:45:00Z", "2026-10-03T16:45:00Z"}},
		{"Lord Howe hourly at :45 over the half hour repeated", Spec{Kind: Hourly, Cron: "45 * * * *", TZ: "Australia/Lord_Howe"}, "2026-04-04T12:00:00Z",
			[]string{"2026-04-04T12:45:00Z", "2026-04-04T13:45:00Z", "2026-04-04T14:45:00Z", "2026-04-04T16:15:00Z", "2026-04-04T17:15:00Z"}},
		{"Lord Howe hourly at :15 beside the half hour repeated", Spec{Kind: Hourly, Cron: "15 * * * *", TZ: "Australia/Lord_Howe"}, "2026-04-04T12:00:00Z",
			[]string{"2026-04-04T12:15:00Z", "2026-04-04T13:15:00Z", "2026-04-04T14:15:00Z", "2026-04-04T15:45:00Z", "2026-04-04T16:45:00Z"}},
		{"Santiago hourly over the skipped midnight", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "America/Santiago"}, "2026-09-06T01:00:00Z",
			[]string{"2026-09-06T01:30:00Z", "2026-09-06T02:30:00Z", "2026-09-06T03:30:00Z", "2026-09-06T04:30:00Z", "2026-09-06T05:30:00Z"}},
		{"Santiago hourly over the repeated 23:00", Spec{Kind: Hourly, Cron: "30 * * * *", TZ: "America/Santiago"}, "2026-04-04T23:00:00Z",
			[]string{"2026-04-04T23:30:00Z", "2026-04-05T00:30:00Z", "2026-04-05T01:30:00Z", "2026-04-05T02:30:00Z", "2026-04-05T04:30:00Z"}},
		{"Chatham hourly at :50 over the skipped 02:45", Spec{Kind: Hourly, Cron: "50 * * * *", TZ: "Pacific/Chatham"}, "2026-09-26T11:00:00Z",
			[]string{"2026-09-26T11:05:00Z", "2026-09-26T12:05:00Z", "2026-09-26T13:05:00Z", "2026-09-26T14:05:00Z", "2026-09-26T15:05:00Z"}},
		{"Chatham hourly at :15 over the skipped 02:45", Spec{Kind: Hourly, Cron: "15 * * * *", TZ: "Pacific/Chatham"}, "2026-09-26T11:00:00Z",
			[]string{"2026-09-26T11:30:00Z", "2026-09-26T12:30:00Z", "2026-09-26T13:30:00Z", "2026-09-26T14:30:00Z", "2026-09-26T15:30:00Z"}},
		{"Chatham hourly at :50 over the repeated 02:45", Spec{Kind: Hourly, Cron: "50 * * * *", TZ: "Pacific/Chatham"}, "2026-04-04T10:00:00Z",
			[]string{"2026-04-04T10:05:00Z", "2026-04-04T11:05:00Z", "2026-04-04T12:05:00Z", "2026-04-04T13:05:00Z", "2026-04-04T15:05:00Z"}},
		{"Chatham hourly at :15 over the repeated 02:45", Spec{Kind: Hourly, Cron: "15 * * * *", TZ: "Pacific/Chatham"}, "2026-04-04T10:00:00Z",
			[]string{"2026-04-04T10:30:00Z", "2026-04-04T11:30:00Z", "2026-04-04T12:30:00Z", "2026-04-04T13:30:00Z", "2026-04-04T15:30:00Z"}},
		{"New York daily at a skipped time", Spec{Kind: Daily, Cron: "30 2 * * *", TZ: "America/New_York"}, "2026-03-06T12:00:00Z",
			[]string{"2026-03-07T07:30:00Z", "2026-03-08T07:30:00Z", "2026-03-09T06:30:00Z", "2026-03-10T06:30:00Z"}},
		{"New York daily at a repeated time", Spec{Kind: Daily, Cron: "30 1 * * *", TZ: "America/New_York"}, "2026-10-30T12:00:00Z",
			[]string{"2026-10-31T05:30:00Z", "2026-11-01T05:30:00Z", "2026-11-02T06:30:00Z", "2026-11-03T06:30:00Z"}},
		{"London daily at a repeated time", Spec{Kind: Daily, Cron: "30 1 * * *", TZ: "Europe/London"}, "2026-10-23T12:00:00Z",
			[]string{"2026-10-24T00:30:00Z", "2026-10-25T00:30:00Z", "2026-10-26T01:30:00Z"}},
		{"Lord Howe daily at a skipped time", Spec{Kind: Daily, Cron: "15 2 * * *", TZ: "Australia/Lord_Howe"}, "2026-10-02T12:00:00Z",
			[]string{"2026-10-02T15:45:00Z", "2026-10-03T15:45:00Z", "2026-10-04T15:15:00Z", "2026-10-05T15:15:00Z"}},
		{"Santiago daily at the skipped midnight half hour", Spec{Kind: Daily, Cron: "30 0 * * *", TZ: "America/Santiago"}, "2026-09-04T12:00:00Z",
			[]string{"2026-09-05T04:30:00Z", "2026-09-06T04:30:00Z", "2026-09-07T03:30:00Z"}},
		{"Santiago daily at the repeated 23:30", Spec{Kind: Daily, Cron: "30 23 * * *", TZ: "America/Santiago"}, "2026-04-03T12:00:00Z",
			[]string{"2026-04-04T02:30:00Z", "2026-04-05T02:30:00Z", "2026-04-06T03:30:00Z"}},
		{"Chatham daily at a skipped time", Spec{Kind: Daily, Cron: "0 3 * * *", TZ: "Pacific/Chatham"}, "2026-09-25T00:00:00Z",
			[]string{"2026-09-25T14:15:00Z", "2026-09-26T14:15:00Z", "2026-09-27T13:15:00Z"}},
		{"New York's skipped 02:30 lands on 03:30 and runs once", Spec{Kind: Custom, Cron: "30 2,3 * * *", TZ: "America/New_York"}, "2026-03-07T00:00:00Z",
			[]string{"2026-03-07T07:30:00Z", "2026-03-07T08:30:00Z", "2026-03-08T07:30:00Z", "2026-03-09T06:30:00Z", "2026-03-09T07:30:00Z"}},
		{"New York's repeated 01:30 runs on its first pass", Spec{Kind: Custom, Cron: "30 1,2 * * *", TZ: "America/New_York"}, "2026-10-31T00:00:00Z",
			[]string{"2026-10-31T05:30:00Z", "2026-10-31T06:30:00Z", "2026-11-01T05:30:00Z", "2026-11-01T07:30:00Z", "2026-11-02T06:30:00Z"}},
		{"Lord Howe's skipped 02:15 runs half an hour before 03:15", Spec{Kind: Custom, Cron: "15 2,3 * * *", TZ: "Australia/Lord_Howe"}, "2026-10-03T00:00:00Z",
			[]string{"2026-10-03T15:45:00Z", "2026-10-03T16:15:00Z", "2026-10-04T15:15:00Z", "2026-10-04T16:15:00Z"}},
		{"Chatham's skipped 03:15 lands on 04:15 and runs once", Spec{Kind: Custom, Cron: "15 3,4 * * *", TZ: "Pacific/Chatham"}, "2026-09-26T00:00:00Z",
			[]string{"2026-09-26T14:30:00Z", "2026-09-27T13:30:00Z", "2026-09-27T14:30:00Z"}},
		{"Santiago's skipped 00:30 lands on 01:30 and runs once", Spec{Kind: Custom, Cron: "30 0,1 * * *", TZ: "America/Santiago"}, "2026-09-05T12:00:00Z",
			[]string{"2026-09-06T04:30:00Z", "2026-09-07T03:30:00Z", "2026-09-07T04:30:00Z"}},
		{"29 February across 2100, which is no leap year", Spec{Kind: Custom, Cron: "0 9 29 2 *", TZ: "Asia/Kolkata"}, "2096-03-01T00:00:00Z",
			[]string{"2104-02-29T03:30:00Z", "2108-02-29T03:30:00Z"}},
		{"29 February from 2026", Spec{Kind: Custom, Cron: "0 9 29 2 *", TZ: "Asia/Kolkata"}, "2026-10-27T12:00:00Z",
			[]string{"2028-02-29T03:30:00Z", "2032-02-29T03:30:00Z", "2036-02-29T03:30:00Z"}},
		{"Kolkata weekdays at midnight fall on Sunday to Thursday in UTC", Spec{Kind: Weekdays, Cron: "0 0 * * 1-5", TZ: "Asia/Kolkata"}, "2026-10-30T12:00:00Z",
			[]string{"2026-11-01T18:30:00Z", "2026-11-02T18:30:00Z", "2026-11-03T18:30:00Z", "2026-11-04T18:30:00Z", "2026-11-05T18:30:00Z", "2026-11-08T18:30:00Z"}},
		{"Chatham Mondays at 01:00 fall on Sunday in UTC", Spec{Kind: Weekly, Cron: "0 1 * * 1", TZ: "Pacific/Chatham"}, "2026-10-27T12:00:00Z",
			[]string{"2026-11-01T11:15:00Z", "2026-11-08T11:15:00Z"}},
		{"New York weekdays over the weekend clocks go back", Spec{Kind: Weekdays, Cron: "0 7 * * 1-5", TZ: "America/New_York"}, "2026-10-27T12:00:00Z",
			[]string{"2026-10-28T11:00:00Z", "2026-10-29T11:00:00Z", "2026-10-30T11:00:00Z", "2026-11-02T12:00:00Z", "2026-11-03T12:00:00Z"}},
		{"the 31st only in months that have one", Spec{Kind: Custom, Cron: "0 12 31 * *", TZ: "America/New_York"}, "2026-10-27T12:00:00Z",
			[]string{"2026-10-31T16:00:00Z", "2026-12-31T17:00:00Z", "2027-01-31T17:00:00Z", "2027-03-31T16:00:00Z"}},
		{"the last minute of the year", Spec{Kind: Custom, Cron: "59 23 31 12 *", TZ: "UTC"}, "2026-10-27T12:00:00Z",
			[]string{"2026-12-31T23:59:00Z", "2027-12-31T23:59:00Z"}},
	} {
		sch, err := Parse(c.spec, utc(t, c.now))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		got := formatted(runs(sch, utc(t, c.now), len(c.want)))
		if len(got) != len(c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %q, want %q", c.name, got, c.want)
				break
			}
		}
	}
}

func TestNextIsStrictlyAfterItsArgumentEvenWithinASecond(t *testing.T) {
	sch, err := Parse(Spec{Kind: Daily, Cron: "30 7 * * *", TZ: "America/New_York"}, storyNow)
	if err != nil {
		t.Fatal(err)
	}
	run := utc(t, "2026-10-28T11:30:00Z")
	for _, c := range []struct {
		after time.Time
		want  string
	}{
		{run.Add(-time.Nanosecond), "2026-10-28T11:30:00Z"},
		{run, "2026-10-29T11:30:00Z"},
		{run.Add(time.Nanosecond), "2026-10-29T11:30:00Z"},
		{run.In(time.FixedZone("elsewhere", 5*3600+1800)), "2026-10-29T11:30:00Z"},
	} {
		if got, ok := sch.Next(c.after); !ok || got.Format(time.RFC3339) != c.want || got.Location() != time.UTC {
			t.Errorf("after %s: %s %t, want %s", c.after, got, ok, c.want)
		}
	}
}
