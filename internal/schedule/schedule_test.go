package schedule

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var storyNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func TestASpecIsRefusedByTheFirstRuleItBreaks(t *testing.T) {
	ny, long := "America/New_York", "America/"+strings.Repeat("a", MaxTZ-len("America/")+1)
	for _, c := range []struct {
		name string
		spec Spec
		now  time.Time
		want Code
	}{
		{"no kind", Spec{Cron: "0 9 * * *", TZ: ny}, storyNow, CodeKind},
		{"a kind past the six", Spec{Kind: Custom + 1, Cron: "0 9 * * *", TZ: ny}, storyNow, CodeKind},
		{"no kind, no fields, no zone", Spec{}, storyNow, CodeKind},
		{"once without once_local", Spec{Kind: Once, TZ: ny}, storyNow, CodeFields},
		{"once with a cron", Spec{Kind: Once, Cron: "0 9 * * *", OnceLocal: "2026-10-28T08:00", TZ: ny}, storyNow, CodeFields},
		{"daily without a cron", Spec{Kind: Daily, TZ: ny}, storyNow, CodeFields},
		{"daily with once_local", Spec{Kind: Daily, Cron: "0 9 * * *", OnceLocal: "2026-10-28T08:00", TZ: ny}, storyNow, CodeFields},
		{"hourly with neither", Spec{Kind: Hourly, TZ: ny}, storyNow, CodeFields},
		{"custom with once_local alone", Spec{Kind: Custom, OnceLocal: "2026-10-28T08:00", TZ: ny}, storyNow, CodeFields},
		{"fields before the zone", Spec{Kind: Once, Cron: "0 9 * * *", TZ: "Mars/Olympus"}, storyNow, CodeFields},
		{"no zone", Spec{Kind: Daily, Cron: "0 9 * * *"}, storyNow, CodeTZ},
		{"Local", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "Local"}, storyNow, CodeTZ},
		{"an unknown zone", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "Mars/Olympus"}, storyNow, CodeTZ},
		{"a zone with a space", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "America/New York"}, storyNow, CodeTZ},
		{"a zone over 64 bytes", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: long}, storyNow, CodeTZ},
		{"a path for a zone", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "../etc/passwd"}, storyNow, CodeTZ},
		{"the zone before the cron", Spec{Kind: Daily, Cron: "x", TZ: "Local"}, storyNow, CodeTZ},
		{"the zone before once_local", Spec{Kind: Once, OnceLocal: "tomorrow", TZ: "Mars/Olympus"}, storyNow, CodeTZ},
		{"a space for the T", Spec{Kind: Once, OnceLocal: "2026-10-28 08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"a one-digit hour", Spec{Kind: Once, OnceLocal: "2026-10-28T8:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"seconds", Spec{Kind: Once, OnceLocal: "2026-10-28T08:00:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"an offset", Spec{Kind: Once, OnceLocal: "2026-10-28T08:00Z", TZ: ny}, storyNow, CodeOnceFormat},
		{"a lowercase t", Spec{Kind: Once, OnceLocal: "2026-10-28t08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"29 February in a common year", Spec{Kind: Once, OnceLocal: "2027-02-29T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"31 April", Spec{Kind: Once, OnceLocal: "2027-04-31T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"month 13", Spec{Kind: Once, OnceLocal: "2027-13-01T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"month 0", Spec{Kind: Once, OnceLocal: "2027-00-01T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"day 0", Spec{Kind: Once, OnceLocal: "2027-01-00T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"24:00", Spec{Kind: Once, OnceLocal: "2026-10-28T24:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"minute 60", Spec{Kind: Once, OnceLocal: "2026-10-28T08:60", TZ: ny}, storyNow, CodeOnceFormat},
		{"a two-digit year", Spec{Kind: Once, OnceLocal: "26-10-28T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"full-width digits", Spec{Kind: Once, OnceLocal: "２０２６-10-28T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"a sign for a digit", Spec{Kind: Once, OnceLocal: "+026-10-28T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"the format before the past", Spec{Kind: Once, OnceLocal: "2020-02-30T08:00", TZ: ny}, storyNow, CodeOnceFormat},
		{"now", Spec{Kind: Once, OnceLocal: "2026-10-27T08:00", TZ: ny}, storyNow, CodeOncePast},
		{"59 seconds ahead", Spec{Kind: Once, OnceLocal: "2026-10-27T08:00", TZ: ny}, storyNow.Add(-59 * time.Second), CodeOncePast},
		{"a minute ahead", Spec{Kind: Once, OnceLocal: "2026-10-27T08:00", TZ: ny}, storyNow.Add(-time.Minute), ""},
		{"yesterday", Spec{Kind: Once, OnceLocal: "2026-10-26T08:00", TZ: ny}, storyNow, CodeOncePast},
		{"year 1", Spec{Kind: Once, OnceLocal: "0001-01-01T00:00", TZ: ny}, storyNow, CodeOncePast},
		{"the first pass is past, the second is not", Spec{Kind: Once, OnceLocal: "2026-11-01T01:30", TZ: ny}, utc(t, "2026-11-01T05:45:00Z"), CodeOncePast},
		{"skipped, 30 seconds ahead", Spec{Kind: Once, OnceLocal: "2026-03-08T02:30", TZ: ny}, utc(t, "2026-03-08T07:29:30Z"), CodeOncePast},
		{"skipped, a minute ahead", Spec{Kind: Once, OnceLocal: "2026-03-08T02:30", TZ: ny}, utc(t, "2026-03-08T07:29:00Z"), ""},
		{"the year 9999", Spec{Kind: Once, OnceLocal: "9999-12-31T12:00", TZ: "Asia/Kolkata"}, storyNow, ""},
		{"a cron's syntax", Spec{Kind: Custom, Cron: "0 9 * *", TZ: ny}, storyNow, CodeCronSyntax},
		{"a cron's range", Spec{Kind: Custom, Cron: "0 24 * * *", TZ: ny}, storyNow, CodeCronRange},
		{"a cron's minute", Spec{Kind: Custom, Cron: "*/5 9 * * *", TZ: ny}, storyNow, CodeCronMinute},
		{"a cron's days", Spec{Kind: Custom, Cron: "0 9 1 * 1", TZ: ny}, storyNow, CodeCronDays},
		{"a preset's shape", Spec{Kind: Weekly, Cron: "0 9 * * 7", TZ: ny}, storyNow, CodeCronShape},
		{"a cron that never runs", Spec{Kind: Custom, Cron: "0 9 30 2 *", TZ: ny}, storyNow, CodeCronNever},
		{"a cron in the past is no matter", Spec{Kind: Daily, Cron: "0 9 * * *", TZ: ny}, time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC), ""},
	} {
		_, err := Parse(c.spec, c.now)
		got, coded := CodeOf(err)
		if got != c.want || (err != nil) != coded {
			t.Errorf("%s: %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}

func TestTheWorkersCheckIsRowsOneAndTwoAlone(t *testing.T) {
	for _, c := range []struct {
		spec Spec
		want Code
	}{
		{Spec{Kind: Once, OnceLocal: "2026-10-28T08:00", TZ: "America/New_York"}, ""},
		{Spec{Kind: Once, OnceLocal: "not a time", TZ: "Mars/Olympus"}, ""},
		{Spec{Kind: Daily, Cron: "not a cron"}, ""},
		{Spec{Kind: 0, Cron: "0 9 * * *", TZ: "UTC"}, CodeKind},
		{Spec{Kind: Once, Cron: "0 9 * * *", OnceLocal: "2026-10-28T08:00", TZ: "UTC"}, CodeFields},
		{Spec{Kind: Custom, TZ: "UTC"}, CodeFields},
	} {
		got, _ := CodeOf(c.spec.CheckFields())
		if got != c.want {
			t.Errorf("%+v: %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestAZoneIsAnIANANameTheEmbeddedDatabaseKnows(t *testing.T) {
	for tz, ok := range map[string]bool{
		"America/New_York": true, "Europe/London": true, "Australia/Lord_Howe": true, "Asia/Kolkata": true,
		"America/Santiago": true, "Pacific/Chatham": true, "UTC": true, "Etc/GMT+12": true, "US/Eastern": true,
		"": false, "Local": false, "Mars/Olympus": false, "America/New York": false, "../etc/passwd": false,
		"/etc/localtime": false, "America/New_York ": false, strings.Repeat("A", MaxTZ+1): false,
	} {
		loc, err := Zone(tz)
		if code, _ := CodeOf(err); ok != (err == nil) || (!ok && code != CodeTZ) || ok != (loc != nil) {
			t.Errorf("%q: %v %v, want accepted %t", tz, loc, err, ok)
		}
	}
}

func TestLoadTakesAOneTimeRunThatHasPassedAndKnowsItHasNoRunLeft(t *testing.T) {
	spec := Spec{Kind: Once, OnceLocal: "2026-10-26T08:00", TZ: "America/New_York"}
	if _, err := Parse(spec, storyNow); err == nil {
		t.Fatal("Parse took a one-time run a day past")
	}
	sch, err := Load(spec)
	if err != nil {
		t.Fatal(err)
	}
	at, ok := sch.Once()
	if !ok || !at.Equal(utc(t, "2026-10-26T12:00:00Z")) {
		t.Errorf("its instant is %s %t", at, ok)
	}
	if next, ok := sch.Next(storyNow); ok {
		t.Errorf("it runs again at %s", next)
	}
	if next, ok := sch.Next(at.Add(-time.Nanosecond)); !ok || !next.Equal(at) {
		t.Errorf("just before its instant it runs at %s %t", next, ok)
	}
	if next, ok := sch.Next(at); ok {
		t.Errorf("at its instant it runs again at %s", next)
	}
	if next, ok := Next(spec, at.Add(-time.Hour)); !ok || !next.Equal(at) {
		t.Errorf("Next of the spec an hour before is %s %t", next, ok)
	}
	if _, ok := Next(Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "Local"}, storyNow); ok {
		t.Error("Next ran a spec Load refuses")
	}
	if _, ok := (Schedule{}).Next(storyNow); ok {
		t.Error("the zero schedule runs")
	}
	if _, ok := (Schedule{}).Once(); ok {
		t.Error("the zero schedule has a one-time instant")
	}
	daily, err := Load(Spec{Kind: Daily, Cron: "0 9 * * *", TZ: "UTC"})
	if _, ok := daily.Once(); err != nil || ok {
		t.Errorf("a daily schedule has a one-time instant: %v", err)
	}
}

func TestEveryPresetCompilesToItsShapeWithoutLeadingZerosAndParsesAsItsKind(t *testing.T) {
	for _, c := range []struct {
		kind         Kind
		minute, hour int
		day          time.Weekday
		want         string
	}{
		{Hourly, 5, 99, 9, "5 * * * *"},
		{Hourly, 0, 0, 0, "0 * * * *"},
		{Daily, 30, 7, 9, "30 7 * * *"},
		{Daily, 0, 0, 0, "0 0 * * *"},
		{Weekdays, 0, 7, 0, "0 7 * * 1-5"},
		{Weekly, 0, 9, time.Monday, "0 9 * * 1"},
		{Weekly, 59, 23, time.Sunday, "59 23 * * 0"},
		{Weekly, 15, 18, time.Saturday, "15 18 * * 6"},
	} {
		got, err := PresetCron(c.kind, c.minute, c.hour, c.day)
		if err != nil || got != c.want {
			t.Errorf("%s %d %d %d: %q %v, want %q", c.kind, c.minute, c.hour, c.day, got, err, c.want)
			continue
		}
		if _, err := Parse(Spec{Kind: c.kind, Cron: got, TZ: "UTC"}, storyNow); err != nil {
			t.Errorf("%s %q: %v", c.kind, got, err)
		}
	}
	for _, c := range []struct {
		kind         Kind
		minute, hour int
		day          time.Weekday
		want         Code
	}{
		{Once, 0, 9, 0, CodeKind},
		{Custom, 0, 9, 0, CodeKind},
		{0, 0, 9, 0, CodeKind},
		{Hourly, 60, 0, 0, CodeCronRange},
		{Daily, -1, 9, 0, CodeCronRange},
		{Daily, 0, 24, 0, CodeCronRange},
		{Weekdays, 0, -1, 0, CodeCronRange},
		{Weekly, 0, 9, 7, CodeCronRange},
		{Weekly, 0, 9, -1, CodeCronRange},
	} {
		if _, err := PresetCron(c.kind, c.minute, c.hour, c.day); func() Code { code, _ := CodeOf(err); return code }() != c.want {
			t.Errorf("%s %d %d %d: %v, want %q", c.kind, c.minute, c.hour, c.day, err, c.want)
		}
	}
}

func TestJitterIsUnderTwoMinutesInWholeSecondsAndFixedByTheTaskID(t *testing.T) {
	for id, want := range map[string]time.Duration{
		"0b7c4e1a-5d2f-4c8e-9a61-3f2d8e9b1c47": 115 * time.Second,
		"00000000-0000-0000-0000-000000000000": 69 * time.Second,
		"ffffffff-ffff-ffff-ffff-ffffffffffff": 57 * time.Second,
	} {
		raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(raw) != 16 {
			t.Fatalf("%s: %v", id, err)
		}
		if got := Jitter([16]byte(raw)); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	seen := map[time.Duration]bool{}
	for n := range 5000 {
		var task [16]byte
		task[0], task[1], task[15] = byte(n), byte(n>>8), 0x47
		j := Jitter(task)
		if j < 0 || j >= 120*time.Second || j%time.Second != 0 {
			t.Fatalf("%x: jitter %s", task, j)
		}
		seen[j] = true
	}
	if len(seen) != 120 {
		t.Errorf("5000 ids spread over %d of the 120 seconds", len(seen))
	}
}

func TestEveryRefusalNamesItsCodeAndSaysWhy(t *testing.T) {
	for _, code := range Codes() {
		err := error(Error{code})
		if msg := err.Error(); !strings.HasPrefix(msg, "schedule: "+string(code)+": ") || len(msg) < len("schedule: "+string(code)+": ")+20 {
			t.Errorf("%s says %q", code, msg)
		}
		if got, ok := CodeOf(fmt.Errorf("creating a task: %w", err)); !ok || got != code {
			t.Errorf("%s wrapped reads as %q %t", code, got, ok)
		}
	}
	if len(reasons) != len(Codes()) {
		t.Errorf("%d reasons for %d codes", len(reasons), len(Codes()))
	}
	if _, ok := CodeOf(errors.New("no schedule")); ok {
		t.Error("another error reads as a schedule refusal")
	}
	if _, ok := CodeOf(nil); ok {
		t.Error("no error reads as a schedule refusal")
	}
}
