package schedule

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testdata/next_runs.json holds the cases the web app's src/lib/schedule must agree with Go on, in the shape
// contracts.md section E.7 gives:
//
//	{"cases": [
//	  {"name": ..., "spec": {"kind", "cron"?, "once_local"?, "tz"}, "now": ..., "next": [...]},
//	  {"name": ..., "spec": {...}, "now": ..., "error": "<code>"},
//	  ...
//	]}
//
// One case to a line. name is unique and says what the case shows. spec is the spec as the bundle and the task
// routes carry it, each field a string read as written: a field left out is absent, and so is one that is "", so a
// case may hold an unknown kind or an empty cron. now is RFC 3339 in UTC to the second, both Parse's now and where
// next starts. next is 1 to 10 instants in RFC 3339 UTC, Next applied from now and then from each run before (a
// once case lists its one instant); error is the code of E.5 Parse refuses the spec with, in next's place.
//
// The cases cover the six zones design.md names across both of their changes of clock in 2026 and 2027, with
// hourly, daily, and custom crons and one-time runs on the wall times each change skips or repeats; every preset
// and the cron subset's corners; and every code, with cases where two codes apply to pin their order.
//
// TestNextRunsJSONIsWhatTheseCasesCompute rebuilds the file from vectorInputs and fails when it differs; go test
// ./internal/schedule -run NextRunsJSON -update rewrites it. The app keeps a byte-for-byte copy at
// src/lib/schedule/testdata/next_runs.json.
const nextRunsFile = "testdata/next_runs.json"

var update = flag.Bool("update", false, "rewrite "+nextRunsFile+" from the cases in this test")

type vectorSpec struct {
	Kind      string  `json:"kind"`
	Cron      *string `json:"cron,omitempty"`
	OnceLocal *string `json:"once_local,omitempty"`
	TZ        string  `json:"tz"`
}

type vectorCase struct {
	Name  string     `json:"name"`
	Spec  vectorSpec `json:"spec"`
	Now   string     `json:"now"`
	Next  []string   `json:"next,omitempty"`
	Error Code       `json:"error,omitempty"`
}

type vectorFile struct {
	Cases []vectorCase `json:"cases"`
}

func (v vectorSpec) spec() Spec {
	kind, _ := kindNames.Parse(v.Kind)
	s := Spec{Kind: kind, TZ: v.TZ}
	if v.Cron != nil {
		s.Cron = *v.Cron
	}
	if v.OnceLocal != nil {
		s.OnceLocal = *v.OnceLocal
	}
	return s
}

func text(s string) *string { return &s }

func cronSpec(kind, cron, tz string) vectorSpec { return vectorSpec{Kind: kind, Cron: &cron, TZ: tz} }

func onceSpec(local, tz string) vectorSpec {
	return vectorSpec{Kind: "once", OnceLocal: &local, TZ: tz}
}

// vectorInput is a case before its runs are computed: runs is how many next lists, and want the code a refused spec
// must carry, so building the file checks every refusal it records.
type vectorInput struct {
	name string
	spec vectorSpec
	now  string
	runs int
	want Code
}

// clockChange is one of the 2026 and 2027 changes of clock in the contract's zones, with a wall time it skips or
// repeats: its local date, hour, and minute. pair is a custom cron's hours, that one and its neighbour. now is a few
// hours before the change.
type clockChange struct {
	tz, place string
	forward   bool
	date      string
	hour      int
	minute    int
	pair      string
	now       string
}

var clockChanges = []clockChange{
	{"America/New_York", "New York", true, "2026-03-08", 2, 30, "2,3", "2026-03-08T03:00:00Z"},
	{"America/New_York", "New York", false, "2026-11-01", 1, 30, "1,2", "2026-11-01T02:00:00Z"},
	{"America/New_York", "New York", true, "2027-03-14", 2, 30, "2,3", "2027-03-14T03:00:00Z"},
	{"America/New_York", "New York", false, "2027-11-07", 1, 30, "1,2", "2027-11-07T02:00:00Z"},
	{"Europe/London", "London", true, "2026-03-29", 1, 30, "1,2", "2026-03-28T21:00:00Z"},
	{"Europe/London", "London", false, "2026-10-25", 1, 30, "1,2", "2026-10-24T21:00:00Z"},
	{"Europe/London", "London", true, "2027-03-28", 1, 30, "1,2", "2027-03-27T21:00:00Z"},
	{"Europe/London", "London", false, "2027-10-31", 1, 30, "1,2", "2027-10-30T21:00:00Z"},
	{"Australia/Lord_Howe", "Lord Howe", false, "2026-04-05", 1, 45, "1,2", "2026-04-04T11:00:00Z"},
	{"Australia/Lord_Howe", "Lord Howe", true, "2026-10-04", 2, 15, "2,3", "2026-10-03T11:30:00Z"},
	{"Australia/Lord_Howe", "Lord Howe", false, "2027-04-04", 1, 45, "1,2", "2027-04-03T11:00:00Z"},
	{"Australia/Lord_Howe", "Lord Howe", true, "2027-10-03", 2, 15, "2,3", "2027-10-02T11:30:00Z"},
	{"America/Santiago", "Santiago", false, "2026-04-04", 23, 30, "22,23", "2026-04-04T23:00:00Z"},
	{"America/Santiago", "Santiago", true, "2026-09-06", 0, 30, "0,1", "2026-09-06T00:00:00Z"},
	{"America/Santiago", "Santiago", false, "2027-04-03", 23, 30, "22,23", "2027-04-03T23:00:00Z"},
	{"America/Santiago", "Santiago", true, "2027-09-05", 0, 30, "0,1", "2027-09-05T00:00:00Z"},
	{"Pacific/Chatham", "Chatham", false, "2026-04-05", 3, 15, "3,4", "2026-04-04T09:00:00Z"},
	{"Pacific/Chatham", "Chatham", true, "2026-09-27", 3, 15, "3,4", "2026-09-26T09:00:00Z"},
	{"Pacific/Chatham", "Chatham", false, "2027-04-04", 3, 15, "3,4", "2027-04-03T09:00:00Z"},
	{"Pacific/Chatham", "Chatham", true, "2027-09-26", 3, 15, "3,4", "2027-09-25T09:00:00Z"},
}

func earlier(t testing.TB, now string, by time.Duration) string {
	return utc(t, now).Add(-by).Format(time.RFC3339)
}

func changeInputs(t testing.TB) []vectorInput {
	var out []vectorInput
	for _, c := range clockChanges {
		goes, does := "back", "repeats"
		if c.forward {
			goes, does = "forward", "skips"
		}
		at := fmt.Sprintf("%02d:%02d", c.hour, c.minute)
		m, h := strconv.Itoa(c.minute), strconv.Itoa(c.hour)
		out = append(out,
			vectorInput{fmt.Sprintf("hourly at :%02d as %s's clocks go %s on %s", c.minute, c.place, goes, c.date), cronSpec("hourly", m+" * * * *", c.tz), c.now, 10, ""},
			vectorInput{fmt.Sprintf("daily at %s, which %s %s on %s", at, c.place, does, c.date), cronSpec("daily", m+" "+h+" * * *", c.tz), earlier(t, c.now, 48*time.Hour), 4, ""},
			vectorInput{fmt.Sprintf("hours %s at :%02d as %s's clocks go %s on %s", c.pair, c.minute, c.place, goes, c.date), cronSpec("custom", m+" "+c.pair+" * * *", c.tz), earlier(t, c.now, 24*time.Hour), 6, ""},
			vectorInput{fmt.Sprintf("once at %s on %s, which %s %s", at, c.date, c.place, does), onceSpec(c.date+"T"+at, c.tz), earlier(t, c.now, 24*time.Hour), 1, ""},
		)
	}
	return out
}

const (
	story  = "2026-10-27T12:00:00Z"
	ny     = "America/New_York"
	london = "Europe/London"
	howe   = "Australia/Lord_Howe"
	india  = "Asia/Kolkata"
	chile  = "America/Santiago"
	chat   = "Pacific/Chatham"
)

func vectorInputs(t testing.TB) []vectorInput {
	long := "00 9 " + strings.Repeat("01,", 30) + "31 * *"
	inputs := []vectorInput{
		{"daily 07:30 across New York's spring forward", cronSpec("daily", "30 7 * * *", ny), "2026-03-07T12:00:00Z", 3, ""},
		{"hourly at :05 in Kolkata, half an hour off UTC", cronSpec("hourly", "5 * * * *", india), story, 6, ""},
		{"hourly at :05 in Chatham, 45 minutes off the hour", cronSpec("hourly", "5 * * * *", chat), story, 5, ""},
		{"hourly at :00 in UTC", cronSpec("hourly", "0 * * * *", "UTC"), story, 3, ""},
		{"hourly with a leading zero in its minute", cronSpec("hourly", "07 * * * *", "UTC"), story, 3, ""},
		{"daily at 19:00 in Kolkata", cronSpec("daily", "0 19 * * *", india), story, 3, ""},
		{"daily at 06:30 in Lord Howe", cronSpec("daily", "30 6 * * *", howe), story, 3, ""},
		{"daily at 08:30 in London across its change to GMT", cronSpec("daily", "30 8 * * *", london), "2026-10-23T12:00:00Z", 4, ""},
		{"daily with a leading zero in its hour", cronSpec("daily", "0 07 * * *", ny), story, 2, ""},
		{"daily at 23:59 in Chatham, the day before in UTC", cronSpec("daily", "59 23 * * *", chat), story, 2, ""},
		{"weekdays at 07:00 in New York over the weekend its clocks go back", cronSpec("weekdays", "0 7 * * 1-5", ny), story, 6, ""},
		{"weekdays at 00:00 in Kolkata fall on Sunday to Thursday in UTC", cronSpec("weekdays", "0 0 * * 1-5", india), "2026-10-30T12:00:00Z", 6, ""},
		{"weekdays at 08:00 in Santiago", cronSpec("weekdays", "0 8 * * 1-5", chile), story, 6, ""},
		{"weekly on Mondays at 09:00 in Santiago", cronSpec("weekly", "0 9 * * 1", chile), story, 4, ""},
		{"weekly on Sundays at 18:00 in London", cronSpec("weekly", "0 18 * * 0", london), story, 4, ""},
		{"weekly on Mondays at 01:00 in Chatham fall on Sunday in UTC", cronSpec("weekly", "0 1 * * 1", chat), story, 3, ""},
		{"weekly on Saturdays at 23:45 in Lord Howe", cronSpec("weekly", "45 23 * * 6", howe), story, 3, ""},
		{"weekly with a leading zero in its day", cronSpec("weekly", "0 9 * * 06", london), story, 2, ""},
		{"every four hours from 9 to 17", cronSpec("custom", "0 9-17/4 * * *", ny), story, 6, ""},
		{"every six hours", cronSpec("custom", "0 */6 * * *", india), story, 5, ""},
		{"a list and a step in one field", cronSpec("custom", "30 */8,9 * * *", london), story, 6, ""},
		{"twice on weekdays", cronSpec("custom", "15 9,17 * * 1-5", ny), story, 6, ""},
		{"the first week of each month", cronSpec("custom", "0 9 1-7 * *", london), story, 8, ""},
		{"quarterly on the 1st", cronSpec("custom", "0 0 1 */3 *", "UTC"), story, 4, ""},
		{"the 31st only in months that have one", cronSpec("custom", "0 12 31 * *", ny), story, 4, ""},
		{"the 30th and 31st in February's neighbours", cronSpec("custom", "0 12 30,31 1-3 *", "UTC"), story, 4, ""},
		{"29 February from 2026", cronSpec("custom", "0 9 29 2 *", india), story, 3, ""},
		{"29 February across 2100, which is no leap year", cronSpec("custom", "0 9 29 2 *", india), "2096-03-01T00:00:00Z", 2, ""},
		{"the last minute of the year", cronSpec("custom", "59 23 31 12 *", "UTC"), story, 2, ""},
		{"New Year's midnight in Lord Howe", cronSpec("custom", "0 0 1 1 *", howe), story, 2, ""},
		{"Sunday as 7", cronSpec("custom", "0 9 * * 7", ny), story, 3, ""},
		{"Sunday as both 0 and 7", cronSpec("custom", "0 9 * * 0,7", ny), story, 3, ""},
		{"Friday to Sunday by 5-7", cronSpec("custom", "0 9 * * 5-7", london), story, 6, ""},
		{"every other day of the week", cronSpec("custom", "30 8 * * */2", chile), story, 5, ""},
		{"Santiago's summer weekdays", cronSpec("custom", "30 8 * 1,2,12 1-5", chile), story, 4, ""},
		{"every day of the month by */1 is every day", cronSpec("custom", "0 9 */1 * *", "UTC"), story, 2, ""},
		{"a cron of exactly 100 bytes", cronSpec("custom", long[1:], "UTC"), story, 2, ""},
		{"Lord Howe hourly at :45 beside the half hour it skips", cronSpec("hourly", "45 * * * *", howe), "2026-10-03T12:00:00Z", 6, ""},
		{"Lord Howe hourly at :15 beside the half hour it repeats", cronSpec("hourly", "15 * * * *", howe), "2026-04-04T12:00:00Z", 5, ""},
		{"Chatham hourly at :50 as its clocks go forward on 2026-09-27", cronSpec("hourly", "50 * * * *", chat), "2026-09-26T11:00:00Z", 6, ""},
		{"Chatham hourly at :50 as its clocks go back on 2026-04-05", cronSpec("hourly", "50 * * * *", chat), "2026-04-04T10:00:00Z", 6, ""},
		{"Chatham daily at 02:50, which it skips on 2026-09-27", cronSpec("daily", "50 2 * * *", chat), "2026-09-25T00:00:00Z", 3, ""},
		{"daily at 23:30, which Scoresbysund carries past midnight on 2026-03-28", cronSpec("daily", "30 23 * * *", "America/Scoresbysund"), "2026-03-29T01:10:00Z", 3, ""},
		{"once tomorrow in New York", onceSpec("2026-10-28T08:00", ny), story, 1, ""},
		{"once a minute from now", onceSpec("2026-10-27T08:00", ny), "2026-10-27T11:59:00Z", 1, ""},
		{"once on Christmas morning in Chatham, Christmas Eve in UTC", onceSpec("2026-12-25T09:00", chat), story, 1, ""},
		{"once in the year 9999", onceSpec("9999-12-31T12:00", india), story, 1, ""},
		{"once at a skipped time a minute from now", onceSpec("2026-03-08T02:30", ny), "2026-03-08T07:29:00Z", 1, ""},

		{"an unknown kind", cronSpec("monthly", "0 9 1 * *", "UTC"), story, 0, CodeKind},
		{"an empty kind", cronSpec("", "0 9 * * *", "UTC"), story, 0, CodeKind},
		{"a kind in capitals", cronSpec("Daily", "0 9 * * *", "UTC"), story, 0, CodeKind},
		{"the kind before the fields and the zone", vectorSpec{Kind: "monthly", TZ: "Mars/Olympus"}, story, 0, CodeKind},
		{"once without once_local", vectorSpec{Kind: "once", TZ: ny}, story, 0, CodeFields},
		{"once with an empty once_local", vectorSpec{Kind: "once", OnceLocal: text(""), TZ: ny}, story, 0, CodeFields},
		{"once with a cron", vectorSpec{Kind: "once", Cron: text("0 9 * * *"), OnceLocal: text("2026-10-28T08:00"), TZ: ny}, story, 0, CodeFields},
		{"once with a cron alone", vectorSpec{Kind: "once", Cron: text("0 9 * * *"), TZ: ny}, story, 0, CodeFields},
		{"daily without a cron", vectorSpec{Kind: "daily", TZ: ny}, story, 0, CodeFields},
		{"daily with an empty cron", cronSpec("daily", "", ny), story, 0, CodeFields},
		{"daily with once_local", vectorSpec{Kind: "daily", Cron: text("0 9 * * *"), OnceLocal: text("2026-10-28T08:00"), TZ: ny}, story, 0, CodeFields},
		{"hourly with neither", vectorSpec{Kind: "hourly", TZ: ny}, story, 0, CodeFields},
		{"custom with once_local alone", vectorSpec{Kind: "custom", OnceLocal: text("2026-10-28T08:00"), TZ: ny}, story, 0, CodeFields},
		{"the fields before the zone", vectorSpec{Kind: "once", Cron: text("0 9 * * *"), TZ: "Mars/Olympus"}, story, 0, CodeFields},
		{"an empty zone", cronSpec("daily", "0 9 * * *", ""), story, 0, CodeTZ},
		{"Local", cronSpec("daily", "0 9 * * *", "Local"), story, 0, CodeTZ},
		{"an unknown zone", cronSpec("daily", "0 9 * * *", "Mars/Olympus"), story, 0, CodeTZ},
		{"a zone with a space", cronSpec("daily", "0 9 * * *", "America/New York"), story, 0, CodeTZ},
		{"a zone with a trailing space", cronSpec("daily", "0 9 * * *", "America/New_York "), story, 0, CodeTZ},
		{"a zone of 65 bytes", cronSpec("daily", "0 9 * * *", "America/"+strings.Repeat("a", MaxTZ+1-len("America/"))), story, 0, CodeTZ},
		{"a path for a zone", cronSpec("daily", "0 9 * * *", "../etc/passwd"), story, 0, CodeTZ},
		{"the zone before the cron", cronSpec("daily", "x", "Local"), story, 0, CodeTZ},
		{"the zone before once_local", onceSpec("tomorrow", "Mars/Olympus"), story, 0, CodeTZ},
		{"a space for the T", onceSpec("2026-10-28 08:00", ny), story, 0, CodeOnceFormat},
		{"a one-digit hour", onceSpec("2026-10-28T8:00", ny), story, 0, CodeOnceFormat},
		{"seconds", onceSpec("2026-10-28T08:00:00", ny), story, 0, CodeOnceFormat},
		{"an offset", onceSpec("2026-10-28T08:00Z", ny), story, 0, CodeOnceFormat},
		{"a lowercase t", onceSpec("2026-10-28t08:00", ny), story, 0, CodeOnceFormat},
		{"29 February in a common year", onceSpec("2027-02-29T08:00", ny), story, 0, CodeOnceFormat},
		{"31 April", onceSpec("2027-04-31T08:00", ny), story, 0, CodeOnceFormat},
		{"month 13", onceSpec("2027-13-01T08:00", ny), story, 0, CodeOnceFormat},
		{"month 0", onceSpec("2027-00-01T08:00", ny), story, 0, CodeOnceFormat},
		{"day 0", onceSpec("2027-01-00T08:00", ny), story, 0, CodeOnceFormat},
		{"24:00", onceSpec("2026-10-28T24:00", ny), story, 0, CodeOnceFormat},
		{"minute 60 in once_local", onceSpec("2026-10-28T08:60", ny), story, 0, CodeOnceFormat},
		{"a two-digit year", onceSpec("26-10-28T08:00", ny), story, 0, CodeOnceFormat},
		{"a sign for the year's first digit", onceSpec("+026-10-28T08:00", ny), story, 0, CodeOnceFormat},
		{"a date alone", onceSpec("2026-10-28", ny), story, 0, CodeOnceFormat},
		{"the format before the past", onceSpec("2020-02-30T08:00", ny), story, 0, CodeOnceFormat},
		{"once now", onceSpec("2026-10-27T08:00", ny), story, 0, CodeOncePast},
		{"once 59 seconds ahead", onceSpec("2026-10-27T08:00", ny), "2026-10-27T11:59:01Z", 0, CodeOncePast},
		{"once yesterday", onceSpec("2026-10-26T08:00", ny), story, 0, CodeOncePast},
		{"once in the year 1", onceSpec("0001-01-01T00:00", ny), story, 0, CodeOncePast},
		{"once on a repeated time whose first pass is past and second is not", onceSpec("2026-11-01T01:30", ny), "2026-11-01T05:45:00Z", 0, CodeOncePast},
		{"once at a skipped time 30 seconds ahead", onceSpec("2026-03-08T02:30", ny), "2026-03-08T07:29:30Z", 0, CodeOncePast},
		{"four fields", cronSpec("custom", "0 9 * *", "UTC"), story, 0, CodeCronSyntax},
		{"six fields", cronSpec("custom", "0 9 * * * *", "UTC"), story, 0, CodeCronSyntax},
		{"two spaces", cronSpec("custom", "0  9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"a leading space", cronSpec("custom", " 0 9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"a trailing space", cronSpec("custom", "0 9 * * * ", "UTC"), story, 0, CodeCronSyntax},
		{"a tab", cronSpec("custom", "0\t9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"a day's name", cronSpec("custom", "0 9 * * MON", "UTC"), story, 0, CodeCronSyntax},
		{"a month's name", cronSpec("custom", "0 9 * JAN *", "UTC"), story, 0, CodeCronSyntax},
		{"a question mark", cronSpec("custom", "0 9 ? * *", "UTC"), story, 0, CodeCronSyntax},
		{"L for the last day", cronSpec("custom", "0 9 L * *", "UTC"), story, 0, CodeCronSyntax},
		{"W for the nearest weekday", cronSpec("custom", "0 9 15W * *", "UTC"), story, 0, CodeCronSyntax},
		{"# for the nth weekday", cronSpec("custom", "0 9 * * 1#2", "UTC"), story, 0, CodeCronSyntax},
		{"a range without its end", cronSpec("custom", "0 9 * * 1-", "UTC"), story, 0, CodeCronSyntax},
		{"a range without its start", cronSpec("custom", "0 9 * * -5", "UTC"), story, 0, CodeCronSyntax},
		{"an empty list item", cronSpec("custom", "0 9 1,,2 * *", "UTC"), story, 0, CodeCronSyntax},
		{"a trailing comma", cronSpec("custom", "0 9 1, * *", "UTC"), story, 0, CodeCronSyntax},
		{"a step without its number", cronSpec("custom", "0 9 */ * *", "UTC"), story, 0, CodeCronSyntax},
		{"a step on a single number", cronSpec("custom", "0 9 5/2 * *", "UTC"), story, 0, CodeCronSyntax},
		{"two steps", cronSpec("custom", "0 9 1-5/2/3 * *", "UTC"), story, 0, CodeCronSyntax},
		{"a star in a list", cronSpec("custom", "0 9 *,1 * *", "UTC"), story, 0, CodeCronSyntax},
		{"two stars", cronSpec("custom", "0 9 ** * *", "UTC"), story, 0, CodeCronSyntax},
		{"three digits in range", cronSpec("custom", "0 100 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"three digits with leading zeros", cronSpec("custom", "0 9 * * 007", "UTC"), story, 0, CodeCronSyntax},
		{"a plus sign", cronSpec("custom", "+5 9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"hexadecimal", cronSpec("custom", "0x1 9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"an Arabic-Indic digit", cronSpec("custom", "٣ 9 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"a macro", cronSpec("custom", "@daily", "UTC"), story, 0, CodeCronSyntax},
		{"a cron of 101 bytes", cronSpec("custom", long, "UTC"), story, 0, CodeCronSyntax},
		{"the minute's syntax before the hour's range", cronSpec("custom", "x 60 * * *", "UTC"), story, 0, CodeCronSyntax},
		{"a field's syntax before its own range", cronSpec("custom", "0 25,x * * *", "UTC"), story, 0, CodeCronSyntax},
		{"minute 60 in a cron", cronSpec("custom", "60 9 * * *", "UTC"), story, 0, CodeCronRange},
		{"hour 24", cronSpec("custom", "0 24 * * *", "UTC"), story, 0, CodeCronRange},
		{"day of the month 0", cronSpec("custom", "0 9 0 * *", "UTC"), story, 0, CodeCronRange},
		{"day of the month 32", cronSpec("custom", "0 9 32 * *", "UTC"), story, 0, CodeCronRange},
		{"month 0 in a cron", cronSpec("custom", "0 9 * 0 *", "UTC"), story, 0, CodeCronRange},
		{"month 13 in a cron", cronSpec("custom", "0 9 * 13 *", "UTC"), story, 0, CodeCronRange},
		{"day of the week 8", cronSpec("custom", "0 9 * * 8", "UTC"), story, 0, CodeCronRange},
		{"a range that runs backwards", cronSpec("custom", "0 9 * * 5-3", "UTC"), story, 0, CodeCronRange},
		{"a month range across the new year", cronSpec("custom", "0 9 * 12-2 *", "UTC"), story, 0, CodeCronRange},
		{"a step of 0 on a range", cronSpec("custom", "0 9-17/0 * * *", "UTC"), story, 0, CodeCronRange},
		{"a step of 0 on a star", cronSpec("custom", "0 */0 * * *", "UTC"), story, 0, CodeCronRange},
		{"the minute's range before the hour's syntax", cronSpec("custom", "60 x * * *", "UTC"), story, 0, CodeCronRange},
		{"the hour's range before the minute's form", cronSpec("custom", "0,30 24 * * *", "UTC"), story, 0, CodeCronRange},
		{"every minute", cronSpec("custom", "* 9 * * *", "UTC"), story, 0, CodeCronMinute},
		{"a minute list", cronSpec("custom", "0,30 * * * *", london), story, 0, CodeCronMinute},
		{"a minute range", cronSpec("custom", "0-30 9 * * *", "UTC"), story, 0, CodeCronMinute},
		{"a minute range of one", cronSpec("custom", "5-5 9 * * *", "UTC"), story, 0, CodeCronMinute},
		{"a minute step", cronSpec("custom", "*/15 * * * *", "UTC"), story, 0, CodeCronMinute},
		{"a minute step of 60", cronSpec("custom", "*/60 9 * * *", "UTC"), story, 0, CodeCronMinute},
		{"the minute's form before the days", cronSpec("custom", "*/15 9 1 * 1", "UTC"), story, 0, CodeCronMinute},
		{"a day of the month and a day of the week", cronSpec("custom", "0 9 1 * 1", "UTC"), story, 0, CodeCronDays},
		{"the first Monday, Vixie's way", cronSpec("custom", "0 9 1-7 * 1", "UTC"), story, 0, CodeCronDays},
		{"both days restricted by steps of 1", cronSpec("custom", "0 9 */1 * */1", "UTC"), story, 0, CodeCronDays},
		{"the days before the shape", cronSpec("daily", "0 9 1 * 1", "UTC"), story, 0, CodeCronDays},
		{"the days before never", cronSpec("custom", "0 9 31 2 1", "UTC"), story, 0, CodeCronDays},
		{"hourly with an hour", cronSpec("hourly", "0 9 * * *", "UTC"), story, 0, CodeCronShape},
		{"hourly with a day of the week", cronSpec("hourly", "0 * * * 1", "UTC"), story, 0, CodeCronShape},
		{"hourly by a step of 1", cronSpec("hourly", "0 */1 * * *", "UTC"), story, 0, CodeCronShape},
		{"daily every hour", cronSpec("daily", "0 * * * *", "UTC"), story, 0, CodeCronShape},
		{"daily over a range of hours", cronSpec("daily", "0 9-17 * * *", "UTC"), story, 0, CodeCronShape},
		{"daily on weekdays", cronSpec("daily", "0 9 * * 1-5", "UTC"), story, 0, CodeCronShape},
		{"daily on the 1st", cronSpec("daily", "0 9 1 * *", "UTC"), story, 0, CodeCronShape},
		{"daily in January", cronSpec("daily", "0 9 * 1 *", "UTC"), story, 0, CodeCronShape},
		{"weekdays with Saturday", cronSpec("weekdays", "0 9 * * 1-6", "UTC"), story, 0, CodeCronShape},
		{"weekdays as a list", cronSpec("weekdays", "0 9 * * 1,2,3,4,5", "UTC"), story, 0, CodeCronShape},
		{"weekdays with leading zeros", cronSpec("weekdays", "0 9 * * 01-05", "UTC"), story, 0, CodeCronShape},
		{"weekdays by a step of 1", cronSpec("weekdays", "0 9 * * 1-5/1", "UTC"), story, 0, CodeCronShape},
		{"weekly on Sunday as 7", cronSpec("weekly", "0 9 * * 7", "UTC"), story, 0, CodeCronShape},
		{"weekly on two days", cronSpec("weekly", "0 9 * * 1,3", "UTC"), story, 0, CodeCronShape},
		{"weekly on every day", cronSpec("weekly", "0 9 * * *", "UTC"), story, 0, CodeCronShape},
		{"weekly on the 1st", cronSpec("weekly", "0 9 1 * *", "UTC"), story, 0, CodeCronShape},
		{"the shape before never", cronSpec("weekly", "0 9 30 2 *", "UTC"), story, 0, CodeCronShape},
		{"30 February", cronSpec("custom", "0 9 30 2 *", "UTC"), story, 0, CodeCronNever},
		{"30 and 31 February", cronSpec("custom", "0 9 30,31 2 *", "UTC"), story, 0, CodeCronNever},
		{"the 31st of the months of 30 days", cronSpec("custom", "0 9 31 4,6,9,11 *", "UTC"), story, 0, CodeCronNever},
		{"the 31st of February and April by a step", cronSpec("custom", "0 9 31 2-4/2 *", "UTC"), story, 0, CodeCronNever},
	}
	return append(inputs, changeInputs(t)...)
}

func buildNextRuns(t *testing.T) []byte {
	t.Helper()
	var cases []vectorCase
	for _, in := range vectorInputs(t) {
		now := utc(t, in.now)
		c := vectorCase{Name: in.name, Spec: in.spec, Now: in.now}
		sch, err := Parse(in.spec.spec(), now)
		code, _ := CodeOf(err)
		switch {
		case code != in.want:
			t.Fatalf("%s: %v, want %q", in.name, err, in.want)
		case err != nil:
			c.Error = code
		default:
			c.Next = formatted(runs(sch, now, in.runs))
			if len(c.Next) != in.runs {
				t.Fatalf("%s: %d runs, want %d", in.name, len(c.Next), in.runs)
			}
		}
		cases = append(cases, c)
	}
	var out bytes.Buffer
	out.WriteString("{\"cases\": [\n")
	for i, c := range cases {
		var line bytes.Buffer
		enc := json.NewEncoder(&line)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(c); err != nil {
			t.Fatal(err)
		}
		out.WriteString("  ")
		out.Write(bytes.TrimSuffix(line.Bytes(), []byte("\n")))
		if i < len(cases)-1 {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("]}\n")
	return out.Bytes()
}

func readNextRuns(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(nextRunsFile)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var file vectorFile
	if err := dec.Decode(&file); err != nil {
		t.Fatalf("%s: %v", nextRunsFile, err)
	}
	return file
}

func TestNextRunsJSONIsWhatTheseCasesCompute(t *testing.T) {
	built := buildNextRuns(t)
	if *update {
		if err := os.WriteFile(nextRunsFile, built, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(nextRunsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, built) {
		t.Fatalf("%s differs from what the cases in this test compute; if the change is on purpose, rerun with -update and copy the file to the app's src/lib/schedule/testdata", nextRunsFile)
	}
}

// Each stored case read back on its own terms: its fields by E.7's rules, its error or its runs from Parse and Next
// directly, and every cron case's runs from the slow search too.
func TestEveryStoredCaseIsWhatParseAndNextSayAndTheSlowSearchAgrees(t *testing.T) {
	names := map[string]bool{}
	for _, c := range readNextRuns(t).Cases {
		if c.Name == "" || names[c.Name] {
			t.Errorf("%q: a case's name is empty or repeated", c.Name)
		}
		names[c.Name] = true
		now, err := time.Parse(time.RFC3339, c.Now)
		if err != nil || now.Format(time.RFC3339) != c.Now || !strings.HasSuffix(c.Now, "Z") {
			t.Errorf("%s: now %q is not RFC 3339 UTC to the second", c.Name, c.Now)
			continue
		}
		spec := c.Spec.spec()
		sch, err := Parse(spec, now)
		code, _ := CodeOf(err)
		switch {
		case (c.Error == "") == (len(c.Next) == 0):
			t.Errorf("%s: a case holds next or an error, not both or neither", c.Name)
		case c.Error != "":
			if !slices.Contains(Codes(), c.Error) || code != c.Error {
				t.Errorf("%s: Parse says %q (%v), the case %q", c.Name, code, err, c.Error)
			}
		case err != nil:
			t.Errorf("%s: Parse refuses it: %v", c.Name, err)
		case len(c.Next) > 10, spec.Kind == Once && len(c.Next) != 1:
			t.Errorf("%s: %d runs", c.Name, len(c.Next))
		default:
			prev := now
			for _, want := range c.Next {
				at, err := time.Parse(time.RFC3339, want)
				if err != nil || at.UTC().Format(time.RFC3339) != want {
					t.Errorf("%s: run %q is not RFC 3339 UTC to the second", c.Name, want)
					break
				}
				if next, ok := sch.Next(prev); !ok || !next.Equal(at) {
					t.Errorf("%s: after %s Next is %s %t, the case %s", c.Name, prev.Format(time.RFC3339), next.Format(time.RFC3339), ok, want)
					break
				}
				if spec.Kind != Once {
					if slow, ok := slowNext(sch.cron, sch.loc, prev, 3200); !ok || !slow.Equal(at) {
						t.Errorf("%s: after %s the slow search finds %s, the case %s", c.Name, prev.Format(time.RFC3339), slow.Format(time.RFC3339), want)
					}
					if !onItsWallTime(sch.cron, sch.loc, at) {
						t.Errorf("%s: %s is no wall time of the cron", c.Name, want)
					}
				}
				prev = at
			}
		}
	}
}

// The file covers what E.7 asks: every code, every kind, the six zones, and each 2026 and 2027 change of clock in
// them with at least three cron cases running across it and a one-time run within two hours of it.
func TestNextRunsJSONCoversEveryCodeKindZoneAndChangeOfClock(t *testing.T) {
	file := readNextRuns(t)
	codes, kinds, zones := map[Code]int{}, map[string]bool{}, map[string]bool{}
	for _, c := range file.Cases {
		if c.Error != "" {
			codes[c.Error]++
			continue
		}
		kinds[c.Spec.Kind], zones[c.Spec.TZ] = true, true
	}
	for _, code := range Codes() {
		if codes[code] < 3 {
			t.Errorf("%d cases refuse with %s, want at least 3", codes[code], code)
		}
	}
	for _, k := range Kinds() {
		if !kinds[k.String()] {
			t.Errorf("no case runs a %s schedule", k)
		}
	}
	from, to := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tz := range []string{ny, london, howe, india, chile, chat} {
		if !zones[tz] {
			t.Errorf("no case runs in %s", tz)
		}
		found := changes(zone(t, tz), from, to)
		if want := map[bool]int{true: 0, false: 4}[tz == india]; len(found) != want {
			t.Errorf("%s changes its clocks %d times in 2026 and 2027, want %d", tz, len(found), want)
		}
		for _, change := range found {
			across, onceNear := 0, false
			for _, c := range file.Cases {
				if c.Spec.TZ != tz || len(c.Next) == 0 {
					continue
				}
				first, last := utc(t, c.Now), utc(t, c.Next[len(c.Next)-1])
				if c.Spec.Kind == "once" {
					onceNear = onceNear || last.Sub(change).Abs() <= 2*time.Hour
				} else if first.Before(change) && !last.Before(change) {
					across++
				}
			}
			if across < 3 || !onceNear {
				t.Errorf("%s's change at %s: %d cron cases run across it, a one-time run near it %t", tz, change.Format(time.RFC3339), across, onceNear)
			}
		}
	}
}
