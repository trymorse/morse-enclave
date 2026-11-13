package schedule

import (
	"math/rand/v2"
	"testing"
	"time"
)

func zone(t testing.TB, tz string) *time.Location {
	t.Helper()
	loc, err := Zone(tz)
	if err != nil {
		t.Fatalf("zone %s: %v", tz, err)
	}
	return loc
}

func utc(t testing.TB, text string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, text)
	if err != nil {
		t.Fatal(err)
	}
	return at.UTC()
}

func wallAt(t testing.TB, text string) time.Time {
	t.Helper()
	at, err := time.Parse("2006-01-02 15:04", text)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func wallOf(at time.Time, loc *time.Location) time.Time {
	l := at.In(loc)
	y, m, d := l.Date()
	h, mi, _ := l.Clock()
	return time.Date(y, m, d, h, mi, 0, 0, time.UTC)
}

func slowInstant(loc *time.Location, wall time.Time) time.Time {
	for quarters := 16 * 4; quarters >= -16*4; quarters-- {
		at := wall.Add(-time.Duration(quarters) * 15 * time.Minute)
		if wallOf(at, loc).Equal(wall) {
			return at
		}
	}
	for at := wall.Add(-17 * time.Hour); at.Before(wall.Add(17 * time.Hour)); at = at.Add(15 * time.Minute) {
		if wallOf(at, loc).Before(wall) && wallOf(at.Add(15*time.Minute), loc).After(wall) {
			_, offset := at.In(loc).Zone()
			return wall.Add(-time.Duration(offset) * time.Second)
		}
	}
	panic("no instant shows " + wall.Format(time.DateTime) + " in " + loc.String() + ", and the clocks never jump past it")
}

var wallInstants = []struct{ tz, wall, want string }{
	{"America/New_York", "2026-03-08 01:59", "2026-03-08T06:59:00Z"},
	{"America/New_York", "2026-03-08 02:00", "2026-03-08T07:00:00Z"},
	{"America/New_York", "2026-03-08 02:30", "2026-03-08T07:30:00Z"},
	{"America/New_York", "2026-03-08 02:59", "2026-03-08T07:59:00Z"},
	{"America/New_York", "2026-03-08 03:00", "2026-03-08T07:00:00Z"},
	{"America/New_York", "2026-11-01 00:59", "2026-11-01T04:59:00Z"},
	{"America/New_York", "2026-11-01 01:00", "2026-11-01T05:00:00Z"},
	{"America/New_York", "2026-11-01 01:30", "2026-11-01T05:30:00Z"},
	{"America/New_York", "2026-11-01 01:59", "2026-11-01T05:59:00Z"},
	{"America/New_York", "2026-11-01 02:00", "2026-11-01T07:00:00Z"},
	{"America/New_York", "2027-03-14 02:30", "2027-03-14T07:30:00Z"},
	{"America/New_York", "2027-11-07 01:30", "2027-11-07T05:30:00Z"},
	{"Europe/London", "2026-03-29 00:59", "2026-03-29T00:59:00Z"},
	{"Europe/London", "2026-03-29 01:00", "2026-03-29T01:00:00Z"},
	{"Europe/London", "2026-03-29 01:30", "2026-03-29T01:30:00Z"},
	{"Europe/London", "2026-03-29 02:00", "2026-03-29T01:00:00Z"},
	{"Europe/London", "2026-10-25 00:59", "2026-10-24T23:59:00Z"},
	{"Europe/London", "2026-10-25 01:00", "2026-10-25T00:00:00Z"},
	{"Europe/London", "2026-10-25 01:30", "2026-10-25T00:30:00Z"},
	{"Europe/London", "2026-10-25 02:00", "2026-10-25T02:00:00Z"},
	{"Europe/London", "2027-03-28 01:30", "2027-03-28T01:30:00Z"},
	{"Europe/London", "2027-10-31 01:30", "2027-10-31T00:30:00Z"},
	{"Australia/Lord_Howe", "2026-04-05 01:29", "2026-04-04T14:29:00Z"},
	{"Australia/Lord_Howe", "2026-04-05 01:30", "2026-04-04T14:30:00Z"},
	{"Australia/Lord_Howe", "2026-04-05 01:45", "2026-04-04T14:45:00Z"},
	{"Australia/Lord_Howe", "2026-04-05 01:59", "2026-04-04T14:59:00Z"},
	{"Australia/Lord_Howe", "2026-04-05 02:00", "2026-04-04T15:30:00Z"},
	{"Australia/Lord_Howe", "2026-10-04 01:59", "2026-10-03T15:29:00Z"},
	{"Australia/Lord_Howe", "2026-10-04 02:00", "2026-10-03T15:30:00Z"},
	{"Australia/Lord_Howe", "2026-10-04 02:15", "2026-10-03T15:45:00Z"},
	{"Australia/Lord_Howe", "2026-10-04 02:29", "2026-10-03T15:59:00Z"},
	{"Australia/Lord_Howe", "2026-10-04 02:30", "2026-10-03T15:30:00Z"},
	{"Australia/Lord_Howe", "2027-04-04 01:45", "2027-04-03T14:45:00Z"},
	{"Australia/Lord_Howe", "2027-10-03 02:15", "2027-10-02T15:45:00Z"},
	{"America/Santiago", "2026-04-04 22:59", "2026-04-05T01:59:00Z"},
	{"America/Santiago", "2026-04-04 23:00", "2026-04-05T02:00:00Z"},
	{"America/Santiago", "2026-04-04 23:30", "2026-04-05T02:30:00Z"},
	{"America/Santiago", "2026-04-04 23:59", "2026-04-05T02:59:00Z"},
	{"America/Santiago", "2026-04-05 00:00", "2026-04-05T04:00:00Z"},
	{"America/Santiago", "2026-09-05 23:59", "2026-09-06T03:59:00Z"},
	{"America/Santiago", "2026-09-06 00:00", "2026-09-06T04:00:00Z"},
	{"America/Santiago", "2026-09-06 00:30", "2026-09-06T04:30:00Z"},
	{"America/Santiago", "2026-09-06 00:59", "2026-09-06T04:59:00Z"},
	{"America/Santiago", "2026-09-06 01:00", "2026-09-06T04:00:00Z"},
	{"America/Santiago", "2027-04-03 23:30", "2027-04-04T02:30:00Z"},
	{"America/Santiago", "2027-09-05 00:30", "2027-09-05T04:30:00Z"},
	{"Pacific/Chatham", "2026-04-05 02:44", "2026-04-04T12:59:00Z"},
	{"Pacific/Chatham", "2026-04-05 02:45", "2026-04-04T13:00:00Z"},
	{"Pacific/Chatham", "2026-04-05 03:15", "2026-04-04T13:30:00Z"},
	{"Pacific/Chatham", "2026-04-05 03:44", "2026-04-04T13:59:00Z"},
	{"Pacific/Chatham", "2026-04-05 03:45", "2026-04-04T15:00:00Z"},
	{"Pacific/Chatham", "2026-09-27 02:44", "2026-09-26T13:59:00Z"},
	{"Pacific/Chatham", "2026-09-27 02:45", "2026-09-26T14:00:00Z"},
	{"Pacific/Chatham", "2026-09-27 03:15", "2026-09-26T14:30:00Z"},
	{"Pacific/Chatham", "2026-09-27 03:44", "2026-09-26T14:59:00Z"},
	{"Pacific/Chatham", "2026-09-27 03:45", "2026-09-26T14:00:00Z"},
	{"Pacific/Chatham", "2027-04-04 03:15", "2027-04-03T13:30:00Z"},
	{"Pacific/Chatham", "2027-09-26 03:15", "2027-09-25T14:30:00Z"},
	{"Asia/Kolkata", "2026-10-27 05:30", "2026-10-27T00:00:00Z"},
	{"Asia/Kolkata", "2026-01-01 00:00", "2025-12-31T18:30:00Z"},
	{"UTC", "2026-03-08 02:30", "2026-03-08T02:30:00Z"},
}

func TestAWallTimeNamesItsOnlyInstantItsFirstPassOrItsTimeUnderTheOffsetBeforeTheSkip(t *testing.T) {
	for _, c := range wallInstants {
		loc, wall := zone(t, c.tz), wallAt(t, c.wall)
		got := resolve(loc, wall)
		if want := utc(t, c.want); !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("%s %s is %s, want %s", c.tz, c.wall, got.Format(time.RFC3339), c.want)
		}
		if slow := slowInstant(loc, wall); !slow.Equal(got) {
			t.Errorf("%s %s: the slow search finds %s, resolve %s", c.tz, c.wall, slow.Format(time.RFC3339), got.Format(time.RFC3339))
		}
	}
}

var testZones = []string{
	"America/New_York", "Europe/London", "Australia/Lord_Howe", "Asia/Kolkata", "America/Santiago", "Pacific/Chatham",
	"UTC", "America/Los_Angeles", "America/St_Johns", "America/Havana", "America/Nuuk", "America/Scoresbysund",
	"America/Sao_Paulo", "America/Asuncion", "Pacific/Honolulu", "Pacific/Apia", "Pacific/Kiritimati", "Pacific/Pago_Pago",
	"Pacific/Norfolk", "Pacific/Auckland", "Australia/Adelaide", "Australia/Eucla", "Asia/Kathmandu", "Asia/Tehran",
	"Asia/Gaza", "Asia/Beirut", "Asia/Jerusalem", "Africa/Cairo", "Africa/Casablanca", "Europe/Dublin", "Europe/Moscow",
	"Antarctica/Troll", "Etc/GMT+12", "Etc/GMT-14",
}

func changes(loc *time.Location, from, to time.Time) []time.Time {
	var out []time.Time
	for at := from.In(loc); ; {
		_, end := at.ZoneBounds()
		if end.IsZero() || end.After(to) {
			return out
		}
		_, before := end.Add(-time.Second).In(loc).Zone()
		if _, offset := end.Zone(); offset != before {
			out = append(out, end)
		}
		at = end
	}
}

func TestResolveAgreesWithTheSlowSearchAroundEveryChangeOfClockInTheTestZones(t *testing.T) {
	from, to := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	checked := 0
	for _, tz := range testZones {
		loc := zone(t, tz)
		for _, change := range changes(loc, from, to) {
			_, before := change.Add(-time.Second).In(loc).Zone()
			_, after := change.In(loc).Zone()
			first := wallOf(change, loc).Add(-time.Duration(max(after-before, before-after))*time.Second - 30*time.Minute)
			for wall := first; wall.Before(first.Add(4 * time.Hour)); wall = wall.Add(5 * time.Minute) {
				if got, slow := resolve(loc, wall), slowInstant(loc, wall); !got.Equal(slow) {
					t.Errorf("%s %s: resolve %s, the slow search %s", tz, wall.Format("2006-01-02 15:04"), got.Format(time.RFC3339), slow.Format(time.RFC3339))
				}
				checked++
			}
		}
	}
	if checked < 3000 {
		t.Errorf("checked only %d wall times; the test zones' changes are not being found", checked)
	}
}

func TestResolveIsTimeDateWhereTheClocksShowAWallTimeOnce(t *testing.T) {
	rng := rand.New(rand.NewPCG(27, 10))
	for range 2000 {
		loc := zone(t, testZones[rng.IntN(len(testZones))])
		wall := time.Date(2026+rng.IntN(80), time.Month(1+rng.IntN(12)), 1+rng.IntN(28), rng.IntN(24), rng.IntN(60), 0, 0, time.UTC)
		date := time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), 0, 0, loc)
		shown := 0
		for quarters := -64; quarters <= 64; quarters++ {
			if wallOf(wall.Add(time.Duration(quarters)*15*time.Minute), loc).Equal(wall) {
				shown++
			}
		}
		if got := resolve(loc, wall); shown == 1 && !got.Equal(date) {
			t.Errorf("%s %s: resolve %s, time.Date %s", loc, wall.Format("2006-01-02 15:04"), got.Format(time.RFC3339), date.UTC().Format(time.RFC3339))
		}
	}
}
