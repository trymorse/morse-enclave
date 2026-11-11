package schedule

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

// slowNext is cron.next the slow way: every day from the day before after's, one at a time, each of the cron's
// hours at its minute, turned to an instant by slowInstant, an instant at or before after or the one before it
// dropped.
func slowNext(c cron, loc *time.Location, after time.Time, days int) (time.Time, bool) {
	y, m, d := after.In(loc).Date()
	var prev time.Time
	enumerated := false
	for i := -1; i <= days; i++ {
		day := time.Date(y, m, d+i, 0, 0, 0, 0, time.UTC)
		if c.months&(1<<int(day.Month())) == 0 || !c.everyDom && c.doms&(1<<day.Day()) == 0 || !c.everyDow && c.dows&(1<<int(day.Weekday())) == 0 {
			continue
		}
		for h := range 24 {
			if c.hours&(1<<h) == 0 {
				continue
			}
			at := slowInstant(loc, day.Add(time.Duration(h)*time.Hour+time.Duration(c.minute)*time.Minute))
			if at.After(after) && (!enumerated || at.After(prev)) {
				return at, true
			}
			prev, enumerated = at, true
		}
	}
	return time.Time{}, false
}

func (c cron) matches(wall time.Time) bool {
	return wall.Minute() == c.minute && c.hours&(1<<wall.Hour()) != 0 && c.runsOn(wall)
}

// onItsWallTime is whether a run is the instant one of the cron's wall times names by E.4, checked from the run's
// side: it shows a wall time the cron lists and no instant in the three hours before showed it, or it lies in the
// gap a forward change opened and under the offset before the change it names a wall time the cron lists.
func onItsWallTime(c cron, loc *time.Location, run time.Time) bool {
	wall := wallOf(run, loc)
	firstPass := true
	for back := 15 * time.Minute; back <= 3*time.Hour; back += 15 * time.Minute {
		firstPass = firstPass && !wallOf(run.Add(-back), loc).Equal(wall)
	}
	if c.matches(wall) && firstPass {
		return true
	}
	start, _ := run.In(loc).ZoneBounds()
	_, before := start.Add(-time.Second).In(loc).Zone()
	_, after := run.In(loc).Zone()
	gap := time.Duration(after-before) * time.Second
	return gap > 0 && run.Sub(start) < gap && c.matches(run.UTC().Add(time.Duration(before)*time.Second))
}

func randomField(rng *rand.Rand, min, max int) string {
	pick := func() int { return min + rng.IntN(max-min+1) }
	switch rng.IntN(6) {
	case 0:
		return "*"
	case 1:
		return strconv.Itoa(pick())
	case 2:
		a := pick()
		return fmt.Sprintf("%d-%d", a, a+rng.IntN(max-a+1))
	case 3:
		a := pick()
		return fmt.Sprintf("%d-%d/%d", a, a+rng.IntN(max-a+1), 1+rng.IntN(6))
	case 4:
		return fmt.Sprintf("*/%d", 1+rng.IntN(8))
	}
	items := make([]string, 1+rng.IntN(4))
	for i := range items {
		items[i] = strconv.Itoa(pick())
	}
	return strings.Join(items, ",")
}

// randomCron is a custom cron Parse accepts: mostly every day, often every hour, so most runs fall near a change of
// clock when one is near.
func randomCron(rng *rand.Rand) string {
	minute := strconv.Itoa(rng.IntN(60))
	if rng.IntN(8) == 0 {
		minute = fmt.Sprintf("%02d", rng.IntN(60))
	}
	hour := "*"
	if rng.IntN(3) > 0 {
		hour = randomField(rng, 0, 23)
	}
	dom, month, dow := "*", "*", "*"
	switch rng.IntN(10) {
	case 0, 1:
		dow = randomField(rng, 0, 7)
	case 2:
		dom = randomField(rng, 1, 28)
	case 3:
		month = randomField(rng, 1, 12)
	}
	return strings.Join([]string{minute, hour, dom, month, dow}, " ")
}

// TestRandomCronsRunInOrderOnTheirWallTimesAndNoMoreThanHourly draws crons and zones, starts each within 14 hours
// before one of the zone's changes of clock, and checks each of 16 runs: that it comes after the one
// before; that it is at least an hour after it, or an hour less the rise when the clocks went forward by less
// than an hour between them (Lord Howe's half hour); that it is the instant E.4 gives one of the cron's wall times;
// and that the slow search finds the same run.
func TestRandomCronsRunInOrderOnTheirWallTimesAndNoMoreThanHourly(t *testing.T) {
	rng := rand.New(rand.NewPCG(2026, 1027))
	from, to := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	var changing []string
	for _, tz := range testZones {
		if len(changes(zone(t, tz), from, to)) > 0 {
			changing = append(changing, tz)
		}
	}
	nearChanges, checked := 0, 0
	for range 160 {
		tz := testZones[rng.IntN(len(testZones))]
		if rng.IntN(4) > 0 {
			tz = changing[rng.IntN(len(changing))]
		}
		loc := zone(t, tz)
		text := randomCron(rng)
		sch, err := Parse(Spec{Kind: Custom, Cron: text, TZ: tz}, from)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		after := from.Add(time.Duration(rng.Int64N(int64(to.Sub(from)))))
		if near := changes(loc, from, to); len(near) > 0 {
			after = near[rng.IntN(len(near))].Add(-time.Duration(rng.Int64N(int64(14 * time.Hour))))
			nearChanges++
		}
		prev := after
		for i := range 16 {
			run, ok := sch.Next(prev)
			if !ok {
				t.Fatalf("%s %q has no run after %s", tz, text, prev.Format(time.RFC3339))
			}
			if !run.After(prev) {
				t.Fatalf("%s %q: run %d at %s is not after %s", tz, text, i, run.Format(time.RFC3339), prev.Format(time.RFC3339))
			}
			if i > 0 {
				_, wasOffset := prev.Add(-time.Hour).In(loc).Zone()
				_, isOffset := run.In(loc).Zone()
				least := time.Hour
				if rise := time.Duration(isOffset-wasOffset) * time.Second; rise > 0 && rise < time.Hour {
					least -= rise
				}
				if gap := run.Sub(prev); gap < least {
					t.Errorf("%s %q: %s runs %s after %s, under %s", tz, text, run.Format(time.RFC3339), gap, prev.Format(time.RFC3339), least)
				}
			}
			if !onItsWallTime(sch.cron, loc, run) {
				t.Errorf("%s %q: %s (%s) is no wall time of the cron", tz, text, run.Format(time.RFC3339), run.In(loc).Format(time.RFC3339))
			}
			if slow, ok := slowNext(sch.cron, loc, prev, 400); !ok || !slow.Equal(run) {
				t.Errorf("%s %q after %s: Next %s, the slow search %s", tz, text, prev.Format(time.RFC3339), run.Format(time.RFC3339), slow.Format(time.RFC3339))
			}
			prev = run
			checked++
		}
	}
	if len(changing) < 15 || nearChanges < 115 || checked != 160*16 {
		t.Errorf("%d zones change; started near a change %d times and checked %d runs; the draw is not reaching the changes", len(changing), nearChanges, checked)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []struct {
		kind           Kind
		cron, once, tz string
	}{
		{Hourly, "5 * * * *", "", "Asia/Kolkata"},
		{Daily, "30 2 * * *", "", "America/New_York"},
		{Weekdays, "0 7 * * 1-5", "", "Europe/London"},
		{Weekly, "45 1 * * 0", "", "Australia/Lord_Howe"},
		{Custom, "15 2,3 * * *", "", "Pacific/Chatham"},
		{Custom, "30 0 * 9 *", "", "America/Santiago"},
		{Custom, "0 9 29 2 *", "", "UTC"},
		{Custom, "0 9 30 2 *", "", "UTC"},
		{Custom, "*/5 * * * *", "", "UTC"},
		{Custom, "0 9 1 * 1", "", "UTC"},
		{Once, "", "2026-11-01T01:30", "America/New_York"},
		{Once, "", "2026-03-08T02:30", "America/New_York"},
		{Once, "0 9 * * *", "2026-10-28T08:00", "UTC"},
		{0, "", "", ""},
	} {
		f.Add(uint8(seed.kind), seed.cron, seed.once, seed.tz, int64(26*365*24*3600))
	}
	base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, kind uint8, cron, once, tz string, seconds int64) {
		now := base.Add(time.Duration(seconds%(300*366*24*3600)) * time.Second)
		spec := Spec{Kind: Kind(kind), Cron: cron, OnceLocal: once, TZ: tz}
		sch, err := Parse(spec, now)
		loaded, loadErr := Load(spec)
		if err != nil {
			code, ok := CodeOf(err)
			if !ok {
				t.Fatalf("%+v refused without a code: %v", spec, err)
			}
			if loadCode, _ := CodeOf(loadErr); loadErr != nil && loadCode != code {
				t.Fatalf("%+v: Parse says %s, Load %s", spec, code, loadCode)
			}
			if loadErr == nil && code != CodeOncePast {
				t.Fatalf("%+v: Load takes what Parse refuses as %s", spec, code)
			}
			return
		}
		if loadErr != nil || spec.CheckFields() != nil {
			t.Fatalf("%+v: Parse takes it, Load says %v", spec, loadErr)
		}
		if at, ok := loaded.Once(); spec.Kind == Once && (!ok || at.Before(now.Add(OnceLead))) {
			t.Fatalf("%+v at %s: once at %s %t", spec, now, at, ok)
		}
		prev := now
		for range 3 {
			next, ok := sch.Next(prev)
			if !ok {
				if spec.Kind == Once && prev.After(now) {
					return
				}
				t.Fatalf("%+v: no run after %s", spec, prev)
			}
			if !next.After(prev) {
				t.Fatalf("%+v: %s is not after %s", spec, next, prev)
			}
			prev = next
		}
	})
}
