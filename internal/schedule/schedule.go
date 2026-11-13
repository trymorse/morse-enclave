package schedule

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"time"
	_ "time/tzdata"
)

// Error is a refused spec: Code is the first rule of contracts.md section E.5 it breaks.
type Error struct{ Code Code }

var reasons = map[Code]string{
	CodeKind:       "the kind is not once, hourly, daily, weekdays, weekly, or custom",
	CodeFields:     "a once schedule carries once_local and no cron, and every other kind a cron and no once_local",
	CodeTZ:         "tz is not an IANA time zone name of at most 64 bytes",
	CodeOnceFormat: "once_local is not a real date and time written YYYY-MM-DDTHH:MM",
	CodeOncePast:   "the one-time run is less than a minute from now",
	CodeCronSyntax: "the cron is not five fields of numbers, ranges, steps, and lists, one space apart, in at most 100 bytes",
	CodeCronRange:  "a cron field names a value outside its range, a range that runs backwards, or a step of 0",
	CodeCronMinute: "the cron's minute is not a single number, so it would run more than once an hour",
	CodeCronDays:   "the cron restricts both the day of the month and the day of the week",
	CodeCronShape:  "the cron does not have its preset's shape",
	CodeCronNever:  "none of the cron's days of the month comes in any of its months",
}

func (e Error) Error() string { return "schedule: " + string(e.Code) + ": " + reasons[e.Code] }

// CodeOf is the code a refusal from this package carries, and false for any other error.
func CodeOf(err error) (Code, bool) {
	var refused Error
	if errors.As(err, &refused) {
		return refused.Code, true
	}
	return "", false
}

// CheckFields checks what a spec's fields alone decide, E.5 rows 1 and 2: a kind of the six, OnceLocal and no Cron
// for Once, and a Cron and no OnceLocal for every other kind.
func (s Spec) CheckFields() error {
	once := s.Kind == Once
	switch {
	case !kindNames.Valid(s.Kind):
		return Error{CodeKind}
	case once != (s.OnceLocal != ""), once == (s.Cron != ""):
		return Error{CodeFields}
	}
	return nil
}

// Zone loads a schedule's time zone, refusing what E.5 row 3 refuses: an empty name, one over 64 bytes, Local, and
// any time.LoadLocation doesn't know.
func Zone(tz string) (*time.Location, error) {
	if tz == "" || len(tz) > MaxTZ || tz == "Local" {
		return nil, Error{CodeTZ}
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, Error{CodeTZ}
	}
	return loc, nil
}

// Schedule is a spec Parse or Load accepted, with its zone loaded and its cron read. The zero Schedule never runs.
type Schedule struct {
	kind Kind
	loc  *time.Location
	cron cron
	once time.Time
}

// Parse reads a spec as a task route does when a device sets it at now: every rule of E.5 in order, the first the
// spec breaks refusing it as an Error.
func Parse(s Spec, now time.Time) (Schedule, error) {
	sch, err := Load(s)
	if err != nil {
		return Schedule{}, err
	}
	if s.Kind == Once && sch.once.Before(now.Add(OnceLead)) {
		return Schedule{}, Error{CodeOncePast}
	}
	return sch, nil
}

// Load reads a spec the relay already holds by every rule Parse checks but once_past, since a stored one-time run's
// time may have passed.
func Load(s Spec) (Schedule, error) {
	if err := s.CheckFields(); err != nil {
		return Schedule{}, err
	}
	loc, err := Zone(s.TZ)
	if err != nil {
		return Schedule{}, err
	}
	if s.Kind == Once {
		wall, ok := readOnce(s.OnceLocal)
		if !ok {
			return Schedule{}, Error{CodeOnceFormat}
		}
		return Schedule{kind: Once, loc: loc, once: resolve(loc, wall)}, nil
	}
	c, err := readCron(s.Kind, s.Cron)
	if err != nil {
		return Schedule{}, err
	}
	return Schedule{kind: s.Kind, loc: loc, cron: c}, nil
}

// Next is the schedule's first run strictly after after (E.6), in UTC, and false when it has none left: a one-time
// run at or before after. Every cron Parse accepts runs again within nine years.
func (s Schedule) Next(after time.Time) (time.Time, bool) {
	switch {
	case s.loc == nil, s.kind == Once && !s.once.After(after):
		return time.Time{}, false
	case s.kind == Once:
		return s.once, true
	}
	return s.cron.next(s.loc, after)
}

// Once is a one-time schedule's instant (E.4), whether or not it has passed, and false for every other kind.
func (s Schedule) Once() (time.Time, bool) {
	if s.loc == nil || s.kind != Once {
		return time.Time{}, false
	}
	return s.once, true
}

// Next loads a spec the relay holds and finds its first run strictly after after: false when Load refuses the spec
// or it has no run left.
func Next(s Spec, after time.Time) (time.Time, bool) {
	sch, err := Load(s)
	if err != nil {
		return time.Time{}, false
	}
	return sch.Next(after)
}

const jitterSeconds = 120

// Jitter is how long after its schedule's time a task's run falls due (E.6): 0 to 119 whole seconds, fixed by the
// task's id, so tasks set for the same minute don't all start in it. A manual run has none.
func Jitter(task [16]byte) time.Duration {
	sum := sha256.Sum256(task[:])
	return time.Duration(binary.BigEndian.Uint64(sum[:8])%jitterSeconds) * time.Second
}

// PresetCron is the cron a preset compiles to (E.3), written as the app writes it, without leading zeros: hourly
// "m * * * *", daily "m h * * *", weekdays "m h * * 1-5", weekly "m h * * d". Hourly reads only minute, and only
// weekly reads day. A kind that isn't a preset is CodeKind; a value it reads out of range, CodeCronRange.
func PresetCron(k Kind, minute, hour int, day time.Weekday) (string, error) {
	in := func(n, lo, hi int) bool { return lo <= n && n <= hi }
	switch {
	case k != Hourly && k != Daily && k != Weekdays && k != Weekly:
		return "", Error{CodeKind}
	case !in(minute, 0, 59), k != Hourly && !in(hour, 0, 23), k == Weekly && !in(int(day), 0, 6):
		return "", Error{CodeCronRange}
	}
	m, h := strconv.Itoa(minute), strconv.Itoa(hour)
	switch k {
	case Hourly:
		return m + " * * * *", nil
	case Daily:
		return m + " " + h + " * * *", nil
	case Weekdays:
		return m + " " + h + " * * 1-5", nil
	}
	return m + " " + h + " * * " + strconv.Itoa(int(day)), nil
}

func readOnce(text string) (time.Time, bool) {
	if len(text) != len(OnceLayout) || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' {
		return time.Time{}, false
	}
	digits := func(from, to int) int {
		n := 0
		for i := from; i < to; i++ {
			if text[i] < '0' || text[i] > '9' {
				return -1
			}
			n = n*10 + int(text[i]-'0')
		}
		return n
	}
	year, month, day, hour, minute := digits(0, 4), digits(5, 7), digits(8, 10), digits(11, 13), digits(14, 16)
	if year < 0 || month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return time.Time{}, false
	}
	wall := time.Date(year, time.Month(month), day, hour, minute, 0, 0, time.UTC)
	if wall.Day() != day {
		return time.Time{}, false
	}
	return wall, true
}
