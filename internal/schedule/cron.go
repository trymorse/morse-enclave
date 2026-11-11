package schedule

import (
	"strings"
	"time"
)

// cron is a cron of the subset contracts.md section E.2 allows: the one minute it runs at, and a bit for each hour,
// day of the month, month, and day of the week it runs in, with Sunday at bit 0 whichever of 0 and 7 named it.
type cron struct {
	minute                    int
	hours, doms, months, dows uint64
	everyDom, everyDow        bool
}

var fieldBounds = [5]struct{ lo, hi int }{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}

// longest is the most days each month has, February's 29 included, for cron_never.
var longest = [13]int{1: 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// searchYears bounds the search for a run. The longest an accepted cron waits for a day it runs on is eight years,
// from one 29 February to the next across a century year that isn't a leap year, as from 2096 to 2104.
const searchYears = 9

// readCron reads a preset's or a custom cron by E.5 rows 6 to 10, in order.
func readCron(k Kind, text string) (cron, error) {
	if len(text) > MaxCron {
		return cron{}, Error{CodeCronSyntax}
	}
	fields := strings.Split(text, " ")
	if len(fields) != 5 {
		return cron{}, Error{CodeCronSyntax}
	}
	var sets [5]uint64
	for i, field := range fields {
		set, err := readField(field, fieldBounds[i].lo, fieldBounds[i].hi)
		if err != nil {
			return cron{}, err
		}
		sets[i] = set
	}
	minute, single := number(fields[0])
	if !single {
		return cron{}, Error{CodeCronMinute}
	}
	c := cron{minute: minute, hours: sets[1], doms: sets[2], months: sets[3], dows: sets[4]&0x7f | sets[4]>>7, everyDom: fields[2] == "*", everyDow: fields[4] == "*"}
	switch {
	case !c.everyDom && !c.everyDow:
		return cron{}, Error{CodeCronDays}
	case !shaped(k, fields):
		return cron{}, Error{CodeCronShape}
	case c.never():
		return cron{}, Error{CodeCronNever}
	}
	return c, nil
}

type item struct{ from, to, step int }

// readField reads one field into a bit per value it allows. A field that doesn't parse is cron_syntax, whatever
// else is wrong with it; one that parses but names a value outside lo to hi, a range that runs backwards, or a step
// of 0 is cron_range.
func readField(field string, lo, hi int) (uint64, error) {
	if field == "*" {
		return span(lo, hi, 1), nil
	}
	var items []item
	for _, text := range strings.Split(field, ",") {
		it, ok := readItem(text, lo, hi)
		if !ok {
			return 0, Error{CodeCronSyntax}
		}
		items = append(items, it)
	}
	var set uint64
	for _, it := range items {
		if it.from < lo || it.to > hi || it.from > it.to || it.step < 1 {
			return 0, Error{CodeCronRange}
		}
		set |= span(it.from, it.to, it.step)
	}
	return set, nil
}

// readItem reads number, number "-" number ["/" step], or "*/" step.
func readItem(text string, lo, hi int) (item, bool) {
	if step, ok := strings.CutPrefix(text, "*/"); ok {
		n, ok := number(step)
		return item{lo, hi, n}, ok
	}
	bounds, step, stepped := strings.Cut(text, "/")
	from, to, ranged := strings.Cut(bounds, "-")
	if !ranged {
		n, ok := number(text)
		return item{n, n, 1}, ok
	}
	a, okA := number(from)
	b, okB := number(to)
	n, okN := 1, true
	if stepped {
		n, okN = number(step)
	}
	return item{a, b, n}, okA && okB && okN
}

// number reads one or two ASCII digits.
func number(text string) (int, bool) {
	if len(text) < 1 || len(text) > 2 {
		return 0, false
	}
	n := 0
	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
		n = n*10 + int(text[i]-'0')
	}
	return n, true
}

func span(from, to, step int) uint64 {
	var set uint64
	for n := from; n <= to; n += step {
		set |= 1 << n
	}
	return set
}

// shaped is whether a preset's cron has its preset's shape (E.3). The minute is a single number by now.
func shaped(k Kind, fields []string) bool {
	_, oneHour := number(fields[1])
	everyDay := fields[2] == "*" && fields[3] == "*"
	switch k {
	case Hourly:
		return fields[1] == "*" && everyDay && fields[4] == "*"
	case Daily:
		return oneHour && everyDay && fields[4] == "*"
	case Weekdays:
		return oneHour && everyDay && fields[4] == "1-5"
	case Weekly:
		day, oneDay := number(fields[4])
		return oneHour && everyDay && oneDay && day <= 6
	}
	return true
}

// never is whether none of the days of the month the cron names comes in any month it names.
func (c cron) never() bool {
	if c.everyDom {
		return false
	}
	for m := 1; m <= 12; m++ {
		if c.months&(1<<m) != 0 && c.doms&span(1, longest[m], 1) != 0 {
			return false
		}
	}
	return true
}

func (c cron) runsOn(day time.Time) bool {
	return c.months&(1<<int(day.Month())) != 0 && (c.everyDom || c.doms&(1<<day.Day()) != 0) && (c.everyDow || c.dows&(1<<int(day.Weekday())) != 0)
}

// next is the cron's first run strictly after after (E.6): taking the days it runs on in order and each of its
// hours at its minute, the first instant resolve gives that is after after. Wall order decides, not instant order,
// so a skipped time that lands on a later listed time is that time's instant and runs once. E.6 also drops an
// instant at or before the one before it, which never changes which run comes first: the instant before the first
// one after after is at or before after. The days start the day before after's, so a time a forward change carried
// past midnight is not missed.
func (c cron) next(loc *time.Location, after time.Time) (time.Time, bool) {
	y, m, d := after.In(loc).Date()
	day := time.Date(y, m, d-1, 0, 0, 0, 0, time.UTC)
	for end := day.AddDate(searchYears, 0, 0); day.Before(end); {
		if c.months&(1<<int(day.Month())) == 0 {
			day = time.Date(day.Year(), day.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if c.runsOn(day) {
			for h := range 24 {
				if c.hours&(1<<h) == 0 {
					continue
				}
				if at := resolve(loc, day.Add(time.Duration(h)*time.Hour+time.Duration(c.minute)*time.Minute)); at.After(after) {
					return at, true
				}
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return time.Time{}, false
}
