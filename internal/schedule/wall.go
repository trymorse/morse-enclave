package schedule

import "time"

// reach bounds how far from a wall time, read as if in UTC, the instants it names and the changes of clock that
// skip it lie. No zone's offset comes near it.
const reach = 36 * time.Hour

// resolve is the instant a wall time names in loc, by contracts.md section E.4. wall is the wall time read as if in
// UTC. When the clocks show it once, that instant. When they show it twice, as they go back, the earlier. When they
// skip it, as they go forward, the instant it names under the offset in force just before the skip, which the
// clocks show as the wall time plus the skip's length. time.Date promises none of these, and on Go 1.27.3 it gives
// the later pass of a repeat in London and an instant on the wrong day for Santiago's midnight skip.
//
// It walks the zone's periods in order: the first that holds the instant the wall time names under its own offset
// holds the earliest, and a wall time no period holds lies in the gap a forward change opens.
func resolve(loc *time.Location, wall time.Time) time.Time {
	var (
		skip      time.Time
		skipped   bool
		before    int
		hasBefore bool
	)
	for at := wall.Add(-reach).In(loc); ; {
		start, end := at.ZoneBounds()
		_, offset := at.Zone()
		named := wall.Add(-time.Duration(offset) * time.Second)
		if (start.IsZero() || !named.Before(start)) && (end.IsZero() || named.Before(end)) {
			return named
		}
		if hasBefore && !skipped && offset > before {
			gapStart := start.Add(time.Duration(before) * time.Second)
			gapEnd := start.Add(time.Duration(offset) * time.Second)
			if !wall.Before(gapStart) && wall.Before(gapEnd) {
				skip, skipped = wall.Add(-time.Duration(before)*time.Second), true
			}
		}
		if end.IsZero() || end.After(wall.Add(reach)) || !end.After(at) {
			break
		}
		at, before, hasBefore = end, offset, true
	}
	if skipped {
		return skip
	}
	return time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), 0, 0, loc).UTC()
}
