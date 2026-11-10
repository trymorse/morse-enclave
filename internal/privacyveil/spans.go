package privacyveil

import (
	"cmp"
	"slices"
	"unicode/utf8"
)

// Span is a detail found in a segment, at byte offsets.
type Span struct {
	Start, End int
	Type       Type
}

// merge unions the filter's spans with the validators'. Spans that overlap become one span over all of them, typed
// as a validator's SSN or card if one is among them, and otherwise as the most sensitive of their types, then the
// longest. So a grant can never release an SSN that the filter labeled a phone number.
func merge(filtered, validated []Span) []Span {
	type tagged struct {
		Span
		validated bool
	}
	all := make([]tagged, 0, len(filtered)+len(validated))
	for _, s := range filtered {
		all = append(all, tagged{Span: s})
	}
	for _, s := range validated {
		all = append(all, tagged{Span: s, validated: true})
	}
	slices.SortFunc(all, func(a, b tagged) int { return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End)) })
	var merged []Span
	for i := 0; i < len(all); {
		group := all[i]
		winner, winnerValidated := group.Span, group.validated
		end := group.End
		j := i + 1
		for ; j < len(all) && all[j].Start < end; j++ {
			end = max(end, all[j].End)
			if beats(all[j].Span, all[j].validated, winner, winnerValidated) {
				winner, winnerValidated = all[j].Span, all[j].validated
			}
		}
		if group.Start < end {
			merged = append(merged, Span{Start: group.Start, End: end, Type: winner.Type})
		}
		i = j
	}
	return merged
}

func beats(s Span, validated bool, than Span, thanValidated bool) bool {
	if validated != thanValidated {
		return validated
	}
	if s.Type.rank() != than.Type.rank() {
		return s.Type.rank() > than.Type.rank()
	}
	return s.End-s.Start > than.End-than.Start
}

// ByteOffsets turns code-point offsets into text into byte offsets, and false when either is out of range.
func ByteOffsets(text string, start, end int) (int, int, bool) {
	if start < 0 || end < start {
		return 0, 0, false
	}
	points, startByte := 0, -1
	for i := range text {
		if points == start {
			startByte = i
		}
		if points == end {
			return startByte, i, startByte >= 0
		}
		points++
	}
	if points == start {
		startByte = len(text)
	}
	if points == end && startByte >= 0 {
		return startByte, len(text), true
	}
	return 0, 0, false
}

// validSpan is a span on rune boundaries inside text.
func validSpan(text string, s Span) bool {
	return 0 <= s.Start && s.Start < s.End && s.End <= len(text) && utf8.RuneStart(text[s.Start]) &&
		(s.End == len(text) || utf8.RuneStart(text[s.End]))
}
