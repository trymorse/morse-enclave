package privacyveil

import (
	"strings"
	"unicode/utf8"
)

const (
	// MaxPiece is the most text one filter call reads. A token is at least a byte, so a piece never reaches the
	// filter's limit of 80,000 tokens, and its FIFO queue interleaves requests.
	MaxPiece = 64 << 10
	// windowOverlap is how far the windows of a segment longer than a piece overlap, so no detail is cut in two.
	windowOverlap = 2 << 10
	joint         = "\n\n"
	// why: Tinfoil's filter runs four inference processes and one call runs on one, so four calls of a quarter of
	// the text end about when one such call would; each call also costs ~0.4 s whatever its size.
	Windows   = 4
	minWindow = 8 << 10
)

// A Piece is text the filter reads in one call: whole segments, or windows of a long one, joined by blank lines.
type Piece struct {
	Text  string
	parts []placed
}

// placed is a run of one segment's text inside a piece.
type placed struct {
	segment, from, at, length int
}

// Plan cuts the segments that need a scan into pieces of at most MaxPiece bytes, in order. A segment longer than a
// piece is cut into windows that overlap, at a space where it can.
func Plan(segments []Segment, needs func(i int) bool) []Piece {
	return plan(segments, needs, MaxPiece)
}

func Spread(segments []Segment, needs func(i int) bool, whole []Piece) []Piece {
	total := Bytes(whole)
	if total < 2*minWindow {
		return whole
	}
	lo := min(MaxPiece, max(minWindow, (total+Windows-1)/Windows+windowOverlap))
	if pieces := plan(segments, needs, lo); len(pieces) <= Windows || lo == MaxPiece {
		return pieces
	}
	hi, best := MaxPiece, whole
	if len(best) > Windows {
		return best
	}
	for hi-lo > 1<<9 {
		mid := lo + (hi-lo)/2
		if pieces := plan(segments, needs, mid); len(pieces) <= Windows {
			hi, best = mid, pieces
		} else {
			lo = mid
		}
	}
	return best
}

func plan(segments []Segment, needs func(i int) bool, size int) []Piece {
	var pieces []Piece
	var cur Piece
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			cur.Text = text.String()
			pieces = append(pieces, cur)
		}
		cur, text = Piece{}, strings.Builder{}
	}
	for i, seg := range segments {
		if seg.Text == "" || !needs(i) {
			continue
		}
		for _, w := range windows(seg.Text, size) {
			if text.Len() > 0 && text.Len()+len(joint)+(w[1]-w[0]) > size {
				flush()
			}
			if text.Len() > 0 {
				text.WriteString(joint)
			}
			cur.parts = append(cur.parts, placed{segment: i, from: w[0], at: text.Len(), length: w[1] - w[0]})
			text.WriteString(seg.Text[w[0]:w[1]])
		}
	}
	flush()
	return pieces
}

func windows(text string, size int) [][2]int {
	var runs [][2]int
	for start := 0; ; {
		end := start + size
		if end >= len(text) {
			return append(runs, [2]int{start, len(text)})
		}
		end = runeStart(text, end)
		if space := strings.LastIndexAny(text[start+size/2:end], " \n\t"); space >= 0 {
			end = start + size/2 + space + 1
		}
		runs = append(runs, [2]int{start, end})
		start = max(runeStart(text, end-windowOverlap), start+1)
		start = runeStart(text, start)
	}
}

func runeStart(text string, at int) int {
	for at > 0 && at < len(text) && !utf8.RuneStart(text[at]) {
		at--
	}
	return at
}

// Bytes is the text all pieces send, joints included.
func Bytes(pieces []Piece) int {
	n := 0
	for _, p := range pieces {
		n += len(p.Text)
	}
	return n
}

// segments maps spans of the piece's text to the segments they fall in, cutting a span that crosses a joint.
func (p Piece) segments(found []Span) map[int][]Span {
	by := map[int][]Span{}
	for _, s := range found {
		for _, part := range p.parts {
			start, end := max(s.Start, part.at), min(s.End, part.at+part.length)
			if start >= end {
				continue
			}
			by[part.segment] = append(by[part.segment], Span{Start: part.from + start - part.at, End: part.from + end - part.at, Type: s.Type})
		}
	}
	return by
}
