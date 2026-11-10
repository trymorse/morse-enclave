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
		for _, w := range windows(seg.Text) {
			if text.Len() > 0 && text.Len()+len(joint)+(w[1]-w[0]) > MaxPiece {
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

// windows cuts text into runs of at most MaxPiece bytes that overlap by windowOverlap, each ending at a space in
// its second half where there is one, and every one on a rune boundary.
func windows(text string) [][2]int {
	var runs [][2]int
	for start := 0; ; {
		end := start + MaxPiece
		if end >= len(text) {
			return append(runs, [2]int{start, len(text)})
		}
		end = runeStart(text, end)
		if space := strings.LastIndexAny(text[start+MaxPiece/2:end], " \n\t"); space >= 0 {
			end = start + MaxPiece/2 + space + 1
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
