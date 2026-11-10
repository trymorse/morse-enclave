package privacyveil

import (
	"context"
	"errors"
)

// A Filter finds personal details in text. Redact's spans are at byte offsets into the text it was given.
type Filter interface {
	Redact(ctx context.Context, text string) (Redaction, error)
}

// Redaction is what one filter call found, and what it bills.
type Redaction struct {
	Spans       []LabeledSpan
	Requests    int
	InputTokens int
}

// LabeledSpan is a span the filter found, under its own label.
type LabeledSpan struct {
	Start, End int
	Label      string
}

// Usage is what a scan cost: the filter's billable calls and tokens, and how many spans carried a label this
// package does not know, which it veils as PII.
type Usage struct {
	Calls, Tokens, UnknownLabels int
}

var (
	// ErrSpan is a span the filter returned outside its text or off a rune boundary, which fails the scan closed.
	ErrSpan = errors.New("privacyveil: the filter returned a span outside the text it was sent")
	// ErrUnattested is a filter with no verified attestation, which a scan never sends text to.
	ErrUnattested = errors.New("privacyveil: the filter is not attested")
	// ErrMalformed is a filter reply this package cannot read.
	ErrMalformed = errors.New("privacyveil: the filter's reply is malformed")
)

// Scanned is a scan's spans for each segment, the ones fresh from the filter for the cache, and its cost.
type Scanned struct {
	Spans [][]Span
	Fresh map[int][]Span
	Usage Usage
}

// Scan finds the details of segments: cached[i] for a segment the cache held, the filter's for the segments in
// pieces, and the validators' in every one. It stops at the first piece that fails, and the scan then fails whole:
// no piece is skipped.
func Scan(ctx context.Context, f Filter, segments []Segment, cached map[int][]Span, pieces []Piece) (Scanned, error) {
	s := Scanned{Spans: make([][]Span, len(segments)), Fresh: map[int][]Span{}}
	for _, p := range pieces {
		for _, part := range p.parts {
			s.Fresh[part.segment] = s.Fresh[part.segment][:0:0]
		}
	}
	for _, p := range pieces {
		r, err := f.Redact(ctx, p.Text)
		if err != nil {
			return s, err
		}
		s.Usage.Calls += r.Requests
		s.Usage.Tokens += r.InputTokens
		found := make([]Span, 0, len(r.Spans))
		for _, ls := range r.Spans {
			t, known := TypeOfLabel(ls.Label)
			if !known {
				s.Usage.UnknownLabels++
			}
			span := Span{Start: ls.Start, End: ls.End, Type: t}
			if !validSpan(p.Text, span) {
				return s, ErrSpan
			}
			found = append(found, span)
		}
		for i, spans := range p.segments(found) {
			s.Fresh[i] = append(s.Fresh[i], spans...)
		}
	}
	for i, seg := range segments {
		filtered, hit := cached[i]
		if !hit {
			filtered = s.Fresh[i]
		}
		s.Spans[i] = merge(filtered, Validated(seg.Text))
	}
	return s, nil
}
