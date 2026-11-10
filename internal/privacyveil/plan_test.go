package privacyveil

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlanJoinsSegmentsIntoPiecesNoLargerThanAPiece(t *testing.T) {
	segments := []Segment{{Text: strings.Repeat("a", 40<<10)}, {Text: strings.Repeat("b", 40<<10)}, {Text: "c"}, {Text: ""}}
	pieces := Plan(segments, func(int) bool { return true })
	if len(pieces) != 2 {
		t.Fatalf("%d pieces, want 2: two 40 KiB segments do not fit one", len(pieces))
	}
	for _, p := range pieces {
		if len(p.Text) > MaxPiece {
			t.Errorf("a piece of %d bytes", len(p.Text))
		}
	}
	if !strings.HasSuffix(pieces[1].Text, joint+"c") {
		t.Errorf("the short segment should join the second piece")
	}
	if got := Bytes(pieces); got != 80<<10+len(joint)+1 {
		t.Errorf("Bytes = %d", got)
	}
}

func TestPlanSkipsTheSegmentsItIsToldNeedNoScan(t *testing.T) {
	pieces := Plan([]Segment{{Text: "one"}, {Text: "two"}}, func(i int) bool { return i == 1 })
	if len(pieces) != 1 || pieces[0].Text != "two" {
		t.Errorf("pieces %+v", pieces)
	}
}

func TestALongSegmentIsCutIntoOverlappingWindows(t *testing.T) {
	text := strings.Repeat("word ", 40<<10)
	pieces := Plan([]Segment{{Text: text}}, func(int) bool { return true })
	covered := make([]bool, len(text))
	for _, p := range pieces {
		for _, part := range p.parts {
			for i := part.from; i < part.from+part.length; i++ {
				covered[i] = true
			}
			if got := p.Text[part.at : part.at+part.length]; got != text[part.from:part.from+part.length] {
				t.Fatal("a window's text is not the segment's")
			}
		}
	}
	for i, c := range covered {
		if !c {
			t.Fatalf("byte %d of the segment is in no window", i)
		}
	}
}

func TestASpanThatCrossesAJointIsCutToEachSegment(t *testing.T) {
	pieces := Plan([]Segment{{Text: "ends Ann"}, {Text: "Lee starts"}}, func(int) bool { return true })
	by := pieces[0].segments([]Span{{Start: 5, End: 13, Type: Name}})
	if got := by[0]; len(got) != 1 || got[0] != (Span{Start: 5, End: 8, Type: Name}) {
		t.Errorf("segment 0: %+v", got)
	}
	if got := by[1]; len(got) != 1 || got[0] != (Span{Start: 0, End: 3, Type: Name}) {
		t.Errorf("segment 1: %+v", got)
	}
}

type fakeFilter struct {
	calls []string
	find  map[string]string
	err   error
}

func (f *fakeFilter) Redact(_ context.Context, text string) (Redaction, error) {
	f.calls = append(f.calls, text)
	if f.err != nil {
		return Redaction{}, f.err
	}
	r := Redaction{Requests: 1, InputTokens: len(text) / 4}
	for value, label := range f.find {
		for at := 0; ; {
			i := strings.Index(text[at:], value)
			if i < 0 {
				break
			}
			r.Spans = append(r.Spans, LabeledSpan{Start: at + i, End: at + i + len(value), Label: label})
			at += i + len(value)
		}
	}
	return r, nil
}

func TestScanMapsTheFiltersSpansToTheirSegmentsAndAddsTheValidators(t *testing.T) {
	f := &fakeFilter{find: map[string]string{"Jane Doe": "private_person", "Jane": "private_passport"}}
	segments := []Segment{{Text: "I am Jane Doe"}, {Text: "card 4111 1111 1111 1111"}, {Text: "cached Ann"}}
	cached := map[int][]Span{2: {{Start: 7, End: 10, Type: Name}}}
	pieces := Plan(segments, func(i int) bool { _, hit := cached[i]; return !hit })
	s, err := Scan(context.Background(), f, segments, cached, pieces)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || strings.Contains(f.calls[0], "cached") {
		t.Errorf("the filter was sent %q", f.calls)
	}
	if s.Usage.Calls != 1 || s.Usage.UnknownLabels != 1 {
		t.Errorf("usage %+v", s.Usage)
	}
	v := New(segments, s.Spans)
	if got := v.Substitute("Jane Doe paid with 4111 1111 1111 1111; Ann too"); got != "[NAME_1] paid with [CARD_1]; [NAME_2] too" {
		t.Errorf("got %q", got)
	}
	if _, ok := s.Fresh[2]; ok {
		t.Error("a cached segment is not fresh")
	}
	if _, ok := s.Fresh[0]; !ok {
		t.Error("a scanned segment is fresh, even with no span")
	}
}

func TestScanFailsWholeWhenAnyPieceFailsOrASpanIsOutOfRange(t *testing.T) {
	segments := []Segment{{Text: "Jane Doe"}}
	pieces := Plan(segments, func(int) bool { return true })
	if _, err := Scan(context.Background(), &fakeFilter{err: errors.New("down")}, segments, nil, pieces); err == nil {
		t.Error("a failed call did not fail the scan")
	}
	bad := filterFunc(func(text string) Redaction {
		return Redaction{Spans: []LabeledSpan{{Start: 0, End: len(text) + 5, Label: "private_person"}}}
	})
	if _, err := Scan(context.Background(), bad, segments, nil, pieces); !errors.Is(err, ErrSpan) {
		t.Errorf("a span past the text: %v", err)
	}
}

type filterFunc func(text string) Redaction

func (f filterFunc) Redact(_ context.Context, text string) (Redaction, error) { return f(text), nil }

func TestTheCacheKeepsSpansPerPartitionAndForgetsThem(t *testing.T) {
	now := time.Unix(0, 0)
	c := NewCache(1<<20, time.Hour, func() time.Time { return now })
	partition := []byte("0123456789abcdef")
	spans := []Span{{Start: 0, End: 3, Type: Name}}
	c.Put(SealedPartition, partition, "Ann", spans)
	if got, ok := c.Get(SealedPartition, partition, "Ann"); !ok || len(got) != 1 {
		t.Fatalf("a put was not got back: %v %v", got, ok)
	}
	if _, ok := c.Get(RelayPartition, partition, "Ann"); ok {
		t.Error("the relay's namespace saw a sealed client's entry")
	}
	if _, ok := c.Get(SealedPartition, []byte("another-partition"), "Ann"); ok {
		t.Error("another partition saw the entry")
	}
	short := []byte("short")
	c.Put(SealedPartition, short, "Ann", spans)
	if _, ok := c.Get(SealedPartition, short, "Ann"); ok {
		t.Error("a sealed partition under 16 bytes was cached")
	}
	c.Put(RelayPartition, nil, "Ann", spans)
	if _, ok := c.Get(RelayPartition, nil, "Ann"); ok {
		t.Error("a call with no partition was cached")
	}
	now = now.Add(2 * time.Hour)
	if _, ok := c.Get(SealedPartition, partition, "Ann"); ok {
		t.Error("an entry outlived its TTL")
	}
}

func TestTheCacheEvictsTheLeastRecentlyUsedPastItsCap(t *testing.T) {
	c := NewCache(3*cacheEntryOverhead, time.Hour, time.Now)
	p := []byte("0123456789abcdef")
	for _, text := range []string{"a", "b", "c"} {
		c.Put(SealedPartition, p, text, nil)
	}
	c.Get(SealedPartition, p, "a")
	c.Put(SealedPartition, p, "d", nil)
	if _, ok := c.Get(SealedPartition, p, "b"); ok {
		t.Error("the least recently used entry survived")
	}
	if _, ok := c.Get(SealedPartition, p, "a"); !ok {
		t.Error("a recently used entry was evicted")
	}
}

func TestAskReadsEveryShapeAndRefusesTheRest(t *testing.T) {
	for raw, want := range map[string]Ask{
		``: {}, `null`: {}, `false`: {}, `true`: {On: true}, `{}`: {On: true}, `{"report":true}`: {On: true, Report: true},
		`{"restore":"none"}`: {On: true, Restore: RestoreNone},
	} {
		got, err := ParseAsk(json.RawMessage(raw))
		if err != nil || got.On != want.On || got.Report != want.Report || got.Restore != want.Restore {
			t.Errorf("%s: %+v (%v), want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{`"true"`, `1`, `[]`, `{"reprot":true}`, `{"restore":"all"}`, `{"release":[{"tool":"x","types":["NAMES"]}]}`,
		`{"release":[{"tool":"","types":["NAME"]}]}`, `{"release":[{"tool":"x","types":[]}]}`, `{} {}`} {
		if _, err := ParseAsk(json.RawMessage(raw)); !errors.Is(err, ErrAsk) {
			t.Errorf("%s: %v, want ErrAsk", raw, err)
		}
	}
}

func TestAWildcardGrantNeverReleasesASensitiveType(t *testing.T) {
	ask, err := ParseAsk(json.RawMessage(`{"release":[{"tool":"*","types":["*"]},{"tool":"pay","types":["CARD"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool string
		t    Type
		want bool
	}{{"any", Name, true}, {"any", Email, true}, {"any", SSN, false}, {"any", Secret, false}, {"any", Card, false}, {"pay", Card, true}} {
		if got := ask.Releases(c.tool)(c.t); got != c.want {
			t.Errorf("%s %v: %v, want %v", c.tool, c.t, got, c.want)
		}
	}
}

func TestAReportTooLargeIsCutAndSaysSo(t *testing.T) {
	r := Report{Unveiled: []string{"image_url"}}
	for i := range 2000 {
		r.Entities = append(r.Entities, Entity{Placeholder: "[NAME_1]", Type: Name, Value: strings.Repeat("x", 30) + string(rune('a'+i%26))})
	}
	out := r.JSON()
	var back Report
	if err := json.Unmarshal(out, &back); err != nil || len(out) > MaxReport || !back.Truncated || len(back.Entities) == 0 {
		t.Errorf("%d bytes, truncated %v, %d entities (%v)", len(out), back.Truncated, len(back.Entities), err)
	}
}
