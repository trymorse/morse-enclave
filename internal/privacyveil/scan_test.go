package privacyveil

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpreadLeavesShortTextWholeAndCutsLongTextIntoAboutWindowsPieces(t *testing.T) {
	all := func(int) bool { return true }
	short := []Segment{{Text: strings.Repeat("word ", 3<<10)}}
	whole := Plan(short, all)
	if got := Spread(short, all, whole); len(got) != 1 || got[0].Text != whole[0].Text {
		t.Errorf("15 KiB spread into %d pieces, want it whole", len(got))
	}
	one := []Segment{{Text: strings.Repeat("word ", 32<<10/5)}}
	if got := Spread(one, all, Plan(one, all)); len(got) != Windows {
		t.Errorf("one 32 KiB segment spread into %d pieces, want %d", len(got), Windows)
	}
	long := []Segment{{Text: strings.Repeat("word ", 32<<10/5)}, {Text: "Ann"}, {Text: strings.Repeat("more ", 4<<10)}}
	pieces := Spread(long, all, Plan(long, all))
	if len(pieces) != Windows {
		t.Fatalf("52 KiB in three segments spread into %d pieces, want %d", len(pieces), Windows)
	}
	turns := []Segment{}
	for range 6 {
		turns = append(turns, Segment{Text: strings.Repeat("ask ", 900/4)}, Segment{Text: strings.Repeat("told ", 5800/5)})
	}
	if got := Spread(turns, all, Plan(turns, all)); len(got) != Windows {
		t.Errorf("six turns of 6.7 KiB spread into %d pieces, want %d", len(got), Windows)
	}
	covered := map[int][]bool{}
	for i, seg := range long {
		covered[i] = make([]bool, len(seg.Text))
	}
	for _, p := range pieces {
		for _, part := range p.parts {
			if p.Text[part.at:part.at+part.length] != long[part.segment].Text[part.from:part.from+part.length] {
				t.Fatalf("a part's text is not its segment's")
			}
			for b := part.from; b < part.from+part.length; b++ {
				covered[part.segment][b] = true
			}
		}
	}
	for i, bytes := range covered {
		for b, ok := range bytes {
			if !ok {
				t.Fatalf("segment %d byte %d is in no piece", i, b)
			}
		}
	}
}

type slowFirst struct {
	inFlight, most atomic.Int32
	find           string
}

func (f *slowFirst) Redact(ctx context.Context, text string) (Redaction, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.most.Load()
		if n <= m || f.most.CompareAndSwap(m, n) {
			break
		}
	}
	delay := 40*time.Millisecond - time.Duration(len(text)%7)*5*time.Millisecond
	if strings.HasPrefix(text, "first") {
		delay = 60 * time.Millisecond
	}
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return Redaction{}, ctx.Err()
	}
	r := Redaction{Requests: 1, InputTokens: len(text)}
	for at := 0; ; {
		i := strings.Index(text[at:], f.find)
		if i < 0 {
			return r, nil
		}
		r.Spans = append(r.Spans, LabeledSpan{Start: at + i, End: at + i + len(f.find), Label: "private_person"})
		at += i + len(f.find)
	}
}

func TestAScanInWindowsFindsWhatOneCallAtATimeFindsWithAtMostWindowsInFlight(t *testing.T) {
	var segments []Segment
	for i := range 12 {
		segments = append(segments, Segment{Text: strings.Repeat("x", 28<<10+i*97) + " Jane Doe " + strings.Repeat("y", 2<<10)})
	}
	segments[0].Text = "first " + segments[0].Text
	all := func(int) bool { return true }
	pieces := Spread(segments, all, Plan(segments, all))
	if len(pieces) <= Windows {
		t.Fatalf("%d pieces, want more than %d to run in waves", len(pieces), Windows)
	}
	f := &slowFirst{find: "Jane Doe"}
	got, err := Scan(context.Background(), f, nil, Windows, segments, nil, pieces)
	if err != nil {
		t.Fatal(err)
	}
	if m := f.most.Load(); m != Windows {
		t.Errorf("%d calls in flight at most, want %d", m, Windows)
	}
	one := &slowFirst{find: "Jane Doe"}
	want, err := Scan(context.Background(), one, NewLanes(1), Windows, segments, nil, pieces)
	if err != nil {
		t.Fatal(err)
	}
	if one.most.Load() != 1 {
		t.Errorf("one lane let %d calls fly", one.most.Load())
	}
	if got.Usage != want.Usage || got.Usage.Calls != len(pieces) {
		t.Errorf("usage %+v, one at a time %+v", got.Usage, want.Usage)
	}
	for i, seg := range segments {
		at := strings.Index(seg.Text, "Jane Doe")
		if len(got.Fresh[i]) != 1 || got.Fresh[i][0] != (Span{Start: at, End: at + len("Jane Doe"), Type: Name}) {
			t.Errorf("segment %d: %+v", i, got.Fresh[i])
		}
		if !equalSpans(got.Fresh[i], want.Fresh[i]) || !equalSpans(got.Spans[i], want.Spans[i]) {
			t.Errorf("segment %d: %+v in windows, %+v one at a time", i, got.Spans[i], want.Spans[i])
		}
	}
}

func equalSpans(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTheLanesCapCallsAcrossEveryScan(t *testing.T) {
	f := &slowFirst{find: "Ann"}
	lanes := NewLanes(3)
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			segments := []Segment{{Text: strings.Repeat("Ann ", 9<<10)}}
			all := func(int) bool { return true }
			if _, err := Scan(context.Background(), f, lanes, Windows, segments, nil, Spread(segments, all, Plan(segments, all))); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if m := f.most.Load(); m != 3 {
		t.Errorf("%d calls in flight across five scans, want the cap of 3", m)
	}
}

type failsOne struct {
	answered, held, stopped atomic.Int32
}

func (f *failsOne) Redact(ctx context.Context, text string) (Redaction, error) {
	switch {
	case strings.Contains(text, "bad"):
		for f.answered.Load() < 1 || f.held.Load() < 2 {
			time.Sleep(time.Millisecond)
		}
		return Redaction{}, errUnreachable
	case strings.Contains(text, "quick"):
		f.answered.Add(1)
		return Redaction{Requests: 1, InputTokens: 7}, nil
	}
	f.held.Add(1)
	<-ctx.Done()
	f.stopped.Add(1)
	return Redaction{}, ctx.Err()
}

var errUnreachable = errors.New("the filter answered 502")

func TestTheFirstPieceToFailFailsTheScanAndStopsTheRest(t *testing.T) {
	segments := []Segment{
		{Text: "quick " + strings.Repeat("a", 12<<10)}, {Text: strings.Repeat("b", 12<<10)},
		{Text: "bad " + strings.Repeat("c", 12<<10)}, {Text: strings.Repeat("d", 12<<10)},
	}
	all := func(int) bool { return true }
	pieces := Spread(segments, all, Plan(segments, all))
	if len(pieces) != 4 {
		t.Fatalf("%d pieces, want 4", len(pieces))
	}
	f := &failsOne{}
	s, err := Scan(context.Background(), f, nil, Windows, segments, nil, pieces)
	if !errors.Is(err, errUnreachable) {
		t.Fatalf("the scan failed with %v, want the failing piece's error", err)
	}
	if f.stopped.Load() != 2 {
		t.Errorf("%d held calls were stopped, want 2", f.stopped.Load())
	}
	if s.Usage.Calls != 1 || s.Usage.Tokens != 7 {
		t.Errorf("usage %+v, want the one call that answered", s.Usage)
	}
}

func TestACallWaitingForALaneEndsWithItsScansDeadline(t *testing.T) {
	lanes := NewLanes(1)
	if err := lanes.take(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	f := &slowFirst{}
	segments := []Segment{{Text: "Ann"}}
	_, err := Scan(ctx, f, lanes, Windows, segments, nil, Plan(segments, func(int) bool { return true }))
	if !errors.Is(err, context.DeadlineExceeded) || f.most.Load() != 0 {
		t.Errorf("a scan with no free lane: %v, %d calls made", err, f.most.Load())
	}
}
