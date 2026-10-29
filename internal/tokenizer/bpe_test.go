package tokenizer

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// referenceEncode is the merge loop the merger replaced: rescan every adjacent pair for the
// lowest rank, leftmost on ties, once per merge. Quadratic in the piece, but the definition of
// the merge order, so the merger is held to its token ids.
func (t *Tokenizer) referenceEncode(s string) []int {
	var ids []int
	emit := func(id int) { ids = append(ids, id) }
	t.splitAdded(s, t.specialAdded, emit, func(gap string) {
		t.splitAdded(gap, t.normalizedAdded, emit, func(gap string) {
			t.pretokenize(context.Background(), gap, 0, func(piece string) { t.referenceBPE(piece, emit) })
		})
	})
	return ids
}

func (t *Tokenizer) referenceBPE(piece string, emit func(int)) {
	if t.ranks != nil {
		if r, ok := t.ranks[piece]; ok {
			emit(r)
			return
		}
		bounds := make([]int, len(piece)+1)
		for i := range bounds {
			bounds[i] = i
		}
		for len(bounds) > 2 {
			best, at := -1, -1
			for i := 0; i+2 < len(bounds); i++ {
				if r, ok := t.ranks[piece[bounds[i]:bounds[i+2]]]; ok && (at < 0 || r < best) {
					best, at = r, i
				}
			}
			if at < 0 {
				break
			}
			bounds = append(bounds[:at+1], bounds[at+2:]...)
		}
		for i := 0; i+1 < len(bounds); i++ {
			emit(t.ranks[piece[bounds[i]:bounds[i+1]]])
		}
		return
	}
	if t.ignoreMerges {
		if id, ok := t.vocab[piece]; ok {
			emit(id)
			return
		}
	}
	syms := make([]int, len(piece))
	for i := 0; i < len(piece); i++ {
		syms[i] = t.vocab[piece[i:i+1]]
	}
	for len(syms) > 1 {
		best, at := merge{rank: -1}, -1
		for i := 0; i+1 < len(syms); i++ {
			if m, ok := t.merges[uint64(syms[i])<<32|uint64(syms[i+1])]; ok && (at < 0 || m.rank < best.rank) {
				best, at = m, i
			}
		}
		if at < 0 {
			break
		}
		syms[at] = best.id
		syms = append(syms[:at+1], syms[at+2:]...)
	}
	for _, id := range syms {
		emit(id)
	}
}

var alphabet = []string{"a", "b", "e", "t", "A", " ", "  ", "\n", ".", "!", "'", "1", "中", "文", "é", "🌊", "<|endoftext|>", "ing", "the"}

func TestTheMergerProducesTheReferenceLoopsTokenIDs(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	texts := slices.Clone(referenceTexts)
	for range 400 {
		var b strings.Builder
		for range rng.IntN(48) {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		texts = append(texts, b.String())
	}
	for _, unit := range []string{"a", "!", " ", "中"} {
		texts = append(texts, strings.Repeat(unit, 2<<10))
	}
	for name := range sources {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tok, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range texts {
				if got, want := tok.tokenIDs(text), tok.referenceEncode(text); !slices.Equal(got, want) {
					t.Errorf("%s encodes %q as %v, the reference loop as %v", name, text, got, want)
				}
			}
		})
	}
}

func cpuTime(t *testing.T) time.Duration {
	var u syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &u); err != nil {
		t.Fatal(err)
	}
	return time.Duration(u.Utime.Nano() + u.Stime.Nano())
}

// The old pair rescan took minutes over 200 KB; the merger takes about 100 ms, or 2 to 3 s under
// the race detector, so the bound is loose and still two orders short of the quadratic cost. The
// bound is on the process's CPU time, since wall time under load passed it. The subtests run one at
// a time so that CPU time is one count's.
func TestALongRunOfOneCharacterIsCountedInLinearTime(t *testing.T) {
	const bound = 10 * time.Second
	for name := range sources {
		t.Run(name, func(t *testing.T) {
			tok, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, unit := range []string{"a", "中"} {
				start := cpuTime(t)
				n, err := tok.Count(context.Background(), strings.Repeat(unit, 200<<10))
				if took := cpuTime(t) - start; err != nil || n == 0 || took > bound {
					t.Errorf("%s counted 200 KB of %q as %d tokens in %v of CPU (%v), want a count within %v", name, unit, n, took, err, bound)
				}
			}
		})
	}
}

func TestACancelledCountStopsAndReportsItsContextError(t *testing.T) {
	tok, err := Load("o200k")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := tok.Count(ctx, strings.Repeat("a", 1<<10)); !errors.Is(err, context.Canceled) || n != 0 {
		t.Errorf("counted %d (%v) under a cancelled context, want 0 and context.Canceled", n, err)
	}
}

func TestACancelledCountOfManyPiecesStopsBeforeSplittingThemAll(t *testing.T) {
	tok, err := Load("o200k")
	if err != nil {
		t.Fatal(err)
	}
	prose := strings.Repeat("the quick brown fox jumps over the lazy dog, ", 8<<20/45)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := tok.Count(ctx, prose); !errors.Is(err, context.Canceled) {
		t.Fatalf("counting under a cancelled context returned %v, want context.Canceled", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("a cancelled count of %d bytes took %v, want it to stop without splitting the whole text", len(prose), took)
	}
}

func (t *Tokenizer) tokenIDs(s string) []int {
	var ids []int
	t.encode(context.Background(), s, func(id int) { ids = append(ids, id) })
	return ids
}
