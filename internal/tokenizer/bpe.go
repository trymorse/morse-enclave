package tokenizer

import (
	"bufio"
	"bytes"
	"cmp"
	"container/heap"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

type merge struct{ rank, id int }

type addedSet map[byte][]string

func (a addedSet) add(s string) {
	b := append(a[s[0]], s)
	sort.SliceStable(b, func(i, j int) bool { return len(b[i]) > len(b[j]) })
	a[s[0]] = b
}

type Tokenizer struct {
	splits []*regexp2.Regexp

	vocab        map[string]int
	merges       map[uint64]merge
	ignoreMerges bool

	ranks map[string]int

	specialAdded    addedSet
	normalizedAdded addedSet
	addedIDs        map[string]int
}

func (t *Tokenizer) Count(ctx context.Context, s string) (int, error) {
	n := 0
	err := t.encode(ctx, s, func(int) { n++ })
	return n, err
}

func (t *Tokenizer) LongestToken() int {
	longest := 0
	for s := range t.vocab {
		if raw, err := fromByteLevel(s); err == nil {
			s = raw
		}
		longest = max(longest, len(s))
	}
	for s := range t.ranks {
		longest = max(longest, len(s))
	}
	return longest
}

func (t *Tokenizer) encode(ctx context.Context, s string, emit func(int)) (err error) {
	t.splitAdded(s, t.specialAdded, emit, func(gap string) {
		t.splitAdded(gap, t.normalizedAdded, emit, func(gap string) {
			t.pretokenize(ctx, gap, 0, func(piece string) {
				if err == nil {
					err = t.bpe(ctx, piece, emit)
				}
			})
		})
	})
	return cmp.Or(err, ctx.Err())
}

func (t *Tokenizer) splitAdded(s string, added addedSet, emit func(int), rest func(string)) {
	if len(added) == 0 {
		rest(s)
		return
	}
	start := 0
	for i := 0; i < len(s); {
		m := ""
		for _, a := range added[s[i]] {
			if strings.HasPrefix(s[i:], a) {
				m = a
				break
			}
		}
		if m == "" {
			i++
			continue
		}
		if i > start {
			rest(s[start:i])
		}
		emit(t.addedIDs[m])
		i += len(m)
		start = i
	}
	if start < len(s) {
		rest(s[start:])
	}
}

func (t *Tokenizer) pretokenize(ctx context.Context, s string, stage int, emit func(string)) {
	if s == "" || ctx.Err() != nil {
		return
	}
	if stage == len(t.splits) {
		emit(s)
		return
	}
	runes := []rune(s)
	// regexp2 reports rune offsets; walk byte offsets alongside.
	prevRune, prevByte := 0, 0
	byteAt := func(r int) int {
		for prevRune < r {
			_, w := utf8.DecodeRuneInString(s[prevByte:])
			prevByte += w
			prevRune++
		}
		return prevByte
	}
	last := 0
	m, _ := t.splits[stage].FindRunesMatch(runes)
	for matches := 0; m != nil; matches++ {
		if matches%cancelPoll == 0 && ctx.Err() != nil {
			return
		}
		if m.Length > 0 {
			b0 := byteAt(m.Index)
			b1 := byteAt(m.Index + m.Length)
			if b0 > last {
				t.pretokenize(ctx, s[last:b0], stage+1, emit)
			}
			t.pretokenize(ctx, s[b0:b1], stage+1, emit)
			last = b1
		}
		m, _ = t.splits[stage].FindNextMatch(m)
	}
	if last < len(s) {
		t.pretokenize(ctx, s[last:], stage+1, emit)
	}
}

func (t *Tokenizer) bpe(ctx context.Context, piece string, emit func(int)) error {
	if t.ranks != nil {
		return t.bpeTiktoken(ctx, piece, emit)
	}
	if t.ignoreMerges {
		if id, ok := t.vocab[piece]; ok {
			emit(id)
			return nil
		}
	}
	syms := make([]int, len(piece))
	for i := 0; i < len(piece); i++ {
		syms[i] = t.vocab[piece[i:i+1]]
	}
	pairOf := func(a, b int) (merge, bool) {
		m, ok := t.merges[uint64(syms[a])<<32|uint64(syms[b])]
		return m, ok
	}
	m := newMerger(len(piece), func(a, b, _ int) (int, bool) {
		m, ok := pairOf(a, b)
		return m.rank, ok
	})
	err := m.run(ctx, func(a, b int) {
		m, _ := pairOf(a, b)
		syms[a] = m.id
	})
	if err != nil {
		return err
	}
	for i := 0; i >= 0; i = m.next[i] {
		emit(syms[i])
	}
	return nil
}

// bpeTiktoken mirrors tiktoken's byte_pair_merge: repeatedly merge the
// adjacent pair whose concatenation has the lowest rank, leftmost on ties.
func (t *Tokenizer) bpeTiktoken(ctx context.Context, piece string, emit func(int)) error {
	if r, ok := t.ranks[piece]; ok {
		emit(r)
		return nil
	}
	m := newMerger(len(piece), func(a, _, end int) (int, bool) {
		r, ok := t.ranks[piece[a:end]]
		return r, ok
	})
	if err := m.run(ctx, func(int, int) {}); err != nil {
		return err
	}
	for i := 0; i >= 0; i = m.next[i] {
		emit(t.ranks[piece[i:m.end(i)]])
	}
	return nil
}

const (
	listEnd    = -1
	mergedAway = -2
	cancelPoll = 1 << 12
)

// merger keeps the symbols of one piece as a doubly linked list over their starting byte offsets
// and the mergeable adjacent pairs in a min-heap by rank, then position, so a merge costs one pop
// and two pushes instead of a rescan of the piece. Entries go stale when a neighbour merges; a
// popped entry is applied only if the pair now at that position still has its rank.
type merger struct {
	next, prev []int
	heap       pairHeap
	rank       func(a, b, end int) (int, bool)
}

type pair struct{ rank, at int }

type pairHeap []pair

func (h pairHeap) Len() int { return len(h) }
func (h pairHeap) Less(i, j int) bool {
	return h[i].rank < h[j].rank || h[i].rank == h[j].rank && h[i].at < h[j].at
}
func (h pairHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *pairHeap) Push(x any)   { *h = append(*h, x.(pair)) }
func (h *pairHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func newMerger(n int, rank func(a, b, end int) (int, bool)) *merger {
	m := &merger{next: make([]int, n), prev: make([]int, n), rank: rank, heap: make(pairHeap, 0, n)}
	for i := range n {
		m.next[i], m.prev[i] = i+1, i-1
	}
	m.next[n-1] = listEnd
	for i := range n {
		m.push(i)
	}
	return m
}

func (m *merger) end(b int) int {
	if m.next[b] >= 0 {
		return m.next[b]
	}
	return len(m.next)
}

func (m *merger) push(a int) {
	if b := m.next[a]; b >= 0 {
		if r, ok := m.rank(a, b, m.end(b)); ok {
			heap.Push(&m.heap, pair{r, a})
		}
	}
}

func (m *merger) run(ctx context.Context, merged func(a, b int)) error {
	for pops := 0; m.heap.Len() > 0; pops++ {
		if pops%cancelPoll == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		p := heap.Pop(&m.heap).(pair)
		a, b := p.at, m.next[p.at]
		if b < 0 {
			continue
		}
		if r, ok := m.rank(a, b, m.end(b)); !ok || r != p.rank {
			continue
		}
		merged(a, b)
		c := m.next[b]
		m.next[a] = c
		if c >= 0 {
			m.prev[c] = a
		}
		m.next[b] = mergedAway
		if m.prev[a] >= 0 {
			m.push(m.prev[a])
		}
		m.push(a)
	}
	return nil
}

var byteLevelDecoder = func() map[rune]byte {
	d := map[rune]byte{}
	n := 0
	for b := 0; b < 256; b++ {
		if (b >= '!' && b <= '~') || (b >= 0xA1 && b <= 0xAC) || (b >= 0xAE && b <= 0xFF) {
			d[rune(b)] = byte(b)
		} else {
			d[rune(256+n)] = byte(b)
			n++
		}
	}
	return d
}()

func fromByteLevel(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		c, ok := byteLevelDecoder[r]
		if !ok {
			return "", fmt.Errorf("token %q has a rune outside the byte-level alphabet", s)
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

type hfFile struct {
	Normalizer *struct {
		Type        string            `json:"type"`
		Normalizers []json.RawMessage `json:"normalizers"`
	} `json:"normalizer"`
	PreTokenizer struct {
		Type          string `json:"type"`
		PreTokenizers []struct {
			Type    string `json:"type"`
			Pattern struct {
				Regex *string `json:"Regex"`
			} `json:"pattern"`
			Behavior       string `json:"behavior"`
			Invert         bool   `json:"invert"`
			AddPrefixSpace bool   `json:"add_prefix_space"`
			UseRegex       bool   `json:"use_regex"`
		} `json:"pretokenizers"`
	} `json:"pre_tokenizer"`
	Model struct {
		Type                    string          `json:"type"`
		Dropout                 *float64        `json:"dropout"`
		ContinuingSubwordPrefix *string         `json:"continuing_subword_prefix"`
		EndOfWordSuffix         *string         `json:"end_of_word_suffix"`
		ByteFallback            bool            `json:"byte_fallback"`
		IgnoreMerges            bool            `json:"ignore_merges"`
		Vocab                   map[string]int  `json:"vocab"`
		Merges                  json.RawMessage `json:"merges"`
	} `json:"model"`
	AddedTokens []struct {
		ID         int    `json:"id"`
		Content    string `json:"content"`
		SingleWord bool   `json:"single_word"`
		Lstrip     bool   `json:"lstrip"`
		Rstrip     bool   `json:"rstrip"`
		Normalized bool   `json:"normalized"`
	} `json:"added_tokens"`
}

func loadHF(data []byte) (*Tokenizer, error) {
	var f hfFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Normalizer != nil && !(f.Normalizer.Type == "Sequence" && len(f.Normalizer.Normalizers) == 0) {
		return nil, fmt.Errorf("unsupported normalizer %q", f.Normalizer.Type)
	}
	if f.PreTokenizer.Type != "Sequence" {
		return nil, fmt.Errorf("unsupported pre_tokenizer %q", f.PreTokenizer.Type)
	}
	t := &Tokenizer{addedIDs: map[string]int{}, specialAdded: addedSet{}, normalizedAdded: addedSet{}}
	pts := f.PreTokenizer.PreTokenizers
	if len(pts) == 0 || pts[len(pts)-1].Type != "ByteLevel" || pts[len(pts)-1].AddPrefixSpace || pts[len(pts)-1].UseRegex {
		return nil, fmt.Errorf("pre_tokenizer must end in ByteLevel(add_prefix_space=false, use_regex=false)")
	}
	for _, p := range pts[:len(pts)-1] {
		if p.Type != "Split" || p.Pattern.Regex == nil || p.Behavior != "Isolated" || p.Invert {
			return nil, fmt.Errorf("unsupported pre_tokenizer stage %+v", p)
		}
		re, err := regexp2.Compile(*p.Pattern.Regex, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("split regex: %w", err)
		}
		t.splits = append(t.splits, re)
	}
	m := f.Model
	if m.Type != "BPE" || m.Dropout != nil || m.ContinuingSubwordPrefix != nil || m.EndOfWordSuffix != nil || m.ByteFallback {
		return nil, fmt.Errorf("unsupported model settings")
	}
	t.ignoreMerges = m.IgnoreMerges
	t.vocab = make(map[string]int, len(m.Vocab))
	isAdded := map[string]bool{}
	for _, a := range f.AddedTokens {
		isAdded[a.Content] = true
	}
	for k, id := range m.Vocab {
		raw, err := fromByteLevel(k)
		if err != nil {
			if isAdded[k] {
				continue
			}
			return nil, err
		}
		t.vocab[raw] = id
	}
	for b := 0; b < 256; b++ {
		if _, ok := t.vocab[string([]byte{byte(b)})]; !ok {
			return nil, fmt.Errorf("vocab lacks byte %#x", b)
		}
	}
	var pairs [][2]string
	var strs []string
	if err := json.Unmarshal(m.Merges, &strs); err == nil {
		pairs = make([][2]string, len(strs))
		for i, s := range strs {
			a, b, ok := strings.Cut(s, " ")
			if !ok {
				return nil, fmt.Errorf("merge %q", s)
			}
			pairs[i] = [2]string{a, b}
		}
	} else if err := json.Unmarshal(m.Merges, &pairs); err != nil {
		return nil, fmt.Errorf("merges: %w", err)
	}
	t.merges = make(map[uint64]merge, len(pairs))
	for rank, p := range pairs {
		a, ok1 := m.Vocab[p[0]]
		b, ok2 := m.Vocab[p[1]]
		id, ok3 := m.Vocab[p[0]+p[1]]
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("merge %d %q references unknown tokens", rank, p)
		}
		k := uint64(a)<<32 | uint64(b)
		if _, dup := t.merges[k]; !dup {
			t.merges[k] = merge{rank, id}
		}
	}
	for _, a := range f.AddedTokens {
		if a.SingleWord || a.Lstrip || a.Rstrip {
			return nil, fmt.Errorf("added token %q uses unsupported flags", a.Content)
		}
		t.addedIDs[a.Content] = a.ID
		if a.Normalized {
			t.normalizedAdded.add(a.Content)
		} else {
			t.specialAdded.add(a.Content)
		}
	}
	return t, nil
}

// Python-style `[A&&[^B]]` class intersections are rewritten to .NET subtraction `[A-[B]]` for regexp2.
func loadTiktoken(data []byte, pattern string) (*Tokenizer, error) {
	pattern = strings.ReplaceAll(pattern, "&&[^", "-[")
	re, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("pattern: %w", err)
	}
	t := &Tokenizer{splits: []*regexp2.Regexp{re}, ranks: map[string]int{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		tokB64, rankStr, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		tok, err := base64.StdEncoding.DecodeString(tokB64)
		if err != nil {
			return nil, err
		}
		r, err := strconv.Atoi(rankStr)
		if err != nil {
			return nil, err
		}
		t.ranks[string(tok)] = r
	}
	return t, sc.Err()
}

var kimiPattern = strings.Join([]string{
	`[\p{Han}]+`,
	`[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?`,
	`[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?`,
	`\p{N}{1,3}`,
	` ?[^\s\p{L}\p{N}]+[\r\n]*`,
	`\s*[\r\n]+`,
	`\s+(?!\S)`,
	`\s+`,
}, "|")
