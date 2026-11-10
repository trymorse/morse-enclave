package privacyveil

import (
	"cmp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A matcher finds the values of a veil in text: names, addresses, emails and URLs in any case, numbers in any
// punctuation, and anything else byte for byte, each where it stands as its own word.
type matcher struct {
	folded, exact *automaton
	digits        *digitTrie
}

type match struct{ start, end, entity int }

type key struct {
	text   string
	how    keying
	entity int
}

func newMatcher(keys []key) *matcher {
	m := &matcher{folded: &automaton{}, exact: &automaton{}, digits: &digitTrie{}}
	for _, k := range keys {
		switch {
		case k.text == "":
		case k.how == byFold:
			m.folded.add(k.text, k.entity)
		case k.how == byDigits:
			m.digits.add(k.text, k.entity)
		default:
			m.exact.add(k.text, k.entity)
		}
	}
	m.folded.build()
	m.exact.build()
	return m
}

// find is every match in text, longest first where two overlap, in order.
func (m *matcher) find(text string) []match {
	var found []match
	folded, at := foldWithOffsets(text)
	for _, h := range m.folded.search(folded) {
		found = appendBounded(found, text, match{start: at[h.start], end: at[h.end], entity: h.entity})
	}
	for _, h := range m.exact.search([]byte(text)) {
		found = appendBounded(found, text, h)
	}
	found = append(found, m.digits.search(text)...)
	return choose(found)
}

// appendBounded keeps a match only where its value stands as its own word.
func appendBounded(found []match, text string, h match) []match {
	first, _ := utf8.DecodeRuneInString(text[h.start:])
	last, _ := utf8.DecodeLastRuneInString(text[:h.end])
	if before, _ := utf8.DecodeLastRuneInString(text[:h.start]); h.start > 0 && wordRune(first) && wordRune(before) {
		return found
	}
	if after, _ := utf8.DecodeRuneInString(text[h.end:]); h.end < len(text) && wordRune(last) && wordRune(after) {
		return found
	}
	return append(found, h)
}

func wordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
}

// choose keeps the longest of overlapping matches, and returns them in order.
func choose(found []match) []match {
	slices.SortFunc(found, func(a, b match) int {
		return cmp.Or(cmp.Compare(b.end-b.start, a.end-a.start), cmp.Compare(a.start, b.start), cmp.Compare(a.entity, b.entity))
	})
	var kept []match
	for _, h := range found {
		i, _ := slices.BinarySearchFunc(kept, h.start, func(k match, start int) int { return cmp.Compare(k.start, start) })
		if i > 0 && kept[i-1].end > h.start || i < len(kept) && kept[i].start < h.end {
			continue
		}
		kept = slices.Insert(kept, i, h)
	}
	return kept
}

// foldWithOffsets lowers text rune by rune, and maps each byte of the result to the start of the rune it came from,
// with one more entry for the end.
func foldWithOffsets(text string) ([]byte, []int) {
	folded := make([]byte, 0, len(text))
	at := make([]int, 0, len(text)+1)
	for i, r := range text {
		before := len(folded)
		folded = utf8.AppendRune(folded, unicode.ToLower(r))
		for range len(folded) - before {
			at = append(at, i)
		}
	}
	return folded, append(at, len(text))
}

// An automaton is Aho-Corasick over bytes.
type automaton struct {
	next []map[byte]int32
	fail []int32
	out  [][]int32
	keys []string
	ids  []int
}

func (a *automaton) add(text string, entity int) {
	if len(a.next) == 0 {
		a.next, a.out = []map[byte]int32{{}}, [][]int32{nil}
	}
	s := int32(0)
	for i := 0; i < len(text); i++ {
		t, ok := a.next[s][text[i]]
		if !ok {
			t = int32(len(a.next))
			a.next[s][text[i]] = t
			a.next, a.out = append(a.next, map[byte]int32{}), append(a.out, nil)
		}
		s = t
	}
	a.out[s] = append(a.out[s], int32(len(a.keys)))
	a.keys, a.ids = append(a.keys, text), append(a.ids, entity)
}

func (a *automaton) build() {
	if len(a.next) == 0 {
		return
	}
	a.fail = make([]int32, len(a.next))
	queue := make([]int32, 0, len(a.next))
	for _, t := range a.next[0] {
		queue = append(queue, t)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for b, t := range a.next[s] {
			queue = append(queue, t)
			f := a.fail[s]
			for {
				if g, ok := a.next[f][b]; ok && g != t {
					a.fail[t] = g
					break
				}
				if f == 0 {
					break
				}
				f = a.fail[f]
			}
			a.out[t] = append(a.out[t], a.out[a.fail[t]]...)
		}
	}
}

func (a *automaton) search(text []byte) []match {
	if len(a.next) == 0 {
		return nil
	}
	var found []match
	s := int32(0)
	for i, b := range text {
		for {
			if t, ok := a.next[s][b]; ok {
				s = t
				break
			}
			if s == 0 {
				break
			}
			s = a.fail[s]
		}
		for _, k := range a.out[s] {
			found = append(found, match{start: i + 1 - len(a.keys[k]), end: i + 1, entity: a.ids[k]})
		}
	}
	return found
}

// separators may stand between the digits of a number, at most maxSeparators in a row.
const (
	separators    = " -.()/+"
	maxSeparators = 3
)

type digitTrie struct {
	next   [10]*digitTrie
	entity int
	ends   bool
}

func (t *digitTrie) add(digits string, entity int) {
	n := t
	for i := 0; i < len(digits); i++ {
		d := digits[i] - '0'
		if n.next[d] == nil {
			n.next[d] = &digitTrie{}
		}
		n = n.next[d]
	}
	if !n.ends {
		n.ends, n.entity = true, entity
	}
}

// search finds each number whose digits are a value's, from a digit no digit stands before to one no digit follows,
// whatever punctuation stands between them.
func (t *digitTrie) search(text string) []match {
	var found []match
	for start := 0; start < len(text); start++ {
		if !isDigit(rune(text[start])) || start > 0 && isDigit(rune(text[start-1])) {
			continue
		}
		n, run, best := t, 0, match{start: -1}
		for i := start; i < len(text); i++ {
			c := text[i]
			if isDigit(rune(c)) {
				if n = n.next[c-'0']; n == nil {
					break
				}
				run = 0
				if n.ends && (i+1 == len(text) || !isDigit(rune(text[i+1]))) {
					best = match{start: start, end: i + 1, entity: n.entity}
				}
				continue
			}
			if run++; run > maxSeparators || !isSeparator(c) {
				break
			}
		}
		if best.start >= 0 {
			if best.start > 0 && text[best.start-1] == '(' && strings.Contains(text[best.start:best.end], ")") {
				best.start--
			}
			found = append(found, best)
		}
	}
	return found
}

func isSeparator(c byte) bool {
	for i := 0; i < len(separators); i++ {
		if separators[i] == c {
			return true
		}
	}
	return false
}
