package privacyveil

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// Segment is client text a veil was found in. Literal marks user and system text, whose own placeholders a
// numbering skips.
type Segment struct {
	Text    string
	Literal bool
}

// A Veil maps the details found in one request to placeholders, and back.
type Veil struct {
	entities []entity
	byText   map[string]int
	match    *matcher
}

type entity struct {
	Type        Type
	Placeholder string
	Bare        string
	Value       string
}

// Entity is one detail and its placeholder, as a report lists it.
type Entity struct {
	Placeholder string `json:"placeholder"`
	Type        Type   `json:"type"`
	Value       string `json:"value"`
}

// minPart is the fewest letters a part of a name needs to stand for the name on its own.
const minPart = 3

// stopParts are words too common to stand for a name: a name's part that is one of them is matched only within the
// whole name.
var stopParts = map[string]bool{
	"and": true, "the": true, "for": true, "but": true, "not": true, "von": true, "van": true, "der": true, "den": true,
	"del": true, "della": true, "los": true, "las": true, "mrs": true, "miss": true,
	"january": true, "february": true, "march": true, "april": true, "may": true, "june": true, "july": true,
	"august": true, "september": true, "october": true, "november": true, "december": true, "monday": true,
	"tuesday": true, "wednesday": true, "thursday": true, "friday": true, "saturday": true, "sunday": true,
}

// New maps the details found in segments, spans[i] holding segment i's, to placeholders. Each type's placeholders
// are numbered from 1 in the order the details first appear, skipping any number a user or system segment already
// writes. A name's whole-word parts stand for it, except a part that two names share, which gets its own.
func New(segments []Segment, spans [][]Span) *Veil {
	found := detected(segments, spans)
	taken := map[Type]map[int]bool{}
	for _, seg := range segments {
		if seg.Literal {
			literals(seg.Text, taken)
		}
	}
	v := &Veil{byText: map[string]int{}}
	var keys []key
	index := make([]int, len(found))
	parts, shared := nameParts(found)
	sharedIndex := map[string]int{}
	for i, e := range found {
		if owner, ok := wholePart(e, parts); ok && owner != i {
			index[i] = -1
			continue
		}
		index[i] = len(v.entities)
		v.entities = append(v.entities, e)
		if w, ok := sharedPart(e, shared); ok {
			sharedIndex[w] = index[i]
		}
	}
	for _, w := range shared {
		if _, ok := sharedIndex[w]; !ok {
			sharedIndex[w] = len(v.entities)
			v.entities = append(v.entities, entity{Type: Name, Value: w})
		}
	}
	for i, e := range found {
		target := index[i]
		if target < 0 {
			owner, _ := wholePart(e, parts)
			target = index[owner]
		}
		keys = append(keys, key{text: e.Type.key(e.Value), how: e.Type.keying(), entity: target})
		for _, form := range urlForms(e) {
			keys = append(keys, key{text: e.Type.key(form), how: e.Type.keying(), entity: target})
		}
	}
	for _, w := range slices.Sorted(maps.Keys(parts)) {
		keys = append(keys, key{text: w, how: byBytes, entity: index[parts[w]]})
	}
	for _, w := range shared {
		keys = append(keys, key{text: w, how: byBytes, entity: sharedIndex[w]})
	}
	next := map[Type]int{}
	for i := range v.entities {
		e := &v.entities[i]
		n := next[e.Type] + 1
		for taken[e.Type][n] {
			n++
		}
		next[e.Type] = n
		e.Placeholder, e.Bare = placeholder(e.Type, n), bare(e.Type, n)
		v.byText[e.Placeholder], v.byText[e.Bare] = i, i
	}
	v.match = newMatcher(keys)
	return v
}

// urlForms are the ways a link writes a detail that holds a character it escapes: a query's, with + for each space,
// and a path's, with %20, so a detail inside a link is veiled, and checked for, as it is in prose. Only details matched
// case-folded have them; a digit's separators are matched already.
func urlForms(e entity) []string {
	if e.Type.keying() != byFold {
		return nil
	}
	var forms []string
	for _, f := range []string{url.QueryEscape(e.Value), url.PathEscape(e.Value)} {
		if f != e.Value && !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	return forms
}

// detected is each distinct detail in the spans, in the order it first appears, keyed as its type keys it.
func detected(segments []Segment, spans [][]Span) []entity {
	var found []entity
	seen := map[string]bool{}
	for i, seg := range segments {
		if i >= len(spans) {
			break
		}
		list := slices.Clone(spans[i])
		slices.SortStableFunc(list, func(a, b Span) int { return a.Start - b.Start })
		for _, s := range list {
			if !validSpan(seg.Text, s) {
				continue
			}
			surface := strings.TrimSpace(seg.Text[s.Start:s.End])
			k := s.Type.key(surface)
			id := fmt.Sprint(s.Type.keying(), ":", k)
			if k == "" || seen[id] {
				continue
			}
			seen[id] = true
			found = append(found, entity{Type: s.Type, Value: surface})
		}
	}
	return found
}

// nameParts finds the whole-word parts of each name of more than one word: those that one name alone has, mapped to
// its index, and those that two or more share, in order.
func nameParts(found []entity) (map[string]int, []string) {
	owners := map[string][]int{}
	var order []string
	for i, e := range found {
		words := nameWords(e)
		if len(words) < 2 {
			continue
		}
		for _, w := range words {
			if letterCount(w) < minPart || stopParts[fold(w)] || slices.Contains(owners[w], i) {
				continue
			}
			if owners[w] == nil {
				order = append(order, w)
			}
			owners[w] = append(owners[w], i)
		}
	}
	parts := map[string]int{}
	var shared []string
	for _, w := range order {
		if len(owners[w]) == 1 {
			parts[w] = owners[w][0]
		} else {
			shared = append(shared, w)
		}
	}
	return parts, shared
}

func nameWords(e entity) []string {
	if e.Type != Name {
		return nil
	}
	var words []string
	for _, w := range strings.FieldsFunc(e.Value, func(r rune) bool { return unicode.IsSpace(r) || r == ',' }) {
		if w = strings.TrimFunc(w, func(r rune) bool { return !unicode.IsLetter(r) && r != '-' && r != '\'' }); w != "" {
			words = append(words, w)
		}
	}
	return words
}

// wholePart is the longer name a one-word name is a part of, when exactly one name has that part.
func wholePart(e entity, parts map[string]int) (int, bool) {
	if words := nameWords(e); len(words) != 1 {
		return 0, false
	}
	for _, w := range slices.Sorted(maps.Keys(parts)) {
		if fold(w) == fold(e.Value) {
			return parts[w], true
		}
	}
	return 0, false
}

// sharedPart is the part two names share that a one-word name is.
func sharedPart(e entity, shared []string) (string, bool) {
	if words := nameWords(e); len(words) != 1 {
		return "", false
	}
	for _, w := range shared {
		if fold(w) == fold(e.Value) {
			return w, true
		}
	}
	return "", false
}

func letterCount(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

// Empty is a veil that found nothing, which changes no text.
func (v *Veil) Empty() bool { return len(v.entities) == 0 }

// Substitute writes text with every value it holds replaced by its placeholder.
func (v *Veil) Substitute(text string) string {
	if v.Empty() || text == "" {
		return text
	}
	found := v.match.find(text)
	if len(found) == 0 {
		return text
	}
	var out strings.Builder
	at := 0
	for _, h := range found {
		// A number matches from its first digit, so the + of an international phone stays outside the match. When the
		// detail was written with it, the placeholder takes it too, or a reply that restores the value would double it.
		if h.start > at && text[h.start-1] == '+' && strings.HasPrefix(v.entities[h.entity].Value, "+") {
			h.start--
		}
		out.WriteString(text[at:h.start])
		out.WriteString(v.entities[h.entity].Placeholder)
		at = h.end
	}
	out.WriteString(text[at:])
	return out.String()
}

// Holds reports whether text still holds a value outside the placeholders, which a veiled request must never do.
func (v *Veil) Holds(text string) bool {
	if v.Empty() || text == "" {
		return false
	}
	for _, h := range v.match.find(text) {
		if !v.insidePlaceholder(text, h) {
			return true
		}
	}
	return false
}

func (v *Veil) insidePlaceholder(text string, h match) bool {
	for _, e := range v.entities {
		for from := max(0, h.end-len(e.Placeholder)); from <= h.start; from++ {
			if strings.HasPrefix(text[from:], e.Placeholder) {
				return true
			}
		}
	}
	return false
}

// Entities lists every detail and its placeholder, in placeholder order of first appearance.
func (v *Veil) Entities() []Entity {
	list := make([]Entity, len(v.entities))
	for i, e := range v.entities {
		list[i] = Entity{Placeholder: e.Placeholder, Type: e.Type, Value: e.Value}
	}
	return list
}

func (v *Veil) String() string   { return fmt.Sprintf("privacyveil.Veil(%d details)", len(v.entities)) }
func (v *Veil) GoString() string { return v.String() }
