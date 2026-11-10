package privacyveil

import (
	"encoding/json"
	"strings"
)

// A Restorer puts a veil's values back into one field of a reply as the field arrives in fragments. It holds back a
// tail that could open a placeholder until a later fragment, or Flush, shows whether it does.
type Restorer struct {
	v    *Veil
	held string
	// wordIn is whether the last byte read from the vendor, before held, is a word byte: a bare placeholder must not
	// follow one, judged on the vendor's text and not on the values put back.
	wordIn bool
	// releases, when set, makes this a restorer of tool-call arguments: JSON text into which only the types it
	// releases go back, escaped, while every other placeholder stays as written and is listed as held.
	releases func(Type) bool
	json     jsonState
	kept     []string
}

// Restorer is for text a person reads: every placeholder goes back.
func (v *Veil) Restorer() *Restorer { return &Restorer{v: v} }

// ArgumentRestorer is for a tool call's arguments, which are JSON: only the types releases admits go back, and every
// other placeholder stays, which Held lists.
func (v *Veil) ArgumentRestorer(releases func(Type) bool) *Restorer {
	if releases == nil {
		releases = func(Type) bool { return false }
	}
	return &Restorer{v: v, releases: releases}
}

// Next is the text to send for fragment, values restored, less a tail it holds back.
func (r *Restorer) Next(fragment string) string { return r.scan(r.held+fragment, false) }

// Flush is the tail held back, restored where it is a whole placeholder. A field ends with it.
func (r *Restorer) Flush() string { return r.scan(r.held, true) }

// Held lists the placeholders left in, each once, in the order they came.
func (r *Restorer) Held() []string { return r.kept }

func (r *Restorer) scan(pending string, final bool) string {
	r.held = ""
	if r.v.Empty() {
		return pending
	}
	var out strings.Builder
	read := len(pending)
	defer func() {
		if read > 0 {
			r.wordIn = isWord(pending[read-1])
		}
	}()
	for i := 0; i < len(pending); {
		c := pending[i]
		wordBefore := r.wordIn
		if i > 0 {
			wordBefore = isWord(pending[i-1])
		}
		if c == '[' || isUpper(c) && !wordBefore {
			e, n, partial := r.v.placeholderAt(pending[i:], final)
			if partial {
				r.held, read = pending[i:], i
				break
			}
			if n > 0 {
				r.put(&out, e, pending[i:i+n])
				i += n
				continue
			}
		}
		r.emit(&out, pending[i:i+1])
		i++
	}
	return out.String()
}

// placeholderAt is the entity whose placeholder opens s and its length, or partial when s could still become one: a
// bracketed placeholder cut short, or a bare one whose end the next byte would show.
func (v *Veil) placeholderAt(s string, final bool) (e int, n int, partial bool) {
	for i, ent := range v.entities {
		for _, p := range []string{ent.Placeholder, ent.Bare} {
			switch {
			case strings.HasPrefix(s, p):
				if p == ent.Placeholder {
					return i, len(p), false
				}
				if len(s) == len(p) {
					if final {
						return i, len(p), false
					}
					return 0, 0, true
				}
				if !isWord(s[len(p)]) {
					return i, len(p), false
				}
			case !final && len(s) < len(p) && strings.HasPrefix(p, s):
				partial = true
			}
		}
	}
	return 0, 0, partial
}

func (r *Restorer) put(out *strings.Builder, e int, written string) {
	ent := r.v.entities[e]
	switch {
	case r.releases == nil:
		r.emit(out, ent.Value)
	case !r.releases(ent.Type):
		if !containsString(r.kept, ent.Placeholder) {
			r.kept = append(r.kept, ent.Placeholder)
		}
		r.emit(out, written)
	case r.json.inString:
		quoted, _ := json.Marshal(ent.Value)
		r.emit(out, string(quoted[1:len(quoted)-1]))
	default:
		quoted, _ := json.Marshal(ent.Value)
		r.emit(out, string(quoted))
	}
}

func (r *Restorer) emit(out *strings.Builder, s string) {
	if s == "" {
		return
	}
	out.WriteString(s)
	if r.releases != nil {
		r.json.advance(s)
	}
}

// jsonState follows JSON text far enough to know whether the next byte is inside a string.
type jsonState struct{ inString, escaped bool }

func (j *jsonState) advance(s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case j.escaped:
			j.escaped = false
		case j.inString && c == '\\':
			j.escaped = true
		case c == '"':
			j.inString = !j.inString
		}
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
