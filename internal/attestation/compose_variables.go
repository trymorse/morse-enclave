package attestation

import "strings"

// Variable is one interpolation docker compose makes in a string: `$NAME`, `${NAME}`, or `${NAME<op>word}` for the
// operators `-`, `:-`, `+`, `:+`, `?`, and `:?`. Text is what follows the dollar sign, minus the braces.
type Variable struct {
	Text     string
	Name     string
	Operator string
	Value    string
}

// Variables lists the interpolations compose makes in text, outermost first. A `$$` is a literal dollar sign and
// interpolates nothing. A `${` that never closes reads to the end of the text, so a variable cut off by a slice is
// still found. A variable nested in an operator's word is in its Value; Names finds it too.
func Variables(text string) []Variable {
	var refs []Variable
	for i := 0; i < len(text); i++ {
		if text[i] != '$' || i+1 == len(text) {
			continue
		}
		switch next := text[i+1]; {
		case next == '$':
			i++
		case next == '{':
			end, depth := i+2, 1
			for ; end < len(text) && depth > 0; end++ {
				switch text[end] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			body := text[i+2 : end]
			if depth == 0 {
				body = text[i+2 : end-1]
			}
			refs = append(refs, parseVariable(body))
			i = end - 1
		case isNameStart(next):
			end := i + 1
			for end < len(text) && isNameChar(text[end]) {
				end++
			}
			refs = append(refs, Variable{Text: text[i+1 : end], Name: text[i+1 : end]})
			i = end - 1
		}
	}
	return refs
}

// Names lists every variable name text interpolates, those nested in a default or alternate included.
func Names(text string) []string {
	var names []string
	for _, v := range Variables(text) {
		if v.Name != "" {
			names = append(names, v.Name)
		}
		names = append(names, Names(v.Value)...)
	}
	return names
}

func parseVariable(body string) Variable {
	v := Variable{Text: body}
	end := 0
	for end < len(body) && isNameChar(body[end]) {
		end++
	}
	v.Name = body[:end]
	rest := body[end:]
	op := min(len(rest), 1)
	if strings.HasPrefix(rest, ":") {
		op = min(len(rest), 2)
	}
	v.Operator, v.Value = rest[:op], rest[op:]
	return v
}

func isNameStart(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

func isNameChar(c byte) bool { return isNameStart(c) || c >= '0' && c <= '9' }
