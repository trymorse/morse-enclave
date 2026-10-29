package chat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// An Example is a launch character the app's character writer learns from: its card and hook as a brief, and its
// SFW prompt's notes and first message as what the brief became.
type Example struct {
	Launch
	Name, Card, Pronoun, Hook, Starter string
}

type Writing struct {
	Examples []Example
}

var errExamplesNeedSystem = fmt.Errorf("%w: the writer's examples go after a first message that is a system message", errMalformedMessages)

// WithExamples puts each example after the system message the request opens with, as a user turn of its brief and
// an assistant turn of the character it became, in the writer's reply format.
func (r *Request) WithExamples(examples []Example) (*Request, error) {
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 || msgs[0].Role != "system" {
		return nil, errExamplesNeedSystem
	}
	var list bytes.Buffer
	list.WriteByte('[')
	list.Write(encodeObject(msgs[0].raw))
	for _, e := range examples {
		for _, turn := range [][2]string{{"user", e.brief()}, {"assistant", e.draft()}} {
			list.WriteByte(',')
			list.Write(textMessage(turn[0], turn[1]))
		}
	}
	for _, m := range msgs[1:] {
		list.WriteByte(',')
		list.Write(encodeObject(m.raw))
	}
	list.WriteByte(']')
	return r.withMessages(list.Bytes()), nil
}

func textMessage(role, content string) []byte {
	roleJSON, _ := json.Marshal(role)
	contentJSON, _ := json.Marshal(content)
	return encodeObject(map[string]json.RawMessage{"role": roleJSON, "content": contentJSON})
}

func (e Example) brief() string {
	return "Name: " + jsTrim(e.Name) + "\nTagline: " + orNone(jsTrim(e.Card)) + "\nPronoun: " + e.Pronoun + "\nBackstory:\n" + orNone(jsTrim(e.Hook))
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func (e Example) draft() string {
	return "<tagline>" + e.Card + "</tagline>\n<pronoun>" + e.Pronoun + "</pronoun>\n<notes>\n" + exampleNotes(e.Prompt) + "\n</notes>\n<starter>\n" + e.Starter + "\n</starter>"
}

// The app's writer and the notes it reads are TypeScript, so the port matches JavaScript's whitespace: `\s` and
// String.prototype.trim take these, where Go's `\s` takes only ASCII.
const jsSpaces = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

const jsBlank = `\t\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var (
	jsParagraphBreak   = regexp.MustCompile(`\n[\n` + jsBlank + `]*\n`)
	contentLine        = regexp.MustCompile(`\nContent:[` + jsBlank + `]*\n`)
	castKnowsParagraph = regexp.MustCompile(`^People [^:\n]* knows:`)
)

func jsTrim(s string) string { return strings.Trim(s, jsSpaces) }

func exampleNotes(prompt string) string {
	var kept []string
	for _, p := range jsParagraphBreak.Split(ownNotes(prompt), -1) {
		if !castKnowsParagraph.MatchString(p) {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "\n\n")
}

const (
	wholePrompt    = "You are playing "
	characterNotes = "Character notes:"
)

func ownNotes(prompt string) string {
	if !strings.HasPrefix(strings.TrimLeft(prompt, jsSpaces), wholePrompt) {
		return jsTrim(prompt)
	}
	notes := prompt
	if at := strings.LastIndex(prompt, characterNotes); at >= 0 {
		notes = prompt[at+len(characterNotes):]
	}
	if at := contentAt(notes); at >= 0 {
		notes = notes[:at]
	}
	return jsTrim(notes)
}

func contentAt(notes string) int {
	for _, m := range contentLine.FindAllStringIndex(notes, -1) {
		for i := m[0]; i > 0; {
			r, size := utf8.DecodeLastRuneInString(notes[:i])
			if !strings.ContainsRune(jsSpaces, r) {
				break
			}
			if r == '\n' {
				return m[0]
			}
			i -= size
		}
	}
	return -1
}
