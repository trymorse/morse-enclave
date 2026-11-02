package chat

import (
	"fmt"
	"strings"
)

// An OwnFrame is the rules a user's own character plays by, for the worker to put around the notes the app sends,
// so the rules never reach the app: Base before the notes and Content, the section for the chat's NSFW switch, after
// them. The proxy picks the section once it checked the caller may play it.
type OwnFrame struct {
	Base    string `json:"base"`
	Content string `json:"content"`
	NSFW    bool   `json:"nsfw"`
}

func (f OwnFrame) String() string   { return fmt.Sprintf("chat.OwnFrame{nsfw=%t}", f.NSFW) }
func (f OwnFrame) GoString() string { return f.String() }

func (OwnFrame) Character() Character { return Character{Kind: OwnCharacter} }

// The lines the app opens an own character's system message with, naming the character for the rules' {name} and
// {short}. They are inside the seal, so only the worker reads them, and it takes them off before the model does.
const (
	OwnNameLine  = "Character name: "
	OwnShortLine = "Short name: "
)

// The longest name the name lines may give, as the rules' opening matches a name.
const maxOwnName = 200

// ownNames takes the name lines off the start of text: the name, the short name (the name when the line is missing),
// and the text after them, its blank lines dropped. Text with no name line, or a name out of bounds, is all rest.
func ownNames(text string) (name, short, rest string) {
	line, after, _ := strings.Cut(text, "\n")
	name, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), OwnNameLine)
	name = strings.TrimSpace(name)
	if !ok || name == "" || len(name) > maxOwnName {
		return "", "", text
	}
	short = name
	if line, rest, _ := strings.Cut(after, "\n"); strings.HasPrefix(line, OwnShortLine) {
		if s := strings.TrimSpace(strings.TrimPrefix(strings.TrimRight(line, "\r"), OwnShortLine)); s != "" && len(s) <= maxOwnName {
			short = s
		}
		after = rest
	}
	return name, short, strings.TrimLeft(after, "\r\n")
}

// unnamed stands in for a character's name where the worker can't read it, an e2ee chat's.
const unnamed = "the character"

// fill puts name and short in for the rules' {name} and {short}. With no name, it puts "the character", capitalized
// where it opens a line or a sentence.
func fill(text, name, short string) string {
	if name != "" {
		return strings.NewReplacer("{name}", name, "{short}", short).Replace(text)
	}
	var b strings.Builder
	for {
		at := strings.IndexByte(text, '{')
		if at < 0 {
			b.WriteString(text)
			return b.String()
		}
		token := ""
		for _, t := range []string{"{name}", "{short}"} {
			if strings.HasPrefix(text[at:], t) {
				token = t
			}
		}
		if token == "" {
			b.WriteString(text[:at+1])
			text = text[at+1:]
			continue
		}
		b.WriteString(text[:at])
		if opensSentence(b.String()) {
			b.WriteString("The character")
		} else {
			b.WriteString(unnamed)
		}
		text = text[at+len(token):]
	}
}

func opensSentence(before string) bool {
	trimmed := strings.TrimRight(before, " ")
	if trimmed == "" {
		return true
	}
	switch trimmed[len(trimmed)-1] {
	case '\n', '.', '!', '?', '-', '*', '"':
		return true
	}
	return false
}

// Around is the system text the worker sends for text, the app's system message: Base, the text without its name
// lines, then Content, each named for the character the name lines name.
func (f OwnFrame) Around(text string) string {
	name, short, rest := ownNames(text)
	parts := []string{fill(f.Base, name, short)}
	if rest = strings.TrimSpace(rest); rest != "" {
		parts = append(parts, rest)
	}
	return strings.Join(append(parts, fill(f.Content, name, short)), "\n\n")
}

// Unnamed is what the worker seals in front of an e2ee chat, whose name lines it can't read: Base, then Content,
// with "the character" for the name.
func (f OwnFrame) Unnamed() string {
	return fill(f.Base, "", "") + "\n\n" + fill(f.Content, "", "")
}

// UnderOwnFrame puts frame's rules around the chat's system message, or opens the chat with them when it has none.
func (r *Request) UnderOwnFrame(frame OwnFrame) (*Request, error) {
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 || msgs[0].Role != "system" {
		return r.Prepend("system", frame.Around(""))
	}
	text, ok := msgs[0].Text()
	if !ok {
		return nil, errSystemNotText
	}
	return r.withFirstText(msgs, frame.Around(text)), nil
}
