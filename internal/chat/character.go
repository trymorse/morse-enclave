package chat

import (
	"cmp"
	"crypto/sha256"
	"regexp"
	"slices"
	"strings"

	"morse/backend/internal/enum"
)

// A PromptHash is a launch character's prompt as the cast knows it, and whether it's the character's NSFW one.
type PromptHash struct {
	ID   string
	Len  int
	Sum  [sha256.Size]byte
	NSFW bool
}

func HashPrompt(id, text string, nsfw bool) PromptHash {
	return PromptHash{ID: id, Len: len(text), Sum: sha256.Sum256([]byte(text)), NSFW: nsfw}
}

type Cast struct {
	prompts []PromptHash
	rules   string
	opening *regexp.Regexp
}

func NewCast(prompts []PromptHash, rules string) Cast {
	byLen := func(a, b PromptHash) int { return cmp.Compare(a.Len, b.Len) }
	c := Cast{prompts: slices.SortedStableFunc(slices.Values(prompts), byLen), rules: rules}
	if rules != "" {
		name := `[^\n]{1,200}`
		quoted := regexp.QuoteMeta(rules)
		quoted = strings.ReplaceAll(quoted, regexp.QuoteMeta("{name}"), name)
		quoted = strings.ReplaceAll(quoted, regexp.QuoteMeta("{short}"), name)
		c.opening = regexp.MustCompile(`\A` + quoted + `(?:\z|\n\n)`)
	}
	return c
}

func (c Cast) Prompts() []PromptHash { return c.prompts }

func (c Cast) Rules() string { return c.rules }

func (c Cast) catalogPrompt(text string) (PromptHash, bool) {
	for _, h := range c.prompts {
		if h.Len > len(text) {
			break
		}
		if (h.Len == len(text) || strings.HasPrefix(text[h.Len:], "\n\n")) && sha256.Sum256([]byte(text[:h.Len])) == h.Sum {
			return h, true
		}
	}
	return PromptHash{}, false
}

type CharacterKind uint8

const (
	NoCharacter CharacterKind = iota
	CatalogCharacter
	OwnCharacter
)

var characterKinds = enum.Names[CharacterKind]{NoCharacter: "none", CatalogCharacter: "catalog", OwnCharacter: "own"}

func (k CharacterKind) MarshalText() ([]byte, error) { return characterKinds.MarshalText(k) }

func (k *CharacterKind) UnmarshalText(text []byte) error {
	return characterKinds.UnmarshalText(k, text)
}

// A Character is who a chat plays. NSFW is set only for a launch character whose NSFW prompt the client sent
// itself, which the proxy checks as it checks an NSFW prompt it writes.
type Character struct {
	Kind CharacterKind
	ID   string
	NSFW bool
}

func (c Character) Plays() bool { return c.Kind != NoCharacter }

func (c Cast) Plays(text string) Character {
	if h, ok := c.catalogPrompt(text); ok {
		return Character{Kind: CatalogCharacter, ID: h.ID, NSFW: h.NSFW}
	}
	if c.opening != nil && c.opening.MatchString(text) {
		return Character{Kind: OwnCharacter}
	}
	return Character{}
}

func (r *Request) SystemText() (string, error) {
	msgs, err := r.Messages()
	if err != nil {
		return "", err
	}
	for _, m := range msgs {
		if m.Role == "system" {
			text, _ := m.Text()
			return text, nil
		}
	}
	return "", nil
}
