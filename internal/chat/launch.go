package chat

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
)

// A Launch is a launch character's system prompt for the proxy to write into a chat, once it checked that the
// caller may play the character with that prompt.
type Launch struct {
	ID     string
	Prompt string
}

func (l Launch) String() string   { return fmt.Sprintf("chat.Launch{id=%q}", l.ID) }
func (l Launch) GoString() string { return l.String() }

func (l Launch) Character() Character { return Character{Kind: CatalogCharacter, ID: l.ID} }

// Casts is whether the launch's prompt is, exactly, one of the cast's prompts for that character.
func (c Cast) Casts(l Launch) bool {
	sum := sha256.Sum256([]byte(l.Prompt))
	for _, h := range c.prompts {
		if h.ID == l.ID && h.Len == len(l.Prompt) && h.Sum == sum {
			return true
		}
	}
	return false
}

var errSystemNotText = fmt.Errorf("%w: the first message is a system message that is not text", errMalformedMessages)

// UnderSystemPrompt opens the chat with prompt: the first message, when it is the system message, becomes prompt, a
// blank line, and its own text, and otherwise prompt goes before it as a system message of its own.
func (r *Request) UnderSystemPrompt(prompt string) (*Request, error) {
	msgs, err := r.Messages()
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 || msgs[0].Role != "system" {
		return r.Prepend("system", prompt)
	}
	text, ok := msgs[0].Text()
	if !ok {
		return nil, errSystemNotText
	}
	if text != "" {
		prompt += "\n\n" + text
	}
	first := maps.Clone(msgs[0].raw)
	first["content"], _ = json.Marshal(prompt)
	var list bytes.Buffer
	list.WriteByte('[')
	list.Write(encodeObject(first))
	for _, m := range msgs[1:] {
		list.WriteByte(',')
		list.Write(encodeObject(m.raw))
	}
	list.WriteByte(']')
	return r.withMessages(list.Bytes()), nil
}

// Prepend puts a message of role and content before the chat's messages, and keeps every byte of theirs.
func (r *Request) Prepend(role, content string) (*Request, error) {
	list := bytes.Trim(r.fields["messages"], jsonSpace)
	if len(list) < 2 || list[0] != '[' {
		return nil, errMalformedMessages
	}
	roleJSON, _ := json.Marshal(role)
	contentJSON, _ := json.Marshal(content)
	rest := bytes.TrimLeft(list[1:], jsonSpace)
	messages := append([]byte{'['}, encodeObject(map[string]json.RawMessage{"role": roleJSON, "content": contentJSON})...)
	if rest[0] != ']' {
		messages = append(messages, ',')
	}
	return r.withMessages(append(messages, rest...)), nil
}

func (r *Request) withMessages(messages json.RawMessage) *Request {
	out := *r
	out.fields = maps.Clone(r.fields)
	out.fields["messages"] = messages
	out.raw = encodeObject(out.fields)
	out.messages = sync.OnceValues(out.parseMessages)
	return &out
}
