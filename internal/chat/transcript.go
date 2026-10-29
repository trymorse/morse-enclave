package chat

import (
	"fmt"
	"strings"
)

type Transcript struct {
	limit     int
	size      int
	truncated bool
	parts     [transcriptParts]strings.Builder
}

const (
	partContent = iota
	partReasoning
	partToolArguments
	transcriptParts
)

func NewTranscript(limitBytes int) *Transcript { return &Transcript{limit: limitBytes} }

func (t *Transcript) Add(d Delta) {
	if t == nil || t.truncated {
		return
	}
	if d.Unreadable {
		t.drop()
		return
	}
	t.write(partContent, d.Content)
	t.write(partReasoning, d.Reasoning)
	t.write(partToolArguments, d.ToolArguments)
}

func (t *Transcript) write(part int, s string) {
	if s == "" || t.truncated {
		return
	}
	if t.size += len(s); t.size > t.limit {
		t.drop()
		return
	}
	t.parts[part].WriteString(s)
}

func (t *Transcript) drop() {
	t.truncated = true
	t.parts = [transcriptParts]strings.Builder{}
}

func (t *Transcript) Complete() bool { return t != nil && !t.truncated }

func (t *Transcript) Texts() []string {
	var texts []string
	for i := range t.parts {
		if s := t.parts[i].String(); s != "" {
			texts = append(texts, s)
		}
	}
	return texts
}

func (t *Transcript) String() string {
	if t == nil {
		return "chat.Transcript(nil)"
	}
	return fmt.Sprintf("chat.Transcript(%d bytes)", t.size)
}

func (t *Transcript) GoString() string { return t.String() }
