package chat

import (
	"encoding/json"
	"strings"
)

// ToolCalls gathers the tool calls a client received in one reply, chunk by chunk, to tell whether one of them is
// unusable. It reads what the client got, after the provider's normalizer, so a shape the normalizer repaired is not
// held against the host. The zero value is ready to use.
type ToolCalls struct {
	calls map[callAt]*gathered
}

type callAt struct{ choice, index int }

type gathered struct {
	named     bool
	arguments strings.Builder
}

type callsView struct {
	Choices []struct {
		Index *int `json:"index"`
		Delta *struct {
			ToolCalls []callView `json:"tool_calls"`
		} `json:"delta"`
		Message *struct {
			ToolCalls []callView `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

type callView struct {
	Index    *int `json:"index"`
	Function struct {
		Name      string  `json:"name"`
		Arguments *string `json:"arguments"`
	} `json:"function"`
}

// Add gathers the tool calls of a chunk the client received. A stream's chunk names each call by its index, and a
// whole message's calls go by their place in it.
func (t *ToolCalls) Add(c Chunk) {
	var view callsView
	if json.Unmarshal(c.object, &view) != nil {
		return
	}
	for position, choice := range view.Choices {
		at := callAt{choice: position}
		if choice.Index != nil {
			at.choice = *choice.Index
		}
		var calls []callView
		switch {
		case choice.Delta != nil:
			calls = choice.Delta.ToolCalls
		case choice.Message != nil:
			calls = choice.Message.ToolCalls
		}
		for place, call := range calls {
			at.index = place
			if call.Index != nil {
				at.index = *call.Index
			}
			t.gather(at, call)
		}
	}
}

func (t *ToolCalls) gather(at callAt, call callView) {
	if t.calls == nil {
		t.calls = map[callAt]*gathered{}
	}
	g, ok := t.calls[at]
	if !ok {
		g = &gathered{}
		t.calls[at] = g
	}
	g.named = g.named || call.Function.Name != ""
	if call.Function.Arguments != nil {
		g.arguments.WriteString(*call.Function.Arguments)
	}
}

// Malformed is whether a call the client received has no function name, or, in a reply that did not stop at its
// length limit or a content filter to a request that set no stop string, arguments that are not JSON. A reply cut at
// its limit or by a filter may end a call's arguments early, some hosts cut them at the client's stop string, and
// arguments left empty are read as none.
func (t *ToolCalls) Malformed(finish Finish, stops bool) bool {
	mayBeCut := finish == FinishLength || finish == FinishContentFilter || stops
	for _, g := range t.calls {
		args := g.arguments.String()
		if !g.named || !mayBeCut && args != "" && !json.Valid([]byte(args)) {
			return true
		}
	}
	return false
}
