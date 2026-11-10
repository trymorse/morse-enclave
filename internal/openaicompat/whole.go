package openaicompat

import (
	"bytes"
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"

	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
)

// Whole joins the chunks of a streamed reply into the chat.completion a host sends whole, in the shape Complete gives
// one: each choice's reasoning, text and refusal run together, each tool call carries the id, type and name its first
// chunk named and every chunk's arguments, and the reply carries the last finish_reason and usage the stream sent.
func Whole(chunks []chat.Chunk) (chat.Chunk, error) {
	var head envelope
	var usage json.RawMessage
	choices := map[int]*wholeChoice{}
	for _, c := range chunks {
		var buf bytes.Buffer
		c.WriteTo(&buf)
		var chunk struct {
			envelope
			Choices []streamedChoice `json:"choices"`
		}
		if err := json.Unmarshal(buf.Bytes(), &chunk); err != nil {
			return chat.Chunk{}, err
		}
		if head.ID == "" {
			head = chunk.envelope
		}
		if !isNull(chunk.Usage) {
			usage = chunk.Usage
		}
		for _, sc := range chunk.Choices {
			if choices[sc.Index] == nil {
				choices[sc.Index] = &wholeChoice{calls: map[int]*wholeCall{}}
			}
			choices[sc.Index].add(sc)
		}
	}
	var out bytes.Buffer
	out.WriteByte('[')
	for i, index := range slices.Sorted(maps.Keys(choices)) {
		if i > 0 {
			out.WriteByte(',')
		}
		choices[index].write(&out, index)
	}
	out.WriteByte(']')
	return chat.NewChunk(jsonx.Encode(envelope{ID: head.ID, Object: "chat.completion", Created: head.Created, Model: head.Model, Choices: out.Bytes(), Usage: usage})), nil
}

type streamedChoice struct {
	Index int `json:"index"`
	Delta struct {
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
		Refusal          string `json:"refusal"`
		ToolCalls        []struct {
			Index    int    `json:"index"`
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	} `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

type wholeChoice struct {
	content, reasoning, refusal strings.Builder
	calls                       map[int]*wholeCall
	finish                      *string
}

type wholeCall struct {
	id, kind, name string
	arguments      strings.Builder
}

func (w *wholeChoice) add(sc streamedChoice) {
	w.content.WriteString(sc.Delta.Content)
	w.reasoning.WriteString(sc.Delta.ReasoningContent)
	w.refusal.WriteString(sc.Delta.Refusal)
	for _, tc := range sc.Delta.ToolCalls {
		call := w.calls[tc.Index]
		if call == nil {
			call = &wholeCall{}
			w.calls[tc.Index] = call
		}
		call.id, call.kind, call.name = cmp.Or(call.id, tc.ID), cmp.Or(call.kind, tc.Type), cmp.Or(call.name, tc.Function.Name)
		call.arguments.WriteString(tc.Function.Arguments)
	}
	if sc.FinishReason != nil {
		w.finish = sc.FinishReason
	}
}

// write writes the choice as Complete gives a message: content null when it has no text, and reasoning_content,
// refusal and tool_calls only when there are any.
func (w *wholeChoice) write(out *bytes.Buffer, index int) {
	var msg bytes.Buffer
	m := objectWriter{out: &msg}
	m.field("role", jsonString("assistant"))
	content := json.RawMessage("null")
	if w.content.Len() > 0 {
		content = jsonString(w.content.String())
	}
	m.field("content", content)
	if w.reasoning.Len() > 0 {
		m.field("reasoning_content", jsonString(w.reasoning.String()))
	}
	if w.refusal.Len() > 0 {
		m.field("refusal", jsonString(w.refusal.String()))
	}
	if len(w.calls) > 0 {
		var calls bytes.Buffer
		calls.WriteByte('[')
		for i, at := range slices.Sorted(maps.Keys(w.calls)) {
			if i > 0 {
				calls.WriteByte(',')
			}
			c := w.calls[at]
			fn := toolCallJSON(map[string]json.RawMessage{"name": jsonString(c.name), "arguments": jsonString(c.arguments.String())})
			calls.Write(toolCallJSON(map[string]json.RawMessage{"id": jsonString(c.id), "type": jsonString(cmp.Or(c.kind, "function")), "function": fn}))
		}
		calls.WriteByte(']')
		m.field("tool_calls", calls.Bytes())
	}
	m.close()
	finish := json.RawMessage("null")
	if w.finish != nil {
		finish = jsonString(*w.finish)
	}
	c := objectWriter{out: out}
	c.field("index", json.RawMessage(strconv.Itoa(index)))
	c.field("message", msg.Bytes())
	c.field("finish_reason", finish)
	c.close()
}
