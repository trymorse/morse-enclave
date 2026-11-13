package openaicompat

import (
	"encoding/json"
	"strings"

	"morse/backend/internal/chat"
	"morse/backend/internal/jsonx"
)

const (
	thinkOpen  = "<think>"
	thinkClose = "</think>"
)

func asksNoReasoning(c chat.Call) bool {
	effort, ok := c.ForwardedEffort()
	return !ok || effort == chat.NoEffort
}

func (p *Provider) turnsThinkingOff(c chat.Call) bool {
	return p.Fixes.ThinkingOffSwitch && p.ThinkingField != "" && asksNoReasoning(c)
}

type thinkStage uint8

const (
	beforeThinking thinkStage = iota
	thinking
	afterThinking
	answering
)

type thinkSplit struct {
	stage        thinkStage
	pending      string
	hostSplitsIt bool
}

type answerPart string

const (
	deltaPart   answerPart = "delta"
	messagePart answerPart = "message"
)

func (s *thinkSplit) feed(text string) (reasoning, content string) {
	s.pending += text
	if s.stage == beforeThinking {
		head := strings.TrimLeft(s.pending, " \t\r\n")
		switch {
		case head == "" || len(head) < len(thinkOpen) && strings.HasPrefix(thinkOpen, head):
			return "", ""
		case strings.HasPrefix(head, thinkOpen):
			s.pending = head[len(thinkOpen):]
		}
		s.stage = thinking
	}
	if s.stage == thinking {
		at := strings.Index(s.pending, thinkClose)
		if at < 0 {
			held := partialSuffix(s.pending, thinkClose)
			reasoning, s.pending = s.pending[:len(s.pending)-held], s.pending[len(s.pending)-held:]
			return reasoning, ""
		}
		reasoning, s.pending = s.pending[:at], s.pending[at+len(thinkClose):]
		s.stage = afterThinking
	}
	if s.stage == afterThinking {
		s.pending = strings.TrimLeft(s.pending, "\r\n")
		if s.pending == "" {
			return reasoning, ""
		}
		s.stage = answering
	}
	content, s.pending = s.pending, ""
	return reasoning, content
}

func (s *thinkSplit) flush() string {
	held := s.pending
	s.pending = ""
	return held
}

func partialSuffix(text, tag string) int {
	for n := min(len(text), len(tag)-1); n > 0; n-- {
		if strings.HasSuffix(text, tag[:n]) {
			return n
		}
	}
	return 0
}

func (s *thinkSplit) splitThinking(r *reply, part answerPart) error {
	raw, ok := r.value("choices")
	if !ok || s.hostSplitsIt {
		return nil
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choices); err != nil || len(choices) == 0 {
		return err
	}
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(choices[0][string(part)], &answer); err != nil || answer == nil {
		return err
	}
	if hasText(answer["reasoning_content"]) || hasText(answer["reasoning"]) {
		s.hostSplitsIt = true
		return nil
	}
	var text string
	if v := answer["content"]; !isNull(v) {
		if err := json.Unmarshal(v, &text); err != nil {
			return err
		}
	}
	reasoning, content := s.feed(text)
	if part == messagePart || !isNull(choices[0]["finish_reason"]) {
		reasoning += s.flush()
	}
	if reasoning != "" {
		answer["reasoning_content"] = jsonx.Encode(reasoning)
	}
	switch {
	case content != "":
		answer["content"] = jsonx.Encode(content)
	case part == messagePart:
		answer["content"] = json.RawMessage("null")
	default:
		delete(answer, "content")
	}
	choices[0][string(part)] = jsonx.Encode(answer)
	r.set("choices", jsonx.Encode(choices))
	return nil
}

func (s *thinkSplit) flushed() (reply, bool) {
	held := s.flush()
	if held == "" || s.hostSplitsIt {
		return reply{}, false
	}
	return parseReply(jsonx.Encode(map[string]any{"choices": []map[string]any{{"index": 0, "delta": map[string]string{"reasoning_content": held}, "finish_reason": nil}}}))
}

func hasText(v json.RawMessage) bool { return !isNull(v) && string(v) != `""` }
