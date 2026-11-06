package measure

import (
	"math"
	"time"

	"morse/backend/internal/chat"
	"morse/backend/internal/enum"
)

type Cut uint8

const (
	NotCut Cut = iota
	CutByClient
	CutByDeadline
	CutByProxy
)

var cutNames = enum.Names[Cut]{NotCut: "none", CutByClient: "client", CutByDeadline: "deadline", CutByProxy: "proxy"}

func (c Cut) String() string { return cutNames.String(c) }

func (c Cut) MarshalText() ([]byte, error) { return cutNames.MarshalText(c) }

func (c *Cut) UnmarshalText(text []byte) error { return cutNames.UnmarshalText(c, text) }

type Evidence struct {
	Outcome            Outcome
	Cut                Cut
	Unsent             bool
	Upstream           chat.Usage
	Counted            Counted
	PromptBytes        int
	Attachments        int
	PromptBound        int
	Budgeted           bool
	Reply              Reply
	Finish             chat.Finish
	ServedBy           chat.Host
	Unanswered         bool
	ReasoningRequested bool
	HidesReasoning     bool
	OutputLimit        int
	ReplyBytesPerToken float64
	ReasoningCap       int
	Thinking           ThinkingTime
	ReasonedAgain      bool
}

type ThinkingTime struct {
	Duration time.Duration
	Rate     int
}

type Thinking struct {
	ThinkingTime
	Tokens int
}

func (t ThinkingTime) bound() int {
	return int(int64(t.Rate) * int64(max(t.Duration, 0)) / int64(time.Second))
}

type Counted struct {
	Prompt, Completion Reading
}

type Reply interface {
	delivered(outputLimit int, replyBytesPerToken float64) Reading
}

type Streamed struct{ Events, VisibleBytes int }

type Buffered struct{ Bytes int }

type SealedEvents struct{ Events int }

type Opaque struct{}

func (r Streamed) delivered(outputLimit int, replyBytesPerToken float64) Reading {
	if r.VisibleBytes > 0 {
		if byBytes := min(int(math.Ceil(float64(r.VisibleBytes)/replyBytesPerToken)), outputLimit); byBytes > r.Events {
			return reading(byBytes, MethodReplyBytes)
		}
	}
	return reading(r.Events, MethodChunks)
}

func (r Buffered) delivered(int, float64) Reading {
	return reading(bytesEstimate(r.Bytes), MethodReplyBytes)
}

func (r SealedEvents) delivered(int, float64) Reading {
	return reading(r.Events, MethodChunks)
}

func (Opaque) delivered(outputLimit int, _ float64) Reading {
	return reading(outputLimit, MethodOutputLimit)
}

const (
	overestimateBytesPerToken = 2
	AttachmentTokens          = 4784
)

func bytesEstimate(bytes int) int {
	return (max(bytes, 0) + overestimateBytesPerToken - 1) / overestimateBytesPerToken
}

type Method uint8

const (
	MethodNone Method = iota
	MethodReported
	MethodCounted
	MethodCalibrated
	MethodClient
	MethodRequestBytes
	MethodChunks
	MethodReplyBytes
	MethodOutputLimit
	MethodThinkingTime
)

type methodRule struct {
	name   string
	source UsageSource
}

var methodRules = [...]methodRule{
	MethodNone:         {"none", UsageNone},
	MethodReported:     {"reported", UsageReported},
	MethodCounted:      {"counted", UsageCounted},
	MethodCalibrated:   {"calibrated", UsageCalibrated},
	MethodClient:       {"client", UsageClient},
	MethodRequestBytes: {"request_bytes", UsageEstimated},
	MethodChunks:       {"chunks", UsageEstimated},
	MethodReplyBytes:   {"reply_bytes", UsageEstimated},
	MethodOutputLimit:  {"output_limit", UsageEstimated},
	MethodThinkingTime: {"thinking_time", UsageEstimated},
}

var methodNames = func() enum.Names[Method] {
	names := make(enum.Names[Method], len(methodRules))
	for m, r := range methodRules {
		names[m] = r.name
	}
	return names
}()

func (m Method) String() string { return methodNames.String(m) }

func (m Method) MarshalText() ([]byte, error) { return methodNames.MarshalText(m) }

func (m *Method) UnmarshalText(text []byte) error { return methodNames.UnmarshalText(m, text) }

func Methods() []Method { return methodNames.Values() }

var sourceRank = map[UsageSource]int{UsageReported: 1, UsageCounted: 2, UsageCalibrated: 3, UsageClient: 4, UsageEstimated: 5, UsageMetered: 5}

type Reading struct {
	Tokens int
	Method Method
}

func reading(tokens int, m Method) Reading {
	if tokens <= 0 {
		return Reading{}
	}
	return Reading{Tokens: tokens, Method: m}
}

type Sides struct {
	Prompt, Completion, Hidden Method
}

func (s Sides) source(whenNone UsageSource) UsageSource {
	label := whenNone
	weakest := 0
	for _, m := range []Method{s.Prompt, s.Completion, s.Hidden} {
		if src := methodRules[m].source; m != MethodNone && sourceRank[src] > weakest {
			label, weakest = src, sourceRank[src]
		}
	}
	return label
}

type Measurement struct {
	Outcome    Outcome
	Tokens     chat.Usage
	Sides      Sides
	Thinking   Thinking
	Finish     chat.Finish
	ServedBy   chat.Host `json:",omitzero"`
	Unanswered bool
	Unsent     bool `json:",omitzero"`
}

func (m Measurement) Source() UsageSource { return m.Sides.source(m.unmeasured()) }

// Measure bills a refusal, and a request no vendor received, only what the vendor reported: neither did work.
func (e Evidence) Measure() Measurement {
	reported := e.Upstream.Normalized()
	if e.Outcome == Rejected || e.Unsent {
		m := measured(e.Outcome, reported, Sides{Prompt: upstreamSide(reported.PromptTokens), Completion: upstreamSide(reported.CompletionTokens)})
		m.Unsent = e.Unsent
		return m
	}
	prompt := rung(reported.PromptTokens, e.Counted.Prompt, e.promptEstimate())
	completion := rung(reported.CompletionTokens, e.Counted.Completion, e.Reply.delivered(e.OutputLimit, e.ReplyBytesPerToken))
	hidden := e.hidden(reported, completion)
	u := chat.Usage{PromptTokens: prompt.Tokens, CompletionTokens: completion.Tokens + hidden.Tokens}
	if prompt.Method == MethodReported {
		u.CachedPromptTokens, u.CacheWritePromptTokens = reported.CachedPromptTokens, reported.CacheWritePromptTokens
	}
	sides := Sides{Prompt: prompt.Method, Completion: completion.Method}
	if hidden.Tokens > 0 {
		sides.Hidden = MethodThinkingTime
	}
	m := measured(e.Outcome, u, sides)
	m.Thinking, m.Finish, m.Unanswered, m.ServedBy = hidden, e.Finish, e.Unanswered, e.ServedBy
	return m
}

func measured(o Outcome, u chat.Usage, sides Sides) Measurement {
	u = u.Normalized()
	u.ReasoningTokens = 0
	return Measurement{Outcome: o, Tokens: u, Sides: sides}
}

// A bill with no measured side is labelled by its outcome: a refusal, or a request never sent, billed
// nothing, and anything else stands on the upstream's word.
func (m Measurement) unmeasured() UsageSource {
	if m.Outcome == Rejected || m.Unsent {
		return UsageNone
	}
	return UsageReported
}

func (e Evidence) promptEstimate() Reading {
	text := e.PromptBytes
	if !e.Budgeted {
		text = bytesEstimate(text)
	}
	return reading(min(text+e.Attachments*AttachmentTokens, e.PromptBound), MethodRequestBytes)
}

func rung(reported int, counted, estimate Reading) Reading {
	switch {
	case reported > 0:
		return Reading{Tokens: reported, Method: MethodReported}
	case counted.Method != MethodNone:
		return counted
	}
	return estimate
}

func upstreamSide(tokens int) Method {
	if tokens > 0 {
		return MethodReported
	}
	return MethodNone
}

func (e Evidence) hidden(reported chat.Usage, visible Reading) Thinking {
	if reported.CompletionTokens > 0 || e.Cut != CutByClient || !e.ReasoningRequested || !e.HidesReasoning {
		return Thinking{}
	}
	t := Thinking{ThinkingTime: e.Thinking}
	t.Tokens = max(min(t.bound(), e.ReasoningCap-visible.Tokens), 0)
	return t
}

func (e Evidence) NeedsCount() bool {
	cut := e.Cut == CutByClient || e.Cut == CutByDeadline
	return e.Outcome == Cancelled && cut && !e.Unsent && (e.Upstream.PromptTokens <= 0 || e.Upstream.CompletionTokens <= 0)
}
