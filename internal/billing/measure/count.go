package measure

import (
	"math"

	"morse/backend/internal/chat"
)

// RawCount is one tokenizer pass over a request: the prompt, 0 when it was not countable, and
// the visible text of the reply.
type RawCount struct{ Prompt, Visible int }

// Counted ranks a raw count for the ladder. A prompt count is used only once the route's overhead
// has been learned, because the upstream's chat template adds tokens the proxy never sees; the
// visible completion stands on its own, and a learned offset corrects it only where the route
// shows its reasoning, since a hidden route's offset is the reasoning the thinking bound bills.
func (l Learned) Counted(route string, e Evidence, raw RawCount) Counted {
	return l.Figures(route, ThinkingTerms{}).Counted(e, raw)
}

func (f RouteFigures) Counted(e Evidence, raw RawCount) Counted {
	var c Counted
	if raw.Prompt > 0 && f.PromptOverhead.Learned {
		c.Prompt = Reading{Tokens: max(raw.Prompt+f.PromptOverhead.Offset, 0), Method: MethodCalibrated}
	}
	if raw.Visible > 0 {
		c.Completion = Reading{Tokens: raw.Visible, Method: MethodCounted}
		if f.CompletionOffset.Learned && !e.HidesReasoning {
			c.Completion = Reading{Tokens: max(raw.Visible+f.CompletionOffset.Offset, 0), Method: MethodCalibrated}
		}
	}
	return c
}

func (e Evidence) Samples(route string, raw RawCount) []Sample {
	reported := e.Upstream.Normalized()
	var out []Sample
	if raw.Prompt > 0 && reported.PromptTokens > 0 {
		out = append(out, Sample{Route: route, Figure: FigurePromptOverhead, Value: float64(reported.PromptTokens - raw.Prompt)})
	}
	if raw.Visible > 0 && reported.CompletionTokens > 0 && !e.HidesReasoning {
		out = append(out, Sample{Route: route, Figure: FigureCompletionOffset, Value: float64(reported.CompletionTokens - raw.Visible)})
	}
	if e.HidesReasoning && reported.ReasoningTokens > 0 && e.Thinking.Duration > 0 && !e.ReasonedAgain {
		out = append(out, Sample{Route: route, Figure: FigureThinkingRate, Value: float64(reported.ReasoningTokens) / e.Thinking.Duration.Seconds()})
	}
	if visible, ok := e.streamedVisibleTokens(reported); ok {
		if r, streamed := e.Reply.(Streamed); streamed && r.VisibleBytes > 0 {
			out = append(out, Sample{Route: route, Figure: FigureReplyBytesPerToken, Value: sizeHidingBytesPerToken(float64(r.VisibleBytes) / float64(visible))})
		}
	}
	return out
}

func (e Evidence) streamedVisibleTokens(reported chat.Usage) (int, bool) {
	hiddenReasoningUnreported := e.HidesReasoning && e.ReasoningRequested && reported.ReasoningTokens == 0
	if e.Outcome != Completed || hiddenReasoningUnreported {
		return 0, false
	}
	visible := reported.CompletionTokens
	if e.HidesReasoning {
		visible -= reported.ReasoningTokens
	}
	return visible, visible > 0
}

func sizeHidingBytesPerToken(v float64) float64 {
	return min(max(math.Round(v*2)/2, minReplyBytesPerToken), maxReplyBytesPerToken)
}
