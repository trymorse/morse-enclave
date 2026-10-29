package measure_test

import (
	"fmt"
	"testing"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
)

func TestACountIsCalibratedOnlyWhereAFigureIsLearnedAndNeverOnTheCompletionOfARouteThatHidesReasoning(t *testing.T) {
	learned := measure.NewLearned([]measure.LearnedFigure{
		{Route: "m", Figure: measure.FigurePromptOverhead, Median: 6, Accounts: measure.MinLearningAccounts},
		{Route: "m", Figure: measure.FigureCompletionOffset, Median: -4, Accounts: measure.MinLearningAccounts},
	})
	raw := measure.RawCount{Prompt: 20, Visible: 10}
	for name, tc := range map[string]struct {
		l    measure.Learned
		e    measure.Evidence
		raw  measure.RawCount
		want measure.Counted
	}{
		"nothing learned":      {measure.Learned{}, measure.Evidence{}, raw, measure.Counted{Completion: counted(10, measure.MethodCounted)}},
		"both learned":         {learned, measure.Evidence{}, raw, measure.Counted{Prompt: counted(26, measure.MethodCalibrated), Completion: counted(6, measure.MethodCalibrated)}},
		"hidden reasoning":     {learned, measure.Evidence{HidesReasoning: true}, raw, measure.Counted{Prompt: counted(26, measure.MethodCalibrated), Completion: counted(10, measure.MethodCounted)}},
		"offset below zero":    {learned, measure.Evidence{}, measure.RawCount{Visible: 3}, measure.Counted{Completion: counted(0, measure.MethodCalibrated)}},
		"prompt not countable": {learned, measure.Evidence{}, measure.RawCount{Visible: 10}, measure.Counted{Completion: counted(6, measure.MethodCalibrated)}},
		"nothing counted":      {learned, measure.Evidence{}, measure.RawCount{}, measure.Counted{}},
	} {
		if got := tc.l.Counted("m", tc.e, tc.raw); got != tc.want {
			t.Errorf("%s: counted %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestSamplesAreTheReportedFiguresLessTheCountAndTheThinkingRateOnlyOnAHiddenRouteThatReasonedBeforeAnswering(t *testing.T) {
	reported := chat.Usage{PromptTokens: 26, CompletionTokens: 14}
	raw := measure.RawCount{Prompt: 20, Visible: 10}
	thought := measure.Evidence{Upstream: chat.Usage{PromptTokens: 26, CompletionTokens: 314, ReasoningTokens: 300}, HidesReasoning: true, Thinking: measure.ThinkingTime{Duration: 1500 * time.Millisecond}}
	for name, tc := range map[string]struct {
		e    measure.Evidence
		raw  measure.RawCount
		want []measure.Sample
	}{
		"both sides":        {measure.Evidence{Upstream: reported}, raw, []measure.Sample{{Route: "m", Figure: measure.FigurePromptOverhead, Value: 6}, {Route: "m", Figure: measure.FigureCompletionOffset, Value: 4}}},
		"nothing reported":  {measure.Evidence{}, raw, nil},
		"nothing counted":   {measure.Evidence{Upstream: reported}, measure.RawCount{}, nil},
		"hidden, reasoned":  {thought, raw, []measure.Sample{{Route: "m", Figure: measure.FigurePromptOverhead, Value: 6}, {Route: "m", Figure: measure.FigureThinkingRate, Value: 200}}},
		"hidden, no count":  {thought, measure.RawCount{}, []measure.Sample{{Route: "m", Figure: measure.FigureThinkingRate, Value: 200}}},
		"reasoned again":    {func() measure.Evidence { e := thought; e.ReasonedAgain = true; return e }(), measure.RawCount{}, nil},
		"no reasoning seen": {func() measure.Evidence { e := thought; e.Upstream.ReasoningTokens = 0; return e }(), measure.RawCount{}, nil},
		"shown reasoning":   {func() measure.Evidence { e := thought; e.HidesReasoning = false; return e }(), measure.RawCount{}, nil},
	} {
		if got := tc.e.Samples("m", tc.raw); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: samples %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestACompletedStreamSamplesItsVisibleBytesPerReportedVisibleToken(t *testing.T) {
	shown := measure.Evidence{Upstream: chat.Usage{CompletionTokens: 200}, Reply: measure.Streamed{Events: 20, VisibleBytes: 900}}
	hidden := measure.Evidence{Upstream: chat.Usage{CompletionTokens: 500, ReasoningTokens: 300}, Reply: measure.Streamed{Events: 20, VisibleBytes: 900}, HidesReasoning: true, ReasoningRequested: true}
	sample := func(v float64) []measure.Sample {
		return []measure.Sample{{Route: "m", Figure: measure.FigureReplyBytesPerToken, Value: v}}
	}
	for name, tc := range map[string]struct {
		base  measure.Evidence
		tweak func(*measure.Evidence)
		want  []measure.Sample
	}{
		"shown":                       {shown, func(*measure.Evidence) {}, sample(4.5)},
		"shown reasoning is streamed": {shown, func(e *measure.Evidence) { e.Upstream.ReasoningTokens = 100 }, sample(4.5)},
		"hidden reasoning subtracted": {hidden, func(*measure.Evidence) {}, sample(4.5)},
		"hidden reasoning unreported": {hidden, func(e *measure.Evidence) { e.Upstream.ReasoningTokens = 0 }, nil},
		"hidden, no reasoning asked":  {hidden, func(e *measure.Evidence) { e.Upstream.ReasoningTokens, e.ReasoningRequested = 0, false }, sample(2)},
		"all reasoning":               {hidden, func(e *measure.Evidence) { e.Upstream.ReasoningTokens = 500 }, nil},
		"cancelled":                   {shown, func(e *measure.Evidence) { e.Outcome = measure.Cancelled }, nil},
		"no bytes":                    {shown, func(e *measure.Evidence) { e.Reply = measure.Streamed{Events: 20} }, nil},
		"buffered":                    {shown, func(e *measure.Evidence) { e.Reply = measure.Buffered{Bytes: 900} }, nil},
		"nothing reported":            {shown, func(e *measure.Evidence) { e.Upstream = chat.Usage{} }, nil},
	} {
		e := tc.base
		tc.tweak(&e)
		if got := e.Samples("m", measure.RawCount{}); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: samples %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestAReplyBytesSampleCannotTellTwoRepliesOfTheSameTokensAndNearbyBytesApart(t *testing.T) {
	sampled := func(bytes, tokens int) float64 {
		e := measure.Evidence{Upstream: chat.Usage{CompletionTokens: tokens}, Reply: measure.Streamed{Events: 20, VisibleBytes: bytes}}
		s := e.Samples("m", measure.RawCount{})
		if len(s) != 1 || s[0].Figure != measure.FigureReplyBytesPerToken {
			t.Fatalf("samples %+v, want one reply-bytes sample", s)
		}
		return s[0].Value
	}
	for _, c := range []struct {
		name          string
		bytes, tokens int
		want          float64
	}{
		{"just above a whole ratio", 4_001, 1_000, 4},
		{"just below the midpoint", 4_249, 1_000, 4},
		{"just past the midpoint", 4_251, 1_000, 4.5},
		{"below the learned floor", 300, 1_000, 1},
		{"above the learned ceiling", 30_000, 1_000, 8},
	} {
		if got := sampled(c.bytes, c.tokens); got != c.want {
			t.Errorf("%s: %d bytes over %d tokens sampled as %v, want %v", c.name, c.bytes, c.tokens, got, c.want)
		}
	}
}
