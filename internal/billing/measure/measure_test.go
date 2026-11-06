package measure_test

import (
	"testing"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
)

func counted(tokens int, m measure.Method) measure.Reading {
	return measure.Reading{Tokens: tokens, Method: m}
}

func TestEachSideTakesTheBestEvidenceItHasAndTheBillIsLabelledByItsWeakestSide(t *testing.T) {
	cut := measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, PromptBytes: 100, PromptBound: 100, Reply: measure.Streamed{Events: 7}, OutputLimit: 900}
	for name, tc := range map[string]struct {
		tweak  func(*measure.Evidence)
		want   chat.Usage
		sides  measure.Sides
		source measure.UsageSource
	}{
		"nothing counted":                                   {func(*measure.Evidence) {}, chat.Usage{PromptTokens: 50, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"nothing counted past the window":                   {func(e *measure.Evidence) { e.PromptBound = 40 }, chat.Usage{PromptTokens: 40, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"budgeted, nothing counted, records a token a byte": {func(e *measure.Evidence) { e.Budgeted = true }, chat.Usage{PromptTokens: 100, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"attachments add an allowance each to the byte estimate": {func(e *measure.Evidence) {
			e.Attachments, e.PromptBound = 2, 20_000
		}, chat.Usage{PromptTokens: 50 + 2*measure.AttachmentTokens, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"budgeted attachments add the allowance to a token a byte": {func(e *measure.Evidence) {
			e.Budgeted, e.Attachments, e.PromptBound = true, 2, 20_000
		}, chat.Usage{PromptTokens: 100 + 2*measure.AttachmentTokens, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"attachments never lift the estimate past the bound": {func(e *measure.Evidence) {
			e.Budgeted, e.Attachments = true, 2
		}, chat.Usage{PromptTokens: 100, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"budgeted, prompt counted": {func(e *measure.Evidence) {
			e.Budgeted = true
			e.Counted.Prompt = counted(36, measure.MethodCalibrated)
		}, chat.Usage{PromptTokens: 36, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodCalibrated, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"budgeted, prompt reported": {func(e *measure.Evidence) {
			e.Budgeted = true
			e.Upstream = chat.Usage{PromptTokens: 30}
		}, chat.Usage{PromptTokens: 30, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodReported, Completion: measure.MethodChunks}, measure.UsageEstimated},
		"both reported": {func(e *measure.Evidence) {
			e.Upstream = chat.Usage{PromptTokens: 30, CompletionTokens: 20}
			e.Counted = measure.Counted{Prompt: counted(1, measure.MethodCalibrated), Completion: counted(2, measure.MethodCounted)}
		}, chat.Usage{PromptTokens: 30, CompletionTokens: 20}, measure.Sides{Prompt: measure.MethodReported, Completion: measure.MethodReported}, measure.UsageReported},
		"completion counted": {func(e *measure.Evidence) {
			e.Counted.Completion = counted(12, measure.MethodCounted)
		}, chat.Usage{PromptTokens: 50, CompletionTokens: 12}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodCounted}, measure.UsageEstimated},
		"prompt reported, completion counted": {func(e *measure.Evidence) {
			e.Upstream = chat.Usage{PromptTokens: 30}
			e.Counted.Completion = counted(12, measure.MethodCounted)
		}, chat.Usage{PromptTokens: 30, CompletionTokens: 12}, measure.Sides{Prompt: measure.MethodReported, Completion: measure.MethodCounted}, measure.UsageCounted},
		"both calibrated": {func(e *measure.Evidence) {
			e.Counted = measure.Counted{Prompt: counted(36, measure.MethodCalibrated), Completion: counted(16, measure.MethodCalibrated)}
		}, chat.Usage{PromptTokens: 36, CompletionTokens: 16}, measure.Sides{Prompt: measure.MethodCalibrated, Completion: measure.MethodCalibrated}, measure.UsageCalibrated},
		"calibrated prompt, counted completion": {func(e *measure.Evidence) {
			e.Counted = measure.Counted{Prompt: counted(36, measure.MethodCalibrated), Completion: counted(12, measure.MethodCounted)}
		}, chat.Usage{PromptTokens: 36, CompletionTokens: 12}, measure.Sides{Prompt: measure.MethodCalibrated, Completion: measure.MethodCounted}, measure.UsageCalibrated},
		"reasoning cut on a route that shows it": {func(e *measure.Evidence) {
			e.ReasoningRequested = true
			e.Counted.Completion = counted(12, measure.MethodCounted)
		}, chat.Usage{PromptTokens: 50, CompletionTokens: 12}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodCounted}, measure.UsageEstimated},
		"cut before it was sent, though counted": {func(e *measure.Evidence) {
			e.Unsent = true
			e.Counted = measure.Counted{Prompt: counted(36, measure.MethodCalibrated), Completion: counted(12, measure.MethodCounted)}
		}, chat.Usage{}, measure.Sides{}, measure.UsageNone},
		"reasoning cut with nothing counted": {func(e *measure.Evidence) {
			e.ReasoningRequested = true
		}, chat.Usage{PromptTokens: 50, CompletionTokens: 7}, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}, measure.UsageEstimated},
	} {
		e := cut
		tc.tweak(&e)
		s := e.Measure()
		if s.Tokens != tc.want || s.Sides != tc.sides || s.Source() != tc.source {
			t.Errorf("%s: measured %+v, want %+v by %+v labelled %v", name, s, tc.want, tc.sides, tc.source)
		}
	}
}

func TestOnlyAClientOrDeadlineCutMissingASideOfItsReportNeedsACount(t *testing.T) {
	for name, tc := range map[string]struct {
		e    measure.Evidence
		want bool
	}{
		"client cut, nothing reported":  {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient}, true},
		"deadline cut, prompt reported": {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByDeadline, Upstream: chat.Usage{PromptTokens: 3}}, true},
		"client cut, both reported":     {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, Upstream: chat.Usage{PromptTokens: 3, CompletionTokens: 4}}, false},
		"shutdown cut":                  {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByProxy}, false},
		"client cut, never sent":        {measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, Unsent: true}, false},
		"completed":                     {measure.Evidence{Outcome: measure.Completed}, false},
		"failed":                        {measure.Evidence{Outcome: measure.Failed}, false},
		"exhausted":                     {measure.Evidence{Outcome: measure.Exhausted}, false},
	} {
		if got := tc.e.NeedsCount(); got != tc.want {
			t.Errorf("%s: needs a count %t, want %t", name, got, tc.want)
		}
	}
}

func TestACalibrationIsUsedOnlyOnceEnoughAccountsBackIt(t *testing.T) {
	l := measure.NewLearned([]measure.LearnedFigure{
		{Route: "few", Figure: measure.FigurePromptOverhead, Median: 6, Accounts: measure.MinLearningAccounts - 1},
		{Route: "many", Figure: measure.FigurePromptOverhead, Median: 5.6, Accounts: measure.MinLearningAccounts},
		{Route: "many", Figure: measure.FigureCompletionOffset, Median: -3, Accounts: measure.MinLearningAccounts},
	})
	for _, tc := range []struct {
		route  string
		figure measure.Figure
		want   int
		ok     bool
	}{
		{"few", measure.FigurePromptOverhead, 0, false},
		{"many", measure.FigurePromptOverhead, 6, true},
		{"many", measure.FigureCompletionOffset, -3, true},
		{"absent", measure.FigurePromptOverhead, 0, false},
	} {
		if got, ok := l.Calibration(tc.route, tc.figure); got != tc.want || ok != tc.ok {
			t.Errorf("%s %v: calibration %d (%t), want %d (%t)", tc.route, tc.figure, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAClientCutOfHiddenReasoningAddsTheThinkingBoundToWhatItReceivedUpToTheCap(t *testing.T) {
	hidden := measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, PromptBytes: 100, PromptBound: 100, Reply: measure.Streamed{Events: 7}, OutputLimit: 900, ReasoningCap: 900,
		ReasoningRequested: true, HidesReasoning: true, Thinking: measure.ThinkingTime{Duration: 2500 * time.Millisecond, Rate: 100}}
	for name, tc := range map[string]struct {
		tweak      func(*measure.Evidence)
		completion int
		thinking   int
		sides      measure.Sides
	}{
		"chunks plus thinking":  {func(*measure.Evidence) {}, 7 + 250, 250, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks, Hidden: measure.MethodThinkingTime}},
		"counted plus thinking": {func(e *measure.Evidence) { e.Counted.Completion = counted(12, measure.MethodCounted) }, 12 + 250, 250, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodCounted, Hidden: measure.MethodThinkingTime}},
		"cut before any answer": {func(e *measure.Evidence) { e.Reply = measure.Streamed{} }, 250, 250, measure.Sides{Prompt: measure.MethodRequestBytes, Hidden: measure.MethodThinkingTime}},
		"capped":                {func(e *measure.Evidence) { e.Thinking.Duration = time.Minute }, 900, 893, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks, Hidden: measure.MethodThinkingTime}},
		"cut before any event":  {func(e *measure.Evidence) { e.Reply, e.Thinking.Duration = measure.Streamed{}, 0 }, 0, 0, measure.Sides{Prompt: measure.MethodRequestBytes}},
		"reported":              {func(e *measure.Evidence) { e.Upstream.CompletionTokens = 40 }, 40, 0, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodReported}},
		"deadline cut":          {func(e *measure.Evidence) { e.Cut = measure.CutByDeadline }, 7, 0, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}},
		"no reasoning asked":    {func(e *measure.Evidence) { e.ReasoningRequested = false }, 7, 0, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}},
		"reasoning shown":       {func(e *measure.Evidence) { e.HidesReasoning = false }, 7, 0, measure.Sides{Prompt: measure.MethodRequestBytes, Completion: measure.MethodChunks}},
	} {
		e := hidden
		tc.tweak(&e)
		s := e.Measure()
		want := chat.Usage{PromptTokens: 50, CompletionTokens: tc.completion}
		if s.Tokens != want || s.Thinking.Tokens != tc.thinking || s.Sides != tc.sides {
			t.Errorf("%s: measured %+v, want %+v with %d thinking tokens by %+v", name, s, want, tc.thinking, tc.sides)
		}
		if tc.thinking > 0 && (s.Thinking.Rate != 100 || s.Thinking.Duration != e.Thinking.Duration || s.Source() != measure.UsageEstimated) {
			t.Errorf("%s: thinking %+v labelled %v, want the rate and duration kept for audit and an estimated label", name, s.Thinking, s.Source())
		}
	}
}

func TestALearnedThinkingRateIsTheLowAccountsRateMovingTheSeedAtMostByHalfOrDoubleAndNeverPastTheDecodeBound(t *testing.T) {
	terms := measure.ThinkingTerms{Seed: 100, DecodeMax: 180}
	learned := func(p10 float64, accounts int) measure.Learned {
		return measure.NewLearned([]measure.LearnedFigure{{Route: "r", Figure: measure.FigureThinkingRate, Median: p10 + 40, P10: p10, Accounts: accounts}})
	}
	for name, tc := range map[string]struct {
		l    measure.Learned
		want int
	}{
		"nothing learned":   {measure.Learned{}, 100},
		"too few accounts":  {learned(150, measure.MinLearningAccounts-1), 100},
		"within the clamp":  {learned(130.4, measure.MinLearningAccounts), 130},
		"poisoned low":      {learned(3, measure.MinLearningAccounts), 50},
		"poisoned high":     {learned(10_000, measure.MinLearningAccounts), 180},
		"past decode alone": {learned(190, measure.MinLearningAccounts), 180},
	} {
		if got := tc.l.ThinkingRate("r", terms); got != tc.want {
			t.Errorf("%s: rate %d, want %d", name, got, tc.want)
		}
	}
}

func TestHiddenThinkingLabelsABillEstimatedEvenWhenBothVisibleSidesAreExact(t *testing.T) {
	e := measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, Upstream: chat.Usage{PromptTokens: 30}, Counted: measure.Counted{Completion: counted(12, measure.MethodCounted)}, Reply: measure.Streamed{},
		ReasoningRequested: true, HidesReasoning: true, ReasoningCap: 900, Thinking: measure.ThinkingTime{Duration: time.Second, Rate: 100}}
	if s := e.Measure(); s.Source() != measure.UsageEstimated || s.Tokens.CompletionTokens != 112 {
		t.Errorf("measured %+v, want 112 completion tokens labelled estimated for the thinking bound", s)
	}
}

func TestBilledTokensTakeTheUpstreamsCountPerSideAndTheEstimateOnlyWhereItSentNoneAndNameTheirSource(t *testing.T) {
	const bound, promptBytes, promptFloor = 500, 101, 51
	reported := chat.Usage{PromptTokens: 12, CachedPromptTokens: 5, CompletionTokens: 40}
	promptOnly := chat.Usage{PromptTokens: 15, CachedPromptTokens: 5}
	cachedOnly := chat.Usage{CachedPromptTokens: 5, CacheWritePromptTokens: 4, CompletionTokens: 40}
	written := chat.Usage{PromptTokens: 12, CachedPromptTokens: 5, CacheWritePromptTokens: 6, CompletionTokens: 40}
	cases := []struct {
		name      string
		outcome   measure.Outcome
		cut       measure.Cut
		reported  chat.Usage
		reasoning bool
		reply     measure.Reply
		want      chat.Usage
		source    measure.UsageSource
	}{
		{"client cut, nothing reported", measure.Cancelled, measure.CutByClient, chat.Usage{}, false, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 3}, measure.UsageEstimated},
		{"failed, nothing reported", measure.Failed, measure.NotCut, chat.Usage{}, false, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 3}, measure.UsageEstimated},
		{"client cut, upstream reported", measure.Cancelled, measure.CutByClient, reported, true, measure.Streamed{}, reported, measure.UsageReported},
		{"client cut, upstream reported cache writes", measure.Cancelled, measure.CutByClient, written, true, measure.Streamed{}, written, measure.UsageReported},
		{"failed, upstream reported cache writes", measure.Failed, measure.NotCut, written, false, measure.Streamed{Events: 3}, written, measure.UsageReported},
		{"failed, upstream reported", measure.Failed, measure.NotCut, reported, false, measure.Streamed{Events: 3}, reported, measure.UsageReported},
		{"only the prompt reported", measure.Cancelled, measure.CutByClient, promptOnly, false, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: 15, CachedPromptTokens: 5, CompletionTokens: 3}, measure.UsageEstimated},
		{"only cached and written tokens reported", measure.Cancelled, measure.CutByClient, cachedOnly, false, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 40}, measure.UsageEstimated},
		{"client cut a reasoning request before the first byte", measure.Cancelled, measure.CutByClient, chat.Usage{}, true, measure.Streamed{}, chat.Usage{PromptTokens: promptFloor}, measure.UsageEstimated},
		{"client cut a reasoning stream after chunks", measure.Cancelled, measure.CutByClient, chat.Usage{}, true, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 3}, measure.UsageEstimated},
		{"proxy cut a reasoning stream", measure.Cancelled, measure.CutByProxy, chat.Usage{}, true, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 3}, measure.UsageEstimated},
		{"upstream failed a reasoning request", measure.Failed, measure.NotCut, chat.Usage{}, true, measure.Streamed{}, chat.Usage{PromptTokens: promptFloor}, measure.UsageEstimated},
		{"buffered body the proxy could not count", measure.Failed, measure.NotCut, chat.Usage{}, false, measure.Buffered{Bytes: 2 * bound}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: bound}, measure.UsageEstimated},
		{"opaque reply", measure.Completed, measure.NotCut, chat.Usage{}, false, measure.Opaque{}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: bound}, measure.UsageEstimated},
		{"completed", measure.Completed, measure.NotCut, reported, true, measure.Streamed{}, reported, measure.UsageReported},
		{"completed with cache writes", measure.Completed, measure.NotCut, written, true, measure.Streamed{}, written, measure.UsageReported},
		{"completed, nothing reported", measure.Completed, measure.NotCut, chat.Usage{}, true, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: promptFloor, CompletionTokens: 3}, measure.UsageEstimated},
		{"rejected", measure.Rejected, measure.NotCut, chat.Usage{}, true, measure.Streamed{}, chat.Usage{}, measure.UsageNone},
		{"rejected with the upstream usage", measure.Rejected, measure.NotCut, chat.Usage{PromptTokens: 12}, false, measure.Streamed{Events: 3}, chat.Usage{PromptTokens: 12}, measure.UsageReported},
		{"completed, upstream reported a prompt and no completion, nothing answered", measure.Completed, measure.NotCut, promptOnly, false, measure.Streamed{}, chat.Usage{PromptTokens: 15, CachedPromptTokens: 5}, measure.UsageReported},
		{"completed, upstream reported a prompt and no completion, chunks answered", measure.Completed, measure.NotCut, promptOnly, false, measure.Streamed{Events: 2}, chat.Usage{PromptTokens: 15, CachedPromptTokens: 5, CompletionTokens: 2}, measure.UsageEstimated},
	}
	for _, c := range cases {
		e := measure.Evidence{Outcome: c.outcome, Cut: c.cut, Upstream: c.reported, PromptBytes: promptBytes, PromptBound: promptBytes, Reply: c.reply, ReasoningRequested: c.reasoning, OutputLimit: bound, ReasoningCap: bound}
		if s := e.Measure(); s.Tokens != c.want || s.Source() != c.source {
			t.Errorf("%s: billed %+v from %s, want %+v from %s", c.name, s.Tokens, s.Source(), c.want, c.source)
		}
	}
}

func TestTheReasoningPartOfAReportChangesNoMeasurement(t *testing.T) {
	for _, o := range []measure.Outcome{measure.Completed, measure.Rejected, measure.Failed, measure.Cancelled} {
		plain := measure.Evidence{Outcome: o, Upstream: chat.Usage{PromptTokens: 1249, CompletionTokens: 79, CachedPromptTokens: 1152}, HidesReasoning: true, ReasoningRequested: true, Reply: measure.Streamed{Events: 1}}
		reasoned := plain
		reasoned.Upstream.ReasoningTokens = 74
		got, want := reasoned.Measure(), plain.Measure()
		if got != want || got.Tokens != plain.Upstream {
			t.Errorf("%v: measured %+v with 74 of the 79 completion tokens marked as reasoning, want %+v", o, got, want)
		}
	}
}

func TestACutStreamWithNoReportBillsItsVisibleBytesAtTheRoutesRatioButNeverBelowItsChunks(t *testing.T) {
	ratio := func(median float64, accounts int) measure.Learned {
		return measure.NewLearned([]measure.LearnedFigure{{Route: "r", Figure: measure.FigureReplyBytesPerToken, Median: median, Accounts: accounts}})
	}
	for name, tc := range map[string]struct {
		reply   measure.Streamed
		learned measure.Learned
		want    int
		method  measure.Method
	}{
		"default ratio":       {measure.Streamed{Events: 40, VisibleBytes: 4000}, measure.Learned{}, 1000, measure.MethodReplyBytes},
		"learned ratio":       {measure.Streamed{Events: 40, VisibleBytes: 4000}, ratio(5, measure.MinLearningAccounts), 800, measure.MethodReplyBytes},
		"too few accounts":    {measure.Streamed{Events: 40, VisibleBytes: 4000}, ratio(5, measure.MinLearningAccounts-1), 1000, measure.MethodReplyBytes},
		"poisoned low":        {measure.Streamed{Events: 40, VisibleBytes: 400}, ratio(0.1, measure.MinLearningAccounts), 400, measure.MethodReplyBytes},
		"poisoned high":       {measure.Streamed{Events: 40, VisibleBytes: 4000}, ratio(100, measure.MinLearningAccounts), 500, measure.MethodReplyBytes},
		"rounds up":           {measure.Streamed{Events: 1, VisibleBytes: 9}, measure.Learned{}, 3, measure.MethodReplyBytes},
		"chunks outnumber":    {measure.Streamed{Events: 40, VisibleBytes: 100}, measure.Learned{}, 40, measure.MethodChunks},
		"no bytes":            {measure.Streamed{Events: 7}, measure.Learned{}, 7, measure.MethodChunks},
		"capped at the limit": {measure.Streamed{Events: 40, VisibleBytes: 40_000}, measure.Learned{}, 2000, measure.MethodReplyBytes},
	} {
		e := measure.Evidence{Outcome: measure.Cancelled, Cut: measure.CutByClient, PromptBytes: 100, Reply: tc.reply, OutputLimit: 2000, ReplyBytesPerToken: tc.learned.ReplyBytesPerToken("r")}
		s := e.Measure()
		if s.Tokens.CompletionTokens != tc.want || s.Sides.Completion != tc.method || s.Source() != measure.UsageEstimated {
			t.Errorf("%s: measured %+v, want %d completion tokens by %v labelled estimated", name, s, tc.want, tc.method)
		}
	}
}

func TestACompletedReplyBillsTheUpstreamsReportWhateverItShowed(t *testing.T) {
	reported := chat.Usage{PromptTokens: 12, CachedPromptTokens: 5, CompletionTokens: 40}
	for name, reply := range map[string]measure.Reply{
		"a stream of a role and a usage chunk": measure.Streamed{Events: 2},
		"a stream of reasoning alone":          measure.Streamed{Events: 5, VisibleBytes: 300},
		"a stream that showed text":            measure.Streamed{Events: 2, VisibleBytes: 20},
		"a completion with empty content":      measure.Buffered{Bytes: 150},
		"a completion that showed text":        measure.Buffered{Bytes: 150},
		"a sealed stream":                      measure.SealedEvents{Events: 2},
		"a sealed body":                        measure.Opaque{},
	} {
		e := measure.Evidence{Outcome: measure.Completed, Upstream: reported, PromptBytes: 100, Reply: reply, OutputLimit: 900}
		if s := e.Measure(); s.Tokens != reported || s.Source() != measure.UsageReported {
			t.Errorf("%s: measured %+v, want the reported %+v labelled reported", name, s, reported)
		}
	}
}
